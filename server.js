import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import {
  BOLETO_AMOUNT_CENTS,
  buildPagarmeOrder,
  customerKeys,
  extractBoleto,
  validateBoletoRequest
} from './payment.js';

const { Pool } = pg;
const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 3000);
const accountMode = String(process.env.PAGARME_ACCOUNT_MODE || '').toLowerCase();
const secretKey = process.env.PAGARME_SECRET_KEY || '';
const databaseUrl = process.env.DATABASE_URL || '';
const idempotencySecret = process.env.IDEMPOTENCY_SECRET || '';
const staleCreatingMs = 5 * 60 * 1000;
const pool = databaseUrl
  ? new Pool({
      connectionString: databaseUrl,
      ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      max: 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000
    })
  : null;

app.set('trust proxy', 1);
// The existing form uses inline JavaScript and styles, so CSP is disabled.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb', strict: true }));

const boletoLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { message: 'Muitas tentativas. Aguarde alguns minutos e tente novamente.', retryable: true }
});

function safeError(res, status, message, extra = {}) {
  return res.status(status).json({ message, ...extra });
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (!origin) return next();
  const expected = `${req.protocol}://${req.get('host')}`;
  if (origin !== expected) return safeError(res, 403, 'Origem não autorizada.');
  next();
}

function identifiersFor(clientRequestId) {
  const compact = clientRequestId.replaceAll('-', '').toLowerCase();
  const numeric = (BigInt(`0x${compact}`) % 9_000_000_000_000_000n) + 1_000_000_000_000_000n;
  return { orderCode: `mei_${compact}`, documentNumber: numeric.toString() };
}

function constantTimeEqualHex(left, right) {
  const a = Buffer.from(String(left || ''), 'utf8');
  const b = Buffer.from(String(right || ''), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function initializeDatabase() {
  if (!pool) throw new Error('DATABASE_URL é obrigatória para impedir boletos duplicados entre sessões e reinícios.');
  if (idempotencySecret.length < 32) throw new Error('Configure IDEMPOTENCY_SECRET com pelo menos 32 caracteres e mantenha-o estável.');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS boleto_customer_requests (
      cpf_key TEXT PRIMARY KEY,
      email_key TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      client_request_id UUID NOT NULL,
      order_code TEXT NOT NULL UNIQUE,
      document_number TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('creating', 'issued', 'unknown', 'rejected')),
      response JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query('SELECT 1');
}

async function reserveOrReuse({ keys, clientRequestId, identifiers }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const inserted = await client.query(
      `INSERT INTO boleto_customer_requests
        (cpf_key, email_key, fingerprint, client_request_id, order_code, document_number, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'creating')
       ON CONFLICT (cpf_key) DO NOTHING
       RETURNING *`,
      [keys.cpfKey, keys.emailKey, keys.fingerprint, clientRequestId, identifiers.orderCode, identifiers.documentNumber]
    );
    if (inserted.rowCount === 1) {
      await client.query('COMMIT');
      return { kind: 'issue', row: inserted.rows[0] };
    }

    const selected = await client.query(
      'SELECT * FROM boleto_customer_requests WHERE cpf_key = $1 FOR UPDATE',
      [keys.cpfKey]
    );
    const row = selected.rows[0];
    if (!row) throw new Error('Não foi possível recuperar a reserva de idempotência.');

    if (!constantTimeEqualHex(row.email_key, keys.emailKey)) {
      await client.query('COMMIT');
      return { kind: 'email-mismatch' };
    }
    if (row.status === 'issued') {
      await client.query('COMMIT');
      return row.response ? { kind: 'issued', row } : { kind: 'unknown', row };
    }
    if (row.status === 'unknown') {
      await client.query('COMMIT');
      return { kind: 'unknown', row };
    }
    if (row.status === 'creating') {
      const ageMs = Date.now() - new Date(row.updated_at).getTime();
      if (ageMs > staleCreatingMs) {
        await client.query(
          `UPDATE boleto_customer_requests SET status = 'unknown', updated_at = NOW() WHERE cpf_key = $1`,
          [keys.cpfKey]
        );
        row.status = 'unknown';
        await client.query('COMMIT');
        return { kind: 'unknown', row };
      }
      await client.query('COMMIT');
      return { kind: 'creating', row };
    }

    // A recusa 4xx da Pagar.me é definitiva; a mesma reserva pode ser tentada novamente.
    await client.query(
      `UPDATE boleto_customer_requests
       SET status = 'creating', fingerprint = $2, client_request_id = $3, updated_at = NOW()
       WHERE cpf_key = $1`,
      [keys.cpfKey, keys.fingerprint, clientRequestId]
    );
    row.status = 'creating';
    await client.query('COMMIT');
    return { kind: 'issue', row };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    throw error;
  } finally {
    client.release();
  }
}

async function updateRequest(cpfKey, status, response = null) {
  await pool.query(
    `UPDATE boleto_customer_requests
     SET status = $2,
         response = CASE WHEN $3::jsonb IS NULL THEN response ELSE $3::jsonb END,
         updated_at = NOW()
     WHERE cpf_key = $1`,
    [cpfKey, status, response ? JSON.stringify(response) : null]
  );
}

async function createPagarmeOrder(customer, identifiers) {
  const orderBody = buildPagarmeOrder(customer, { ...identifiers, accountMode });
  const authorization = Buffer.from(`${secretKey}:`, 'utf8').toString('base64');
  const response = await fetch('https://api.pagar.me/core/v5/orders', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${authorization}`,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify(orderBody),
    signal: AbortSignal.timeout(25_000)
  });

  let result = {};
  try { result = await response.json(); } catch {}
  if (!response.ok) {
    const providerCode = String(result?.errors?.[0]?.code || result?.code || 'unavailable').slice(0, 80);
    console.error(`[Pagar.me] request rejected: status=${response.status} code=${providerCode}`);
    const error = new Error('A Pagar.me recusou a emissão. Confira os dados e a configuração da conta.');
    // Somente recusas claramente definitivas liberam tentativa posterior. 409, 408,
    // 429 e respostas 5xx são conservadas como ambíguas para nunca duplicar cobrança.
    error.providerRejected = [400, 401, 403, 422].includes(response.status);
    throw error;
  }

  let boleto;
  try { boleto = extractBoleto(result); }
  catch {
    const error = new Error('Resposta sem linha digitável após criação do pedido.');
    error.ambiguous = true;
    throw error;
  }
  if (boleto.amountCents !== BOLETO_AMOUNT_CENTS) {
    const error = new Error('O valor retornado diverge do valor configurado.');
    error.ambiguous = true;
    throw error;
  }
  boleto.reference = identifiers.orderCode;
  return boleto;
}

app.get('/api/health', async (_req, res) => {
  try {
    if (!pool) return safeError(res, 503, 'Banco de dados não configurado.');
    await pool.query('SELECT 1');
    return res.json({ status: 'ok' });
  } catch {
    return safeError(res, 503, 'Banco de dados indisponível.');
  }
});

app.post('/api/boleto', requireSameOrigin, boletoLimiter, async (req, res) => {
  if (!secretKey || !['gateway', 'psp'].includes(accountMode)) {
    return safeError(res, 503, 'Configure PAGARME_SECRET_KEY e PAGARME_ACCOUNT_MODE no Render.', { retryable: false });
  }
  if (!pool || idempotencySecret.length < 32) {
    return safeError(res, 503, 'Configure PostgreSQL e IDEMPOTENCY_SECRET no Render antes de emitir boletos.', { retryable: false });
  }

  const clientRequestId = String(req.body?.clientRequestId || '').toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(clientRequestId)) {
    return safeError(res, 400, 'Identificador da solicitação inválido. Atualize a página e tente novamente.', { retryable: true });
  }

  const validation = validateBoletoRequest(req.body, accountMode);
  if (!validation.valid) return safeError(res, 422, validation.errors[0], { retryable: true });

  let keys;
  try { keys = customerKeys(idempotencySecret, validation.customer); }
  catch { return safeError(res, 503, 'Configuração de idempotência inválida.', { retryable: false }); }

  let reservation;
  try {
    reservation = await reserveOrReuse({ keys, clientRequestId, identifiers: identifiersFor(clientRequestId) });
  } catch (error) {
    console.error('[database] unable to reserve boleto:', error?.code || error?.message || 'unknown');
    return safeError(res, 503, 'Não foi possível verificar se já existe um boleto. Nenhuma nova emissão foi iniciada; tente novamente em instantes.', { retryable: true });
  }

  if (reservation.kind === 'email-mismatch') {
    return safeError(res, 409, 'Já existe uma solicitação para este CPF com outro e-mail. Por segurança, não emitimos outro boleto; use o mesmo e-mail informado antes ou fale com o atendimento.', { retryable: false });
  }
  if (reservation.kind === 'issued') return res.json(reservation.row.response);
  if (reservation.kind === 'creating') {
    return safeError(res, 409, 'Já existe uma emissão em andamento para este CPF. Aguarde alguns instantes e tente consultar novamente; não será criado outro boleto.', { retryable: true });
  }
  if (reservation.kind === 'unknown') {
    return safeError(res, 409, `Não foi possível confirmar a emissão anterior. Não gere outro boleto; consulte o painel Pagar.me com a referência ${reservation.row.order_code}.`, { retryable: false, state: 'unknown' });
  }

  const row = reservation.row;
  const identifiers = { orderCode: row.order_code, documentNumber: row.document_number };
  try {
    const boleto = await createPagarmeOrder(validation.customer, identifiers);
    try {
      await updateRequest(keys.cpfKey, 'issued', boleto);
    } catch (error) {
      console.error(`[database] boleto issued but result not stored: ${row.order_code}; ${error?.code || 'unknown'}`);
      return safeError(res, 503, `A Pagar.me confirmou a emissão, mas não foi possível salvar a resposta. Não tente emitir novamente. Confira o painel Pagar.me com a referência ${row.order_code}.`, { retryable: false, state: 'unknown' });
    }
    return res.status(201).json(boleto);
  } catch (error) {
    if (error.providerRejected) {
      try { await updateRequest(keys.cpfKey, 'rejected'); }
      catch (dbError) {
        console.error('[database] unable to save provider rejection:', dbError?.code || 'unknown');
        return safeError(res, 503, `A Pagar.me recusou a solicitação, mas o estado não pôde ser salvo. Não tente novamente até verificar a referência ${row.order_code}.`, { retryable: false, state: 'unknown' });
      }
      return safeError(res, 422, error.message, { retryable: true });
    }
    try { await updateRequest(keys.cpfKey, 'unknown'); }
    catch (dbError) { console.error('[database] unable to save uncertain result:', dbError?.code || 'unknown'); }
    console.error(`[Pagar.me] result uncertain for reference ${row.order_code}`);
    return safeError(res, 503, `Não foi possível confirmar a emissão. Não gere outro boleto. Consulte o painel Pagar.me com a referência ${row.order_code}.`, { retryable: false, state: 'unknown' });
  }
});

app.get('/', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get(['/assessoria', '/assessoria/'], (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'assessoria', 'index.html'));
});

app.use((error, _req, res, _next) => {
  if (error?.type === 'entity.too.large') return safeError(res, 413, 'A solicitação excede o tamanho permitido.');
  if (error instanceof SyntaxError && 'body' in error) return safeError(res, 400, 'JSON inválido.');
  console.error('[server] unexpected error:', error?.message || String(error));
  return safeError(res, 500, 'Erro interno. Tente novamente.');
});

async function start() {
  await initializeDatabase();
  app.listen(port, '0.0.0.0', () => console.log(`Web service ready on port ${port}`));
}

start().catch(error => {
  console.error('Startup failed:', error?.message || String(error) || 'erro sem mensagem');
  if (error?.code) console.error('Startup error code:', error.code);
  if (error?.stack) console.error(error.stack);
  process.exit(1);
});

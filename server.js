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
  extractBoleto,
  validateBoletoRequest
} from './lib/payment.js';

const { Pool } = pg;
const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const accountMode = String(process.env.PAGARME_ACCOUNT_MODE || '').toLowerCase();
const secretKey = process.env.PAGARME_SECRET_KEY || '';
const idempotencySecret = process.env.IDEMPOTENCY_SECRET || '';
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      max: 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000
    })
  : null;

app.set('trust proxy', 1);
// The supplied form uses inline styles/scripts; CSP is disabled here and should be
// replaced with a nonce-based policy before introducing third-party scripts.
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
  if (!origin) return next(); // permits health checks and server-side clients
  const expected = `${req.protocol}://${req.get('host')}`;
  if (origin !== expected) return safeError(res, 403, 'Origem não autorizada.');
  next();
}

async function initializeDatabase() {
  if (!pool) {
    if (isProduction) throw new Error('DATABASE_URL é obrigatória em produção.');
    console.warn('DATABASE_URL ausente: rotas de boleto ficam indisponíveis até configurar PostgreSQL.');
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_requests (
      client_request_id UUID PRIMARY KEY,
      payload_hash TEXT NOT NULL,
      order_code VARCHAR(52) NOT NULL UNIQUE,
      document_number VARCHAR(16) NOT NULL,
      status VARCHAR(16) NOT NULL CHECK (status IN ('creating', 'issued', 'rejected', 'unknown')),
      provider_order_id VARCHAR(80),
      response JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

function hashPayload(customer) {
  if (idempotencySecret.length < 32) throw new Error('IDEMPOTENCY_SECRET is missing or too short');
  const canonical = JSON.stringify({
    name: customer.name,
    email: customer.email.toLowerCase(),
    cpf: customer.cpf,
    zipCode: customer.zipCode,
    street: customer.street,
    number: customer.number,
    neighborhood: customer.neighborhood,
    city: customer.city,
    state: customer.state,
    phone: customer.phone || '',
    amount: BOLETO_AMOUNT_CENTS
  });
  return crypto.createHmac('sha256', idempotencySecret).update(canonical).digest('hex');
}

function generateOrderIdentifiers(clientRequestId) {
  const compact = clientRequestId.replaceAll('-', '').toLowerCase();
  const orderCode = `mei_${compact}`.slice(0, 52);
  const numeric = (BigInt(`0x${compact}`) % 9_000_000_000_000_000n) + 1_000_000_000_000_000n;
  return { orderCode, documentNumber: numeric.toString() };
}

async function reserveRequest(clientRequestId, payloadHash, orderCode, documentNumber) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const inserted = await client.query(
      `INSERT INTO payment_requests (client_request_id, payload_hash, order_code, document_number, status)
       VALUES ($1, $2, $3, $4, 'creating')
       ON CONFLICT (client_request_id) DO NOTHING
       RETURNING client_request_id`,
      [clientRequestId, payloadHash, orderCode, documentNumber]
    );
    const rowResult = await client.query(
      'SELECT * FROM payment_requests WHERE client_request_id = $1 FOR UPDATE',
      [clientRequestId]
    );
    const row = rowResult.rows[0];
    if (!row) throw new Error('Could not reserve payment request');
    if (row.payload_hash !== payloadHash) {
      await client.query('ROLLBACK');
      return { kind: 'conflict' };
    }
    if (!inserted.rowCount && row.status === 'issued') {
      await client.query('COMMIT');
      return { kind: 'cached', response: row.response };
    }
    if (!inserted.rowCount && row.status === 'creating') {
      await client.query('COMMIT');
      return { kind: 'processing' };
    }
    if (!inserted.rowCount && row.status === 'unknown') {
      await client.query('COMMIT');
      return { kind: 'unknown', orderCode: row.order_code };
    }
    if (!inserted.rowCount && row.status === 'rejected') {
      const update = await client.query(
        `UPDATE payment_requests SET status='creating', updated_at=NOW()
         WHERE client_request_id=$1 AND status='rejected' RETURNING client_request_id`,
        [clientRequestId]
      );
      if (!update.rowCount) {
        await client.query('COMMIT');
        return { kind: 'processing' };
      }
    }
    await client.query('COMMIT');
    return { kind: 'reserved', orderCode: row.order_code, documentNumber: row.document_number };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    throw error;
  } finally {
    client.release();
  }
}

async function updateRequest(clientRequestId, values) {
  await pool.query(
    `UPDATE payment_requests
     SET status=$2, provider_order_id=$3, response=$4::jsonb, updated_at=NOW()
     WHERE client_request_id=$1`,
    [clientRequestId, values.status, values.providerOrderId || null,
      values.response ? JSON.stringify(values.response) : null]
  );
}

async function createPagarmeOrder(customer, identifiers) {
  const body = buildPagarmeOrder(customer, { ...identifiers, accountMode });
  const authorization = Buffer.from(`${secretKey}:`, 'utf8').toString('base64');
  const response = await fetch('https://api.pagar.me/core/v5/orders', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${authorization}`,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(25_000)
  });
  let result = {};
  try { result = await response.json(); } catch {}
  if (!response.ok) {
    const providerCode = String(result?.errors?.[0]?.code || result?.code || 'unavailable').slice(0, 80);
    console.error(`[Pagar.me] request rejected: status=${response.status} code=${providerCode}`);
    const error = new Error('A Pagar.me recusou a emissão. Confira os dados e a configuração da conta.');
    error.providerRejected = response.status >= 400 && response.status < 500;
    error.statusCode = error.providerRejected ? 422 : 502;
    throw error;
  }
  return result;
}

app.get('/api/health', async (_req, res) => {
  try {
    if (!pool) return res.status(503).json({ status: 'database_not_configured' });
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch {
    res.status(503).json({ status: 'unavailable' });
  }
});

app.post('/api/boleto', requireSameOrigin, boletoLimiter, async (req, res) => {
  if (!pool) return safeError(res, 503, 'O serviço de pagamento ainda não está configurado.', { retryable: false });
  if (!secretKey || !idempotencySecret || !['gateway', 'psp'].includes(accountMode)) {
    return safeError(res, 503, 'A configuração da integração Pagar.me está incompleta.', { retryable: false });
  }

  const clientRequestId = String(req.body?.clientRequestId || '').toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(clientRequestId)) {
    return safeError(res, 400, 'Identificador da solicitação inválido. Atualize a página e tente novamente.', { retryable: true });
  }

  const validation = validateBoletoRequest(req.body, accountMode);
  if (!validation.valid) {
    return safeError(res, 422, validation.errors[0], { retryable: true });
  }

  let payloadHash;
  try { payloadHash = hashPayload(validation.customer); }
  catch { return safeError(res, 503, 'A configuração de segurança do servidor está incompleta.', { retryable: false }); }

  const identifiers = generateOrderIdentifiers(clientRequestId);
  let reservation;
  try {
    reservation = await reserveRequest(clientRequestId, payloadHash, identifiers.orderCode, identifiers.documentNumber);
  } catch (error) {
    console.error('[payment-db] Could not reserve request:', error.message);
    return safeError(res, 503, 'Não foi possível acessar o serviço de pagamentos. Tente novamente em instantes.', { retryable: true });
  }

  if (reservation.kind === 'conflict') {
    return safeError(res, 409, 'Os dados foram alterados. Atualize a página para iniciar uma nova emissão.', { retryable: false });
  }
  if (reservation.kind === 'cached') return res.json(reservation.response);
  if (reservation.kind === 'processing') {
    return safeError(res, 409, 'A emissão deste boleto já está em andamento. Aguarde alguns instantes e tente novamente.', { retryable: true });
  }
  if (reservation.kind === 'unknown') {
    return safeError(res, 409, `A Pagar.me não confirmou o resultado da emissão. Não tente gerar outro boleto ainda. Referência: ${reservation.orderCode}.`, { retryable: false, state: 'unknown' });
  }

  try {
    const providerOrder = await createPagarmeOrder(validation.customer, reservation);
    let boleto;
    try { boleto = extractBoleto(providerOrder); }
    catch (error) {
      await updateRequest(clientRequestId, { status: 'unknown', providerOrderId: providerOrder?.id });
      console.error(`[Pagar.me] order created without boleto line: ${String(providerOrder?.id || 'unknown')}`);
      return safeError(res, 502, 'A Pagar.me recebeu o pedido, mas não retornou o código do boleto. Não tente gerar outro; consulte o painel Pagar.me.', { retryable: false, state: 'unknown' });
    }
    if (boleto.amountCents !== BOLETO_AMOUNT_CENTS) {
      await updateRequest(clientRequestId, { status: 'unknown', providerOrderId: boleto.orderId });
      console.error(`[Pagar.me] amount mismatch for order ${boleto.orderId}`);
      return safeError(res, 502, 'O valor retornado pela Pagar.me não corresponde ao pedido. A emissão foi bloqueada; consulte o painel.', { retryable: false, state: 'unknown' });
    }
    boleto.reference = reservation.orderCode;
    await updateRequest(clientRequestId, { status: 'issued', providerOrderId: boleto.orderId, response: boleto });
    return res.status(201).json(boleto);
  } catch (error) {
    if (error.providerRejected) {
      await updateRequest(clientRequestId, { status: 'rejected' });
      return safeError(res, error.statusCode || 422, error.message, { retryable: true });
    }
    // Timeouts and network/server errors are ambiguous: do not automatically issue a second charge.
    await updateRequest(clientRequestId, { status: 'unknown' });
    console.error(`[Pagar.me] ambiguous create-order result for reference ${reservation.orderCode}`);
    return safeError(res, 503, `Não foi possível confirmar se o boleto foi emitido. Não tente gerar outro. Consulte o painel Pagar.me com a referência ${reservation.orderCode}.`, { retryable: false, state: 'unknown' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), {
  index: 'index.html',
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
  }
}));

app.use((error, _req, res, _next) => {
  if (error?.type === 'entity.too.large') return safeError(res, 413, 'A solicitação excede o tamanho permitido.');
  if (error instanceof SyntaxError && 'body' in error) return safeError(res, 400, 'JSON inválido.');
  console.error('[server] unexpected error:', error.message);
  return safeError(res, 500, 'Erro interno. Tente novamente.');
});

if (isProduction && !process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL é obrigatória em produção.');
}

initializeDatabase()
  .then(() => app.listen(port, '0.0.0.0', () => console.log(`Web service ready on port ${port}`)))
  .catch(error => {
    console.error('Startup failed:', error.message);
    process.exit(1);
  });

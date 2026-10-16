import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import {
  BOLETO_AMOUNT_CENTS,
  buildPagarmeOrder,
  extractBoleto,
  validateBoletoRequest
} from './payment.js';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 3000);
const accountMode = String(process.env.PAGARME_ACCOUNT_MODE || '').toLowerCase();
const secretKey = process.env.PAGARME_SECRET_KEY || '';
// Chave aleatória por processo: CPF/e-mail não ficam guardados em claro no Map.
const processKey = crypto.randomBytes(32).toString('hex');
const customerRequests = new Map();
const inFlight = new Map();
const MAX_CUSTOMERS_PER_PROCESS = 5000;
const STALE_REQUEST_MS = 5 * 60 * 1000;

app.set('trust proxy', 1);
// O formulário atual usa estilos e scripts inline.
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

function customerKeysForProcess(customer) {
  const cpf = String(customer.cpf || '').replace(/\D/g, '');
  const email = String(customer.email || '').trim().toLowerCase();
  const hmac = value => crypto.createHmac('sha256', processKey).update(value).digest('hex');
  return { cpfKey: hmac(`cpf:${cpf}`), emailKey: hmac(`email:${email}`) };
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
    // 409/408/429/5xx podem ser ambíguos; bloqueia nova emissão por segurança.
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

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/boleto', requireSameOrigin, boletoLimiter, async (req, res) => {
  if (!secretKey || !['gateway', 'psp'].includes(accountMode)) {
    return safeError(res, 503, 'Configure PAGARME_SECRET_KEY e PAGARME_ACCOUNT_MODE no Render.', { retryable: false });
  }

  const clientRequestId = String(req.body?.clientRequestId || '').toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(clientRequestId)) {
    return safeError(res, 400, 'Identificador da solicitação inválido. Atualize a página e tente novamente.', { retryable: true });
  }

  const validation = validateBoletoRequest(req.body, accountMode);
  if (!validation.valid) return safeError(res, 422, validation.errors[0], { retryable: true });

  const keys = customerKeysForProcess(validation.customer);
  let entry = customerRequests.get(keys.cpfKey);
  if (entry) {
    if (entry.emailKey !== keys.emailKey) {
      return safeError(res, 409, 'Já existe uma solicitação para este CPF com outro e-mail. Use o mesmo e-mail informado antes; não foi criado outro boleto.', { retryable: false });
    }
    if (entry.status === 'issued' && entry.response) return res.json(entry.response);
    if (entry.status === 'issued' || entry.status === 'unknown') {
      return safeError(res, 409, `A emissão anterior não pode ser confirmada automaticamente. Não gere outro boleto. Referência: ${entry.orderCode}.`, { retryable: false, state: 'unknown' });
    }
    if (entry.status === 'creating') {
      const activeRequest = inFlight.get(keys.cpfKey);
      if (activeRequest) {
        try { return res.json(await activeRequest); }
        catch {
          return safeError(res, 409, `A emissão anterior não foi confirmada. Não gere outro boleto; verifique a referência ${entry.orderCode}.`, { retryable: false, state: 'unknown' });
        }
      }
      if (Date.now() - entry.updatedAt > STALE_REQUEST_MS) {
        entry.status = 'unknown';
        return safeError(res, 409, `A emissão anterior não foi confirmada. Não gere outro boleto; verifique a referência ${entry.orderCode}.`, { retryable: false, state: 'unknown' });
      }
      return safeError(res, 409, 'Já existe uma emissão em andamento para este CPF. Aguarde alguns instantes e tente novamente.', { retryable: true });
    }
    // Uma recusa definitiva da Pagar.me não criou boleto; a mesma reserva pode ser tentada novamente.
    entry.status = 'creating';
    entry.updatedAt = Date.now();
  } else {
    if (customerRequests.size >= MAX_CUSTOMERS_PER_PROCESS) {
      return safeError(res, 503, 'Limite temporário de solicitações atingido. Tente novamente mais tarde.', { retryable: true });
    }
    const identifiers = identifiersFor(clientRequestId);
    entry = {
      emailKey: keys.emailKey,
      orderCode: identifiers.orderCode,
      documentNumber: identifiers.documentNumber,
      status: 'creating',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      response: null
    };
    customerRequests.set(keys.cpfKey, entry);
  }

  const identifiers = { orderCode: entry.orderCode, documentNumber: entry.documentNumber };
  const operation = createPagarmeOrder(validation.customer, identifiers);
  inFlight.set(keys.cpfKey, operation);
  try {
    const boleto = await operation;
    entry.status = 'issued';
    entry.response = boleto;
    entry.updatedAt = Date.now();
    return res.status(201).json(boleto);
  } catch (error) {
    if (error.providerRejected) {
      entry.status = 'rejected';
      entry.updatedAt = Date.now();
      return safeError(res, 422, error.message, { retryable: true });
    }
    entry.status = 'unknown';
    entry.updatedAt = Date.now();
    console.error(`[Pagar.me] result uncertain for reference ${entry.orderCode}`);
    return safeError(
      res,
      503,
      `Não foi possível confirmar a emissão. Não gere outro boleto. Consulte o painel Pagar.me com a referência ${entry.orderCode}.`,
      { retryable: false, state: 'unknown' }
    );
  } finally {
    inFlight.delete(keys.cpfKey);
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

app.listen(port, '0.0.0.0', () => console.log(`Web service ready on port ${port}`));

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
const requestCache = new Map();
const inFlight = new Map();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CACHE_ENTRIES = 1000;

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

function pruneCache() {
  const cutoff = Date.now() - CACHE_TTL_MS;
  for (const [id, entry] of requestCache) {
    if (entry.status !== 'creating' && entry.createdAt < cutoff) requestCache.delete(id);
  }
  while (requestCache.size > MAX_CACHE_ENTRIES) {
    const oldest = [...requestCache].find(([, entry]) => entry.status !== 'creating');
    if (!oldest) break;
    requestCache.delete(oldest[0]);
  }
}

function payloadFingerprint(customer) {
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
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function identifiersFor(clientRequestId) {
  const compact = clientRequestId.replaceAll('-', '').toLowerCase();
  const numeric = (BigInt(`0x${compact}`) % 9_000_000_000_000_000n) + 1_000_000_000_000_000n;
  return { orderCode: `mei_${compact}`, documentNumber: numeric.toString() };
}

function apiFailure(res, error, entry) {
  if (error.providerRejected) {
    entry.status = 'rejected';
    return safeError(res, 422, error.message, { retryable: true });
  }
  entry.status = 'unknown';
  return safeError(
    res,
    503,
    `Não foi possível confirmar a emissão. Não gere outro boleto. Consulte o painel Pagar.me com a referência ${entry.orderCode}.`,
    { retryable: false, state: 'unknown' }
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
    error.providerRejected = response.status >= 400 && response.status < 500;
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

  pruneCache();
  const fingerprint = payloadFingerprint(validation.customer);
  const identifiers = identifiersFor(clientRequestId);
  let entry = requestCache.get(clientRequestId);

  if (entry && entry.fingerprint !== fingerprint) {
    return safeError(res, 409, 'Os dados foram alterados. Atualize a página para iniciar uma solicitação nova.', { retryable: false });
  }
  if (entry?.status === 'issued') return res.json(entry.response);
  if (entry?.status === 'unknown') {
    return safeError(res, 409, `A emissão anterior não foi confirmada. Não gere outro boleto. Referência: ${entry.orderCode}.`, { retryable: false, state: 'unknown' });
  }
  if (entry?.status === 'creating' && inFlight.has(clientRequestId)) {
    try { return res.json(await inFlight.get(clientRequestId)); }
    catch (error) { return apiFailure(res, error, entry); }
  }

  if (!entry) {
    entry = {
      fingerprint,
      orderCode: identifiers.orderCode,
      status: 'creating',
      createdAt: Date.now(),
      response: null
    };
    requestCache.set(clientRequestId, entry);
  } else {
    entry.status = 'creating';
  }

  const operation = createPagarmeOrder(validation.customer, identifiers);
  inFlight.set(clientRequestId, operation);
  try {
    const boleto = await operation;
    entry.status = 'issued';
    entry.response = boleto;
    return res.status(201).json(boleto);
  } catch (error) {
    if (error.providerRejected) return apiFailure(res, error, entry);
    console.error(`[Pagar.me] result uncertain for reference ${entry.orderCode}`);
    return apiFailure(res, error, entry);
  } finally {
    inFlight.delete(clientRequestId);
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

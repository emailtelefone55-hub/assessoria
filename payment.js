import crypto from 'node:crypto';

export const BOLETO_AMOUNT_CENTS = 5990;

export function digitsOnly(value = '') {
  return String(value).replace(/\D/g, '');
}

export function customerKeys(secret, customer) {
  if (typeof secret !== 'string' || secret.length < 32) {
    throw new Error('IDEMPOTENCY_SECRET deve ter pelo menos 32 caracteres.');
  }
  const cpf = digitsOnly(customer.cpf);
  const email = String(customer.email || '').trim().toLowerCase();
  const hmac = value => crypto.createHmac('sha256', secret).update(value).digest('hex');
  const fingerprint = JSON.stringify({
    name: String(customer.name || '').trim(),
    email,
    cpf,
    zipCode: digitsOnly(customer.zipCode),
    street: String(customer.street || '').trim(),
    number: String(customer.number || '').trim(),
    neighborhood: String(customer.neighborhood || '').trim(),
    city: String(customer.city || '').trim(),
    state: String(customer.state || '').trim().toUpperCase(),
    phone: digitsOnly(customer.phone),
    amount: BOLETO_AMOUNT_CENTS
  });
  return {
    cpfKey: hmac(`cpf:${cpf}`),
    emailKey: hmac(`email:${email}`),
    fingerprint: hmac(`fingerprint:${fingerprint}`)
  };
}

export function isValidCpf(value) {
  const cpf = digitsOnly(value);
  if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
  const calc = (base, factor) => {
    let total = 0;
    for (const digit of base) total += Number(digit) * factor--;
    const remainder = (total * 10) % 11;
    return remainder === 10 ? 0 : remainder;
  };
  const first = calc(cpf.slice(0, 9), 10);
  const second = calc(cpf.slice(0, 10), 11);
  return first === Number(cpf[9]) && second === Number(cpf[10]);
}

export function validateBoletoRequest(input, accountMode = 'gateway') {
  const data = input && typeof input === 'object' ? input : {};
  const errors = [];
  const name = String(data.fullName || '').trim();
  const email = String(data.email || '').trim();
  const cpf = digitsOnly(data.cpf);
  const zipCode = digitsOnly(data.zipCode);
  const street = String(data.address || '').trim();
  const number = String(data.number || '').trim();
  const neighborhood = String(data.neighborhood || '').trim();
  const city = String(data.city || '').trim();
  const state = String(data.state || '').trim().toUpperCase();

  if (name.length < 3 || name.length > 64) errors.push('Informe o nome completo (máximo de 64 caracteres).');
  if (email.length > 64 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('Informe um e-mail válido.');
  if (!isValidCpf(cpf)) errors.push('Informe um CPF válido.');
  if (zipCode.length !== 8) errors.push('Informe um CEP válido.');
  if (!street || street.length > 200) errors.push('Informe o logradouro.');
  if (!number || number.length > 20) errors.push('Informe o número do endereço.');
  if (!neighborhood || neighborhood.length > 100) errors.push('Informe o bairro.');
  if (!city || city.length > 100) errors.push('Informe a cidade.');
  if (!/^[A-Z]{2}$/.test(state)) errors.push('Informe a UF do endereço.');

  const phone = digitsOnly(data.phone);
  if (accountMode === 'psp' && phone.length < 10) {
    errors.push('A conta Pagar.me está configurada como PSP, modalidade que exige telefone. Inclua o telefone no formulário antes de emitir.');
  }
  if (phone && (phone.length < 10 || phone.length > 11)) errors.push('Informe um telefone brasileiro válido.');

  return {
    valid: errors.length === 0,
    errors,
    customer: { name, email, cpf, zipCode, street, number, neighborhood, city, state, phone }
  };
}

export function buildPagarmeOrder(customer, { orderCode, documentNumber, accountMode = 'gateway' }) {
  const pagarmeCustomer = {
    name: customer.name,
    email: customer.email,
    document: customer.cpf,
    document_type: 'CPF',
    type: 'individual',
    address: {
      country: 'BR',
      state: customer.state,
      city: customer.city,
      zip_code: customer.zipCode,
      line_1: `${customer.number}, ${customer.street}, ${customer.neighborhood}`.slice(0, 256)
    }
  };

  if (accountMode === 'psp' && customer.phone) {
    pagarmeCustomer.phones = {
      mobile_phone: {
        country_code: '55',
        area_code: customer.phone.slice(0, 2),
        number: customer.phone.slice(2)
      }
    };
  }

  return {
    code: orderCode,
    closed: true,
    items: [{
      amount: BOLETO_AMOUNT_CENTS,
      description: 'Assessoria MEI',
      quantity: 1,
      code: 'ASSESSORIA-MEI'
    }],
    customer: pagarmeCustomer,
    payments: [{
      payment_method: 'boleto',
      boleto: {
        instructions: 'Pagamento referente ao serviço privado opcional de assessoria MEI.',
        type: 'DM',
        document_number: documentNumber
      }
    }]
  };
}

function trustedPagarmeUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && (url.hostname === 'pagar.me' || url.hostname.endsWith('.pagar.me'))
      ? url.toString()
      : null;
  } catch {
    return null;
  }
}

export function extractBoleto(order) {
  const charges = Array.isArray(order?.charges) ? order.charges : [];
  const charge = charges.find(item => item?.payment_method === 'boleto') || charges[0];
  const transaction = charge?.last_transaction;
  const line = transaction?.line || transaction?.digitable_line || transaction?.digitableLine;
  if (!line) throw new Error('A resposta da Pagar.me não contém a linha digitável.');
  return {
    orderId: String(order.id || ''),
    amountCents: Number(order.amount ?? charge?.amount ?? BOLETO_AMOUNT_CENTS),
    digitableLine: String(line),
    boletoUrl: trustedPagarmeUrl(transaction?.url),
    pdfUrl: trustedPagarmeUrl(transaction?.pdf),
    dueAt: transaction?.due_at || null,
    status: String(charge?.status || order?.status || 'pending')
  };
}

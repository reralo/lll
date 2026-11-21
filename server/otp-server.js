// سرور ورود با کد پیامکی (OTP) برای Reralo — Node.js 18+، بدون وابستگی خارجی
// کلید API پنل پیامکی فقط در متغیر محیطی SMS_API_KEY روی سرور قرار می‌گیرد؛ هرگز داخل صفحه‌ی سایت نگذارید.
const http = require('http'), crypto = require('crypto');
const { GOOGLE_CLIENT_ID, GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs', PORT = 3000, SMS_API_KEY, SMS_TEMPLATE = 'reralo-otp', SESSION_SECRET, ALLOWED_ORIGIN = '', SMS_DRY_RUN } = process.env;
if (!SESSION_SECRET || SESSION_SECRET.length < 24) throw new Error('SESSION_SECRET (حداقل ۲۴ نویسه‌ی تصادفی) لازم است');

const OTP_TTL = 120e3, RESEND_GAP = 60e3, MAX_TRIES = 5, MAX_PER_HOUR = 5, MAX_IP_PER_HOUR = 20, SESSION_MS = 30 * 864e5;
const otps = new Map(), sends = new Map(), ipHits = new Map(); // برای چند سرور/ری‌استارت: Redis یا دیتابیس بگذارید
const hmac = s => crypto.createHmac('sha256', SESSION_SECRET).update(s).digest('hex');
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const hit = (map, key, limit, win = 36e5) => { const now = Date.now(), a = (map.get(key) || []).filter(t => now - t < win); if (a.length >= limit) return false; a.push(now); map.set(key, a); return true; };

// ===== آداپتور پنل پیامکی =====
// SMS_PROVIDER=melipayamak (پیش‌فرض) یا kavenegar
async function sendMeli(phone, code) {
  // ملی‌پیامک — پیامک پترن (خدماتی)، متد REST: BaseServiceNumber. مستندات: melipayamak.com/api
  const { MELI_USERNAME, MELI_PASSWORD, MELI_BODY_ID, MELI_BASE = 'https://rest.payamak-panel.com' } = process.env;
  if (!MELI_USERNAME || !MELI_PASSWORD || !MELI_BODY_ID) throw new Error('MELI_USERNAME / MELI_PASSWORD / MELI_BODY_ID تنظیم نشده');
  const body = new URLSearchParams({ username: MELI_USERNAME, password: MELI_PASSWORD, text: code, to: phone, bodyId: MELI_BODY_ID });
  const r = await fetch(MELI_BASE + '/api/SendSMS/BaseServiceNumber', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const j = await r.json().catch(() => ({}));
  const v = String(j.Value ?? '');
  if (!/^\d{15,}$/.test(v)) { console.error('melipayamak failed. Value:', v, 'RetStatus:', j.RetStatus, j.StrRetStatus || ''); return false; } // عدد بیش از ۱۵ رقم یعنی ارسال موفق
  return true;
}
async function sendKavenegar(phone, code) {
  if (!SMS_API_KEY) throw new Error('SMS_API_KEY تنظیم نشده');
  const url = `https://api.kavenegar.com/v1/${encodeURIComponent(SMS_API_KEY)}/verify/lookup.json?receptor=${phone}&token=${code}&template=${encodeURIComponent(SMS_TEMPLATE)}`;
  return (await fetch(url)).ok;
}
async function sendSms(phone, code) {
  if (SMS_DRY_RUN) { console.log('[DRY RUN] sms to', phone, 'code', code); return true; }
  return (process.env.SMS_PROVIDER || 'melipayamak') === 'kavenegar' ? sendKavenegar(phone, code) : sendMeli(phone, code);
}

// ===== ورود با گوگل: بررسی ID Token (امضای RS256، aud، iss، exp، email_verified) =====
let jwks = { keys: [], at: 0 };
async function getKey(kid) {
  if (Date.now() - jwks.at > 36e5 || !jwks.keys.find(k => k.kid === kid)) { const r = await fetch(GOOGLE_JWKS_URL); jwks = { keys: (await r.json()).keys || [], at: Date.now() }; }
  const k = jwks.keys.find(k => k.kid === kid); return k && crypto.createPublicKey({ key: k, format: 'jwk' });
}
async function verifyGoogle(idToken) {
  const [h, p, sg] = String(idToken || '').split('.'); if (!sg) return null;
  const head = JSON.parse(Buffer.from(h, 'base64url')), pay = JSON.parse(Buffer.from(p, 'base64url'));
  if (head.alg !== 'RS256') return null;
  const key = await getKey(head.kid); if (!key) return null;
  if (!crypto.verify('RSA-SHA256', Buffer.from(h + '.' + p), key, Buffer.from(sg, 'base64url'))) return null;
  if (!['https://accounts.google.com', 'accounts.google.com'].includes(pay.iss) || pay.aud !== GOOGLE_CLIENT_ID || !(pay.exp * 1000 > Date.now()) || !pay.email || pay.email_verified !== true) return null;
  return { email: pay.email, name: pay.name || '' };
}
const readJson = req => new Promise((res, rej) => { let b = ''; req.on('data', c => { b += c; if (b.length > 2000) { rej(new Error('big')); req.destroy(); } }); req.on('end', () => { try { res(JSON.parse(b || '{}')); } catch (e) { rej(e); } }); });
const cookie = (v, age) => `rs=${v}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${age}`;
const session = id => { const p = Buffer.from(JSON.stringify({ id, exp: Date.now() + SESSION_MS })).toString('base64url'); return `${p}.${hmac(p)}`; };
const readSession = req => { const m = /(?:^|;\s*)rs=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return null; const [p, sig] = m[1].split('.'); if (!sig || !safeEq(sig, hmac(p))) return null; try { const o = JSON.parse(Buffer.from(p, 'base64url')); return o.exp > Date.now() ? o.id : null; } catch (e) { return null; } };

http.createServer(async (req, res) => {
  const send = (code, obj, extra = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': ALLOWED_ORIGIN, 'Access-Control-Allow-Credentials': 'true', 'Vary': 'Origin', ...extra }); res.end(JSON.stringify(obj)); };
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': ALLOWED_ORIGIN, 'Access-Control-Allow-Credentials': 'true', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' }); return res.end(); }
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  try {
    if (req.method === 'POST' && req.url === '/otp/send') {
      const { phone } = await readJson(req);
      if (!/^09\d{9}$/.test(phone || '')) return send(400, { ok: false, error: 'bad_phone' });
      const prev = otps.get(phone);
      if (prev && Date.now() - prev.last < RESEND_GAP) return send(429, { ok: false, error: 'wait' });
      if (!hit(sends, phone, MAX_PER_HOUR) || !hit(ipHits, ip, MAX_IP_PER_HOUR)) return send(429, { ok: false, error: 'rate' });
      const code = String(crypto.randomInt(10000, 100000));
      otps.set(phone, { h: hmac(phone + ':' + code), exp: Date.now() + OTP_TTL, tries: 0, last: Date.now() });
      const ok = await sendSms(phone, code);
      if (!ok) { otps.delete(phone); return send(502, { ok: false, error: 'sms_failed' }); }
      return send(200, { ok: true });
    }
    if (req.method === 'POST' && req.url === '/otp/verify') {
      const { phone, code } = await readJson(req), o = otps.get(phone);
      if (!o || o.exp < Date.now() || o.tries >= MAX_TRIES) { otps.delete(phone); return send(400, { ok: false, error: 'expired' }); }
      o.tries++;
      if (!safeEq(o.h, hmac(phone + ':' + String(code || '')))) return send(400, { ok: false, error: 'wrong_code' });
      otps.delete(phone);
      return send(200, { ok: true }, { 'Set-Cookie': cookie(session('tel:' + phone), SESSION_MS / 1000) });
    }
    if (req.method === 'POST' && req.url === '/auth/google') {
      if (!GOOGLE_CLIENT_ID) return send(501, { ok: false, error: 'google_not_configured' });
      if (!hit(ipHits, 'g:' + ip, MAX_IP_PER_HOUR * 3)) return send(429, { ok: false, error: 'rate' });
      const { credential } = await readJson(req), u = await verifyGoogle(credential).catch(() => null);
      if (!u) return send(401, { ok: false, error: 'bad_token' });
      return send(200, { ok: true, email: u.email, name: u.name }, { 'Set-Cookie': cookie(session('g:' + u.email), SESSION_MS / 1000) });
    }
    if (req.method === 'GET' && req.url === '/me') { const p = readSession(req); return send(p ? 200 : 401, p ? { ok: true, id: p } : { ok: false }); }
    if (req.method === 'POST' && req.url === '/logout') return send(200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
    send(404, { ok: false });
  } catch (e) { console.error(e.message); send(500, { ok: false }); }
}).listen(PORT, () => console.log('OTP server on', PORT));

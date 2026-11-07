// Tj AI Boardroom connector — v0.4 (prototype, tested locally only; NOT deployed).
// v0.4 = v0.3 safety rules + OAuth login (Tj's Claude account has no "Request headers" option).
//   Claude registers itself, Tj sees a login page, types his PIN, and Claude gets a token.
//   Only claude.ai / claude.com may receive tokens. 5 wrong PINs lock the login for 30 minutes.
//
// Secrets/vars (set in Cloudflare, never in code or chat):
//   OPENAI_API_KEY   required (server -> OpenAI only)
//   OWNER_PIN        required, 10+ characters (Tj's login PIN)
//   PUBLIC_URL       optional; if unset, the Worker's own https address is used
//   CAP_USD          optional, 0 < cap <= 5 (default 4)
//   UPSTREAM_URL / ALLOW_TEST_UPSTREAM / TIMEOUT_MS / DECISION_LIMIT   optional, as in v0.3
// Bindings: BOARDROOM (Durable Object), OAUTH_KV (KV namespace)
import { OAuthProvider } from '@cloudflare/workers-oauth-provider';

const PROD_UPSTREAM = 'https://api.openai.com/v1/chat/completions';
const MAX_CAP_USD = 5;
const MAX_BODY_BYTES = 100_000;
const SYSTEM_PROMPT = "You are ChatGPT, the independent reviewer in Tj's AI Boardroom, talking with Claude. Challenge weak reasoning; do not just agree. Be concise. If you want Claude to answer something, end with a line starting 'QUESTION FOR CLAUDE:'.";
const MEM = { identityChars: 16000, historyChars: 8000, historyTurns: 6, storeChars: 8000, exchangeLimit: 20000, identityVersions: 200 };
const FIXED = {
  maxInputChars: 12000, maxOutputTokens: 800,
  pricePerMInput: 0.75, pricePerMOutput: 4.50, // USD per 1M tokens, small model — NOT VERIFIED
  maxConsecutiveErrors: 3, model: 'gpt-5.4-mini',
};
const NOT_BILLED = new Set([400, 401, 403, 404, 413, 415, 422, 429]);
const DEC_LIMITS = { title: 200, field: 4000, recordBytes: 16000 };
const ALLOWED_REDIRECT_HOSTS = new Set(['claude.ai', 'claude.com']);
const PIN_MAX_FAILS = 5, PIN_LOCK_MS = 30 * 60 * 1000;
const enc = new TextEncoder();
const bytes = (s) => enc.encode(s).length;

function loadConfig(env) {
  if (!env.OPENAI_API_KEY) return { error: 'missing OPENAI_API_KEY' };
  if (typeof env.OWNER_PIN !== 'string' || env.OWNER_PIN.length < 10) return { error: 'OWNER_PIN missing or shorter than 10' };
  if (env.PUBLIC_URL !== undefined && (typeof env.PUBLIC_URL !== 'string' || !/^https:\/\/[a-z0-9.-]+$/.test(env.PUBLIC_URL))) return { error: 'invalid PUBLIC_URL' };
  if (!env.OAUTH_KV || !env.BOARDROOM) return { error: 'missing bindings' };
  const intIn = (raw, lo, hi, dflt) => {
    if (raw === undefined) return dflt;
    const n = Number(raw);
    return Number.isSafeInteger(n) && n >= lo && n <= hi ? n : NaN;
  };
  const capRaw = env.CAP_USD ?? '4';
  const cap = /^\d+(\.\d{1,6})?$/.test(String(capRaw).trim()) ? Number(capRaw) : NaN;
  if (!Number.isFinite(cap) || cap <= 0 || cap > MAX_CAP_USD) return { error: 'invalid CAP_USD' };
  const timeoutMs = intIn(env.TIMEOUT_MS, 100, 120000, 60000);
  if (Number.isNaN(timeoutMs)) return { error: 'invalid TIMEOUT_MS' };
  const decisionLimit = intIn(env.DECISION_LIMIT, 1, 5000, 1000);
  if (Number.isNaN(decisionLimit)) return { error: 'invalid DECISION_LIMIT' };
  const upstream = env.UPSTREAM_URL ?? PROD_UPSTREAM;
  if (upstream !== PROD_UPSTREAM) {
    let host = '';
    try { host = new URL(upstream).hostname; } catch { return { error: 'invalid UPSTREAM_URL' }; }
    const local = host === '127.0.0.1' || host === 'localhost';
    if (!(env.ALLOW_TEST_UPSTREAM === 'true' && local)) return { error: 'UPSTREAM_URL not allowed' };
  }
  return { cfg: { ...FIXED, capUsd: cap, capMicro: Math.round(cap * 1e6), timeoutMs, decisionLimit, upstream } };
}

const json = (code, obj, extra = {}) =>
  new Response(JSON.stringify(obj), { status: code, headers: { 'content-type': 'application/json', ...extra } });
const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (code, title, body, headers = new Headers()) => {
  headers.set('content-type', 'text/html; charset=utf-8');
  headers.set('x-frame-options', 'DENY');
  headers.set('content-security-policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
  return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body style="font-family:system-ui;max-width:420px;margin:40px auto;padding:0 16px">${body}</body>`, { status: code, headers });
};

async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(a)), crypto.subtle.digest('SHA-256', enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let diff = 0; for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function readLimited(req, max) {
  const declared = Number(req.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > max) return null;
  if (!req.body) return '';
  const reader = req.body.getReader();
  const chunks = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) { await reader.cancel().catch(() => {}); return null; }
    chunks.push(value);
  }
  const all = new Uint8Array(total); let off = 0;
  for (const c of chunks) { all.set(c, off); off += c.byteLength; }
  return new TextDecoder().decode(all);
}

const boardroom = (env) => env.BOARDROOM.get(env.BOARDROOM.idFromName('main'));

// ---------- MCP endpoint (reached only with a valid OAuth token) ----------
const McpApiHandler = {
  async fetch(req, env, ctx) {
    if (loadConfig(env).error) return json(503, { error: 'server not configured' });
    if (ctx.props?.userId !== 'tj' || !String(ctx.auth?.scope ?? '').split(' ').includes('mcp')) return json(403, { error: 'forbidden' });
    if (req.method !== 'POST') return json(405, { error: 'POST only' });
    const body = await readLimited(req, MAX_BODY_BYTES);
    if (body === null) return json(413, { error: 'too large' });
    return boardroom(env).fetch('https://do/mcp', { method: 'POST', body });
  },
};

// ---------- Login page: Tj types his PIN to let Claude in ----------
const LoginHandler = {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname !== '/authorize') return page(404, 'Not found', '<p>Not found.</p>');
    if (loadConfig(env).error) return page(503, 'Unavailable', '<p>Server not configured.</p>');
    const oauth = env.OAUTH_PROVIDER;

    if (req.method === 'GET') {
      let request;
      try { request = await oauth.parseAuthRequest(req); } catch { return page(400, 'Invalid request', '<p>Invalid sign-in request.</p>'); }
      const details = await oauth.describeConsent(request);
      if (!ALLOWED_REDIRECT_HOSTS.has(details.redirectHost)) return page(400, 'Refused', '<p>Only Claude may connect to this Boardroom.</p>');
      // v0.5.1: keep the pending sign-in in the Durable Object (strongly consistent), not a KV+cookie pair.
      const handle = [...crypto.getRandomValues(new Uint8Array(24))].map(b => b.toString(16).padStart(2, '0')).join('');
      await boardroom(env).fetch('https://do/consent-put', { method: 'POST', body: JSON.stringify({ handle, request }) });
      const h = new Headers({ 'cache-control': 'no-store' });
      return page(200, 'Tj AI Boardroom', `
        <h2>Connect ${esc(details.clientName || 'app')} to Tj's AI Boardroom?</h2>
        <p>Access goes to <strong>${esc(details.redirectHost)}</strong>. It lets Claude ask ChatGPT and save decisions, within the spending cap.</p>
        <form method="post">
          <input type="hidden" name="handle" value="${esc(handle)}">
          <p><label>PIN<br><input name="pin" type="password" autocomplete="current-password" required style="font-size:18px;width:100%"></label></p>
          <p><button name="decision" value="approve" style="font-size:18px">Allow</button>
             <button name="decision" value="deny" formnovalidate style="font-size:18px">Deny</button></p>
        </form>`, h);
    }

    if (req.method === 'POST') {
      const form = await req.formData();
      const handle = String(form.get('handle') ?? '');
      const take = async () => (await (await boardroom(env).fetch('https://do/consent-take', { method: 'POST', body: JSON.stringify({ handle }) })).json());
      if (form.get('decision') !== 'approve') { await take(); return page(200, 'Cancelled', '<p>Cancelled. You can close this tab.</p>'); }
      const check = await (await boardroom(env).fetch('https://do/pin-check', { method: 'POST', body: JSON.stringify({ pin: String(form.get('pin') ?? '') }) })).json();
      if (!check.ok) return page(check.locked ? 429 : 401, 'Wrong PIN', check.locked ? '<p>Too many wrong PINs. Try again in 30 minutes.</p>' : '<p>Wrong PIN. Go back and try again.</p>');
      const pending = await take();
      if (!pending.request) return page(400, 'Invalid request', '<p>Sign-in expired (' + esc(pending.why || 'unknown') + '). Start again from Claude.</p>');
      let redirectTo;
      try {
        ({ redirectTo } = await oauth.completeAuthorization({
          request: pending.request, userId: 'tj', metadata: {}, scope: ['mcp'], props: { userId: 'tj' },
        }));
      } catch (e) { return page(400, 'Invalid request', '<p>Could not finish sign-in: ' + esc(String(e && e.message || e).slice(0, 200)) + '. Start again from Claude.</p>'); }
      return new Response(null, { status: 302, headers: { Location: redirectTo, 'cache-control': 'no-store' } });
    }
    return page(405, 'Not allowed', '<p>Method not allowed.</p>');
  },
};

let provider = null, providerFor = null;
export default {
  async fetch(req, env, ctx) {
    if (loadConfig(env).error) return json(503, { error: 'server not configured' }); // fail closed
    // Our own address: PUBLIC_URL if set, otherwise the https address Cloudflare delivered this request to.
    const origin = env.PUBLIC_URL ?? new URL(req.url).origin;
    if (!/^https:\/\/[a-z0-9.-]+$/.test(origin)) return json(503, { error: 'https only' });
    if (!provider || providerFor !== origin) {
      provider = new OAuthProvider({
        apiRoute: '/mcp', apiHandler: McpApiHandler, defaultHandler: LoginHandler,
        authorizeEndpoint: '/authorize', tokenEndpoint: '/token', clientRegistrationEndpoint: '/register',
        scopesSupported: ['mcp'], requiredScopes: ['mcp'],
        resourceMetadata: { resource: `${origin}/mcp`, authorization_servers: [origin] },
      });
      providerFor = origin;
    }
    return provider.fetch(req, env, ctx);
  },
};

const NEW_LEDGER = () => ({ spentMicro: 0, reservedMicro: 0, calls: 0, consecutiveErrors: 0, overruns: 0, decisions: 0,
  pinFails: 0, pinLockedUntil: 0, exchanges: 0, threadStart: '', identityVersion: 0,
  breaker: { open: false, reason: null, at: null } });

const CONSENT_TTL_MS = 15 * 60 * 1000;
export class Boardroom {
  constructor(ctx, env) {
    this.ctx = ctx; this.env = env;
    const { cfg, error } = loadConfig(env);
    this.C = cfg; this.configError = error;
    ctx.blockConcurrencyWhile(async () => {
      this.ledger = { ...NEW_LEDGER(), ...((await ctx.storage.get('ledger')) ?? {}) };
      this.identity = (await ctx.storage.get('identity')) ?? null;
      if (this.ledger.reservedMicro > 0) { this.ledger.spentMicro += this.ledger.reservedMicro; this.ledger.reservedMicro = 0; }
      if (this.C && this.ledger.spentMicro >= this.C.capMicro && !this.ledger.breaker.open) this.trip(`spend cap $${this.C.capUsd} reached`);
      await ctx.storage.put('ledger', this.ledger);
    });
  }

  persist() { return this.ctx.storage.put('ledger', this.ledger); }
  trip(reason) { if (!this.ledger.breaker.open) this.ledger.breaker = { open: true, reason, at: new Date().toISOString() }; }
  cost(inTok, outTok) { return Math.ceil(inTok * this.C.pricePerMInput + outTok * this.C.pricePerMOutput); }

  // PIN check lives here so attempts are counted in one place (no parallel guessing past the limit).
  async pinCheck(pin) {
    const L = this.ledger, now = Date.now();
    if (L.pinLockedUntil > now) return { ok: false, locked: true };
    L.pinFails = L.pinLockedUntil && L.pinLockedUntil <= now && L.pinFails >= PIN_MAX_FAILS ? 0 : L.pinFails;
    const good = typeof pin === 'string' && await safeEqual(pin, this.env.OWNER_PIN);
    if (good) { L.pinFails = 0; L.pinLockedUntil = 0; await this.persist(); return { ok: true }; }
    L.pinFails += 1;
    if (L.pinFails >= PIN_MAX_FAILS) L.pinLockedUntil = now + PIN_LOCK_MS;
    await this.persist();
    return { ok: false, locked: L.pinFails >= PIN_MAX_FAILS };
  }

  // ---- ChatGPT identity package (written by Tj's real ChatGPT). Old versions are kept, never deleted. ----
  async setIdentity(text) {
    if (typeof text !== 'string' || !text.trim()) return { error: 'identity text required' };
    if (text.length > MEM.identityChars) return { error: `identity too long (${text.length} > ${MEM.identityChars} chars)` };
    const L = this.ledger;
    if (L.identityVersion >= MEM.identityVersions) return { error: 'identity version limit reached; nothing deleted automatically' };
    const rec = { version: L.identityVersion + 1, at: new Date().toISOString(), text };
    L.identityVersion = rec.version;
    await this.ctx.storage.put({ identity: rec, [`idv:${String(rec.version).padStart(6, '0')}`]: rec, ledger: L });
    this.identity = rec;
    return { saved: true, version: rec.version, chars: text.length };
  }
  async identityVersions() {
    const map = await this.ctx.storage.list({ prefix: 'idv:', reverse: true, limit: 50 });
    return { versions: [...map.values()].map((r) => ({ version: r.version, at: r.at, chars: r.text.length })) };
  }
  getIdentity() {
    return this.identity ? { version: this.identity.version, at: this.identity.at, text: this.identity.text } : { version: 0, text: '' };
  }

  // ---- Thread memory: recent successful exchanges in the current topic. ----
  async startNewTopic() {
    this.ledger.threadStart = new Date().toISOString();
    await this.persist();
    return { newTopic: true, since: this.ledger.threadStart, note: 'Older exchanges are kept in the audit log, just not sent to ChatGPT.' };
  }
  async history() {
    const L = this.ledger;
    const map = await this.ctx.storage.list({ prefix: 'thr:', start: `thr:${L.threadStart}`, reverse: true, limit: MEM.historyTurns * 4 });
    const out = []; let used = 0;
    for (const r of map.values()) {
      if (r.status !== 'ok' || r.at < L.threadStart) continue;
      const size = r.question.length + r.answer.length;
      if (out.length >= MEM.historyTurns || used + size > MEM.historyChars) break;
      out.push(r); used += size;
    }
    return out.reverse(); // oldest first
  }
  async listThread(limit = 10) {
    const n = Math.min(Math.max(1, Math.floor(Number(limit)) || 10), 30);
    const map = await this.ctx.storage.list({ prefix: 'thr:', reverse: true, limit: n });
    return { exchanges: [...map.values()], threadStart: this.ledger.threadStart || null };
  }
  async record(rec) { // audit record of every paid attempt (ok or error)
    const L = this.ledger;
    if (L.exchanges >= MEM.exchangeLimit) { await this.persist(); return false; }
    L.exchanges += 1;
    await this.ctx.storage.put({ [`thr:${rec.at}:${crypto.randomUUID()}`]: rec, ledger: L });
    return true;
  }

  async askChatGPT(question, context = '', fresh = false) {
    const C = this.C, L = this.ledger;
    if (typeof question !== 'string' || !question.trim()) return { error: 'empty question' };
    if (context !== undefined && context !== null && typeof context !== 'string') return { error: 'context must be text' };
    const prompt = (context ? `Context:\n${context}\n\n` : '') + `Question:\n${question}`;
    if (prompt.length > C.maxInputChars) return { error: `input too long (${prompt.length} > ${C.maxInputChars} chars)` };
    if (L.breaker.open) return { error: `circuit breaker OPEN: ${L.breaker.reason}` };

    // Build everything ChatGPT will see BEFORE reserving, so the reservation covers all of it.
    const system = this.identity ? `${SYSTEM_PROMPT}\n\n=== Tj's ChatGPT identity & knowledge package (v${this.identity.version}) ===\n${this.identity.text}` : SYSTEM_PROMPT;
    const past = fresh === true ? [] : await this.history();
    const messages = [{ role: 'system', content: system }];
    for (const r of past) messages.push({ role: 'user', content: r.question }, { role: 'assistant', content: r.answer });
    messages.push({ role: 'user', content: prompt });
    const inputBound = messages.reduce((n, m) => n + bytes(m.content) + 16, 64); // tokens <= bytes, + per-message overhead
    const worst = this.cost(inputBound, C.maxOutputTokens);

    // check + reserve with no await in between
    if (L.breaker.open) return { error: `circuit breaker OPEN: ${L.breaker.reason}` };
    if (L.spentMicro + L.reservedMicro + worst > C.capMicro) {
      if (L.spentMicro + worst > C.capMicro) { this.trip(`spend cap $${C.capUsd} reached`); await this.persist(); }
      return { error: `spend cap: $${(L.spentMicro / 1e6).toFixed(4)} spent, $${(L.reservedMicro / 1e6).toFixed(4)} in flight, cap $${C.capUsd}` };
    }
    L.reservedMicro += worst;
    await this.persist();

    let res = null, body = null;
    try {
      res = await fetch(C.upstream, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${this.env.OPENAI_API_KEY}` },
        body: JSON.stringify({ model: C.model, max_completion_tokens: C.maxOutputTokens, messages }),
        signal: AbortSignal.timeout(C.timeoutMs),
      });
      body = await res.json().catch(() => null);
    } catch { res = null; }

    const at = new Date().toISOString();
    const stored = { at, question: prompt.slice(0, MEM.storeChars), historyUsed: past.length, identityVersion: this.identity?.version ?? 0 };
    L.reservedMicro = Math.max(0, L.reservedMicro - worst);
    if (!res || !res.ok) {
      const billed = !res || !NOT_BILLED.has(res.status);
      if (billed) L.spentMicro += worst;
      L.consecutiveErrors += 1;
      if (L.consecutiveErrors >= C.maxConsecutiveErrors) this.trip(`${L.consecutiveErrors} upstream errors in a row`);
      if (L.spentMicro >= C.capMicro) this.trip(`spend cap $${C.capUsd} reached`);
      const err = `upstream error (${res ? `status ${res.status}` : 'network/timeout'})${billed ? ' — counted as possibly billed' : ''}`;
      await this.record({ ...stored, status: 'error', answer: '', error: err, costMicro: billed ? worst : 0 });
      return { error: err };
    }
    const u = (body && typeof body === 'object' && body.usage) || {};
    const okTok = (n) => Number.isSafeInteger(n) && n >= 0;
    const usageValid = okTok(u.prompt_tokens) && okTok(u.completion_tokens);
    const actual = usageValid ? this.cost(u.prompt_tokens, u.completion_tokens) : worst;
    if (actual > worst) { L.overruns += 1; this.trip(`usage exceeded reservation (${actual} > ${worst} micro-USD)`); }
    L.spentMicro += actual; L.calls += 1; L.consecutiveErrors = 0;
    if (L.spentMicro >= C.capMicro) this.trip(`spend cap $${C.capUsd} reached`);
    const raw = body?.choices?.[0]?.message?.content;
    const answer = typeof raw === 'string' ? raw : '';
    const saved = await this.record({ ...stored, status: 'ok', answer: answer.slice(0, MEM.storeChars), costMicro: actual });
    return {
      answer, historyUsed: past.length, identityVersion: this.identity?.version ?? 0,
      ...(saved ? {} : { warning: 'exchange log full: this answer was not saved to thread memory' }),
      costUsd: actual / 1e6, spentUsd: L.spentMicro / 1e6,
      remainingUsd: Math.max(0, C.capMicro - L.spentMicro) / 1e6,
      ...(usageValid ? {} : { note: 'usage missing/invalid — charged worst case' }),
    };
  }

  async logDecision(a) {
    const F = ['title', 'decision', 'claude', 'chatgpt', 'disagreements'];
    for (const f of F) if (a[f] !== undefined && typeof a[f] !== 'string') return { error: `${f} must be text` };
    if (!a.title || !a.decision) return { error: 'title and decision required' };
    if (a.title.length > DEC_LIMITS.title) return { error: `title too long (max ${DEC_LIMITS.title})` };
    for (const f of F.slice(1)) if ((a[f] || '').length > DEC_LIMITS.field) return { error: `${f} too long (max ${DEC_LIMITS.field})` };
    const at = new Date().toISOString();
    const rec = { at }; for (const f of F) rec[f] = a[f] || '';
    if (bytes(JSON.stringify(rec)) > DEC_LIMITS.recordBytes) return { error: 'record too large' };
    const L = this.ledger;
    if (L.decisions >= this.C.decisionLimit) return { error: `decision log full (${this.C.decisionLimit}). Tj must archive old records; nothing is deleted automatically.` };
    L.decisions += 1;
    await this.ctx.storage.put({ [`dec:${at}:${crypto.randomUUID()}`]: rec, ledger: L });
    return { saved: true, at, count: L.decisions };
  }

  async listDecisions(limit = 10) {
    const n = Math.min(Math.max(1, Math.floor(Number(limit)) || 10), 50);
    const map = await this.ctx.storage.list({ prefix: 'dec:', reverse: true, limit: n });
    return { decisions: [...map.values()] };
  }

  async fetch(req) {
    if (this.configError) return json(503, { error: 'server not configured' });
    const path = new URL(req.url).pathname;
    if (path === '/consent-put') {
      let m = {}; try { m = await req.json(); } catch {}
      if (typeof m.handle !== 'string' || m.handle.length < 32 || !m.request) return json(400, { error: 'bad' });
      // drop old pending sign-ins so storage can't grow
      const old = await this.ctx.storage.list({ prefix: 'consent:' });
      const cutoff = Date.now() - CONSENT_TTL_MS;
      for (const [k, v] of old) if (!v || v.at < cutoff) await this.ctx.storage.delete(k);
      if (old.size > 20) return json(429, { error: 'too many pending' });
      await this.ctx.storage.put('consent:' + m.handle, { request: m.request, at: Date.now() });
      return json(200, { ok: true });
    }
    if (path === '/consent-take') {
      let m = {}; try { m = await req.json(); } catch {}
      if (typeof m.handle !== 'string' || m.handle.length < 32) return json(200, { why: 'no handle' });
      const key = 'consent:' + m.handle;
      const v = await this.ctx.storage.get(key);
      if (!v) return json(200, { why: 'not found or already used' });
      await this.ctx.storage.delete(key);
      if (Date.now() - v.at > CONSENT_TTL_MS) return json(200, { why: 'older than 15 minutes' });
      return json(200, { request: v.request });
    }
    if (path === '/pin-check') {
      let pin = ''; try { pin = (await req.json()).pin; } catch {}
      return json(200, await this.pinCheck(pin));
    }
    let msg; try { msg = JSON.parse(await req.text()); } catch { return json(400, { error: 'bad json' }); }
    if (!msg || typeof msg !== 'object') return json(400, { error: 'bad json' });
    const reply = (result) => json(200, { jsonrpc: '2.0', id: msg.id ?? null, result });
    if (msg.method === 'initialize') return reply({ protocolVersion: '2025-06-18', serverInfo: { name: 'tj-boardroom', version: '0.5.1-cf' }, capabilities: { tools: {} } });
    if (msg.method === 'notifications/initialized') return new Response(null, { status: 202 });
    if (msg.method === 'tools/list') return reply({ tools: TOOLS });
    if (msg.method === 'tools/call') {
      const { name, arguments: a } = msg.params || {};
      const args = a && typeof a === 'object' ? a : {};
      let out;
      if (name === 'ask_chatgpt') out = await this.askChatGPT(args.question, args.context, args.fresh);
      else if (name === 'set_chatgpt_identity') out = await this.setIdentity(args.text);
      else if (name === 'get_chatgpt_identity') out = this.getIdentity();
      else if (name === 'list_identity_versions') out = await this.identityVersions();
      else if (name === 'start_new_topic') out = await this.startNewTopic();
      else if (name === 'list_thread') out = await this.listThread(args.limit);
      else if (name === 'log_decision') out = await this.logDecision(args);
      else if (name === 'list_decisions') out = await this.listDecisions(args.limit);
      else if (name === 'budget_status') { const L = this.ledger; out = { spentUsd: L.spentMicro / 1e6, reservedUsd: L.reservedMicro / 1e6, calls: L.calls, exchanges: L.exchanges, identityVersion: L.identityVersion, consecutiveErrors: L.consecutiveErrors, overruns: L.overruns, decisions: L.decisions, breaker: L.breaker, capUsd: this.C.capUsd }; }
      else out = { error: 'unknown tool' };
      return reply({ content: [{ type: 'text', text: JSON.stringify(out) }], isError: !!out.error });
    }
    return json(200, { jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32601, message: 'method not found' } });
  }
}

const TOOLS = [
  { name: 'ask_chatgpt', description: "Ask ChatGPT (Tj's independent reviewer). It remembers recent exchanges in the current topic and has Tj's identity package. If its answer has 'QUESTION FOR CLAUDE:', answer it with another ask_chatgpt call when Tj wants a debate. Set fresh=true to ask without history.",
    inputSchema: { type: 'object', properties: { question: { type: 'string' }, context: { type: 'string' }, fresh: { type: 'boolean' } }, required: ['question'] } },
  { name: 'set_chatgpt_identity', description: "Save Tj's ChatGPT identity & knowledge package (only when Tj pastes one and says to save it). Old versions are kept.",
    inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
  { name: 'get_chatgpt_identity', description: 'Show the current ChatGPT identity package and its version.',
    inputSchema: { type: 'object', properties: {} } },
  { name: 'list_identity_versions', description: 'List saved versions of the ChatGPT identity package (newest first).',
    inputSchema: { type: 'object', properties: {} } },
  { name: 'start_new_topic', description: 'Start a new topic so ChatGPT stops seeing the previous discussion (nothing is deleted).',
    inputSchema: { type: 'object', properties: {} } },
  { name: 'list_thread', description: 'Show recent ChatGPT exchanges (audit log: questions, answers, cost, errors).',
    inputSchema: { type: 'object', properties: { limit: { type: 'number' } } } },
  { name: 'log_decision', description: 'Save a Boardroom decision record.',
    inputSchema: { type: 'object', properties: { title: { type: 'string' }, decision: { type: 'string' }, claude: { type: 'string' }, chatgpt: { type: 'string' }, disagreements: { type: 'string' } }, required: ['title', 'decision'] } },
  { name: 'list_decisions', description: 'Read recent Boardroom decisions (newest first).',
    inputSchema: { type: 'object', properties: { limit: { type: 'number' } } } },
  { name: 'budget_status', description: 'Show spending, remaining budget and breaker state.',
    inputSchema: { type: 'object', properties: {} } },
];

import { DurableObject } from 'cloudflare:workers';

// 路由：
//   GET  /api/churches                 召會清單
//   POST /api/churches                 新增召會 {name}（預設密碼 0000）→ {id, name, token}
//   POST /api/churches/:id/login       {password} → {id, name, token}
//   POST /api/churches/:id/password    {password}（需 Authorization: Bearer token）
//   GET  /api/churches/:id/ws?token=   即時同步 WebSocket

const DEFAULT_PASSWORD = '0000';
const MAX_DOC_BYTES = 1_500_000;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8' } });

const randomHex = bytes => [...crypto.getRandomValues(new Uint8Array(bytes))].map(b => b.toString(16).padStart(2, '0')).join('');

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function readJson(req) {
  try { return await req.json(); } catch { return {}; }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const parts = url.pathname.split('/').filter(Boolean); // ['api','churches',id,action]
    if (parts[0] !== 'api' || parts[1] !== 'churches') return env.ASSETS.fetch(req);

    const registry = env.REGISTRY.get(env.REGISTRY.idFromName('registry'));

    if (parts.length === 2) {
      if (req.method === 'GET') return json(await registry.list());
      if (req.method === 'POST') {
        const name = String((await readJson(req)).name || '').trim();
        if (!name || name.length > 30) return json({ error: '請輸入召會名稱（30 字以內）' }, 400);
        const res = await registry.create(name);
        if (res.error) return json(res, 400);
        const room = env.CHURCH.get(env.CHURCH.idFromName(res.id));
        await room.init(res.id, name, DEFAULT_PASSWORD);
        const token = await room.issueToken();
        return json({ id: res.id, name, token });
      }
      return json({ error: 'method' }, 405);
    }

    const id = parts[2];
    if (!/^[a-z0-9]{8,32}$/.test(id) || !(await registry.has(id))) return json({ error: '找不到這個召會' }, 404);
    const room = env.CHURCH.get(env.CHURCH.idFromName(id));
    const action = parts[3];

    if (action === 'login' && req.method === 'POST') {
      const res = await room.login(String((await readJson(req)).password || ''));
      return json(res, res.error ? 403 : 200);
    }
    if (action === 'password' && req.method === 'POST') {
      const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
      const res = await room.setPassword(token, String((await readJson(req)).password || ''));
      return json(res, res.error ? 403 : 200);
    }
    if (action === 'ws') {
      if (req.headers.get('upgrade') !== 'websocket') return json({ error: 'expected websocket' }, 426);
      return room.fetch(req);
    }
    return json({ error: 'not found' }, 404);
  },
};

// 全部召會的名單（只存 id 與名稱，不含密碼）
export class Registry extends DurableObject {
  async list() {
    const list = (await this.ctx.storage.get('churches')) || [];
    return list.map(({ id, name }) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name, 'zh-Hant'));
  }
  async has(id) {
    return ((await this.ctx.storage.get('churches')) || []).some(c => c.id === id);
  }
  async create(name) {
    const list = (await this.ctx.storage.get('churches')) || [];
    if (list.some(c => c.name === name)) return { error: '已有同名的召會，請直接點選登入' };
    if (list.length >= 1000) return { error: '召會數量已達上限' };
    const id = randomHex(8);
    list.push({ id, name, created: Date.now() });
    await this.ctx.storage.put('churches', list);
    return { id };
  }
}

// 每個召會一個房間：存密碼、登入憑證、點名資料，並即時廣播修改
export class ChurchRoom extends DurableObject {
  async init(id, name, password) {
    if (await this.ctx.storage.get('meta')) return;
    const salt = randomHex(16);
    await this.ctx.storage.put('meta', { id, name, salt, hash: await sha256(salt + password) });
    await this.ctx.storage.put('doc', {});
  }

  async issueToken() {
    const token = randomHex(24);
    await this.ctx.storage.put('tok:' + (await sha256(token)), Date.now());
    return token;
  }

  async validToken(token) {
    if (!token || token.length > 100) return false;
    return !!(await this.ctx.storage.get('tok:' + (await sha256(token))));
  }

  async login(password) {
    const meta = await this.ctx.storage.get('meta');
    if (!meta) return { error: '找不到這個召會' };
    const fail = (await this.ctx.storage.get('fail')) || { n: 0, until: 0 };
    if (Date.now() < fail.until) return { error: `密碼錯誤次數過多，請 ${Math.ceil((fail.until - Date.now()) / 60000)} 分鐘後再試` };
    if ((await sha256(meta.salt + password)) !== meta.hash) {
      fail.n += 1;
      if (fail.n >= 5) { fail.until = Date.now() + 5 * 60_000; fail.n = 0; }
      await this.ctx.storage.put('fail', fail);
      return { error: '密碼錯誤' };
    }
    await this.ctx.storage.delete('fail');
    return { id: meta.id, name: meta.name, token: await this.issueToken() };
  }

  // 改密碼只影響之後新登入的人；已登入的服事者保持登入
  async setPassword(token, password) {
    if (!(await this.validToken(token))) return { error: '請重新登入' };
    if (password.length < 4 || password.length > 32) return { error: '密碼需 4～32 個字元' };
    const meta = await this.ctx.storage.get('meta');
    meta.salt = randomHex(16);
    meta.hash = await sha256(meta.salt + password);
    await this.ctx.storage.put('meta', meta);
    return { ok: true };
  }

  async fetch(req) {
    const token = new URL(req.url).searchParams.get('token');
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    if (!(await this.validToken(token))) {
      server.send(JSON.stringify({ type: 'auth-error' }));
      server.close(4001, 'unauthorized');
    } else {
      const meta = await this.ctx.storage.get('meta');
      server.send(JSON.stringify({ type: 'state', name: meta.name, doc: (await this.ctx.storage.get('doc')) || {} }));
    }
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (msg.type !== 'set' || !validPath(msg.path)) return;
    const doc = (await this.ctx.storage.get('doc')) || {};
    applySet(doc, msg.path, msg.value);
    if (JSON.stringify(doc).length > MAX_DOC_BYTES) {
      ws.send(JSON.stringify({ type: 'ack', id: msg.id, error: '資料量過大' }));
      return;
    }
    await this.ctx.storage.put('doc', doc);
    ws.send(JSON.stringify({ type: 'ack', id: msg.id }));
    const out = JSON.stringify({ type: 'set', path: msg.path, value: msg.value ?? null });
    for (const other of this.ctx.getWebSockets()) if (other !== ws) { try { other.send(out); } catch {} }
  }

  async webSocketClose(ws, code) {
    try { ws.close(code === 1005 ? 1000 : code); } catch {}
  }
}

const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
function validPath(p) {
  return Array.isArray(p) && p.length > 0 && p.length <= 8 && p.every(k => typeof k === 'string' && k.length > 0 && k.length <= 64 && !BAD_KEYS.has(k));
}

// 設定 doc 中某路徑的值；null 代表刪除
function applySet(doc, path, value) {
  let o = doc;
  for (const k of path.slice(0, -1)) {
    if (typeof o[k] !== 'object' || o[k] === null || Array.isArray(o[k])) o[k] = {};
    o = o[k];
  }
  const last = path[path.length - 1];
  if (value === null || value === undefined) delete o[last];
  else o[last] = value;
}

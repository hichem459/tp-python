// api.mjs : port Netlify de api.php (suivi des étudiants, publication, enseignants délégués, photos, documents, base de données).
// Stockage : Netlify Blobs (store « tppython »), à la place du dossier api_private/ de la version PHP.
// Même protocole que api.php : les URL « api.php?action=… » du site sont redirigées ici (voir netlify.toml).
import { getStore } from '@netlify/blobs';
import { createHash, randomBytes, scryptSync, pbkdf2Sync, timingSafeEqual } from 'node:crypto';

export const config = { path: '/api.php' };

const store = getStore({ name: 'tppython', consistency: 'strong' });
const MAXBIN = 5 * 1024 * 1024;   // limite Netlify Functions : ~6 Mo par requête

/* ---------- utilitaires ---------- */
class Out { constructor(a, c) { this.a = a; this.c = c || 200; } }
const out = (a, c) => { throw new Out(a, c); };
const nowms = () => Date.now();
const sha256 = s => createHash('sha256').update(s).digest('hex');
const hex = n => randomBytes(n).toString('hex');
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => o !== null && o !== undefined && o[k] !== undefined && o[k] !== null;
const num = v => (typeof v === 'number' ? v : (typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN));
const isNum = v => Number.isFinite(num(v));
const toBuf = ab => Buffer.from(ab);
const ab = buf => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
const cut = (s, n) => Array.from(String(s)).slice(0, n).join('');
const sleep = ms => new Promise(r => setTimeout(r, ms));

let REQ = null;   // contexte de la requête en cours
const P = k => REQ.url.searchParams.get(k);
const getp = k => (P(k) === null ? '' : P(k));
const chk_sid = s => (typeof s === 'string' && /^u[0-9a-f]{24}$/.test(s)) ? s : null;
const client_ip = () => {
  const h = REQ.req.headers;
  for (const c of [h.get('x-nf-client-connection-ip'), REQ.ctx && REQ.ctx.ip, h.get('cf-connecting-ip'), h.get('x-forwarded-for'), h.get('x-real-ip')]) {
    if (!c) continue;
    for (const x of String(c).split(',')) { const t = x.trim(); if (/^[0-9a-fA-F:.]{3,45}$/.test(t)) return t; }
  }
  return '';
};
const json = (raw) => { try { const j = JSON.parse(raw); return j; } catch (e) { return null; } };
const jbody = () => { const j = json(REQ.raw); return (isObj(j) || Array.isArray(j)) ? j : null; };

/* ---------- accès au stockage ---------- */
const MC = new Map();   // petit cache mémoire (lectures fréquentes : live/, prog/)
async function jget(key, def) {
  let v;
  try { v = await store.get(key, { type: 'json' }); } catch (e) { if (e instanceof SyntaxError) return def; throw e; }
  return (v !== null && v !== undefined && typeof v === 'object') ? v : def;
}
async function jput(key, d) { MC.delete(key); await store.set(key, JSON.stringify(d)); }
async function jgetc(key, ttl) { const c = MC.get(key); if (c && nowms() - c.t < ttl) return c.v; const v = await jget(key, null); MC.set(key, { t: nowms(), v }); return v; }
async function del(key) { MC.delete(key); try { await store.delete(key); } catch (e) {} }
async function listKeys(prefix) { const r = await store.list({ prefix }); return (r.blobs || []).map(b => b.key); }
async function bget(key) { const r = await store.get(key, { type: 'arrayBuffer' }); return r ? toBuf(r) : null; }
async function bput(key, buf) { await store.set(key, ab(buf)); }

/* verrou global (remplace flock) : écriture conditionnelle Netlify Blobs ; sans support, on continue sans verrou */
let LOCKED = false;
async function lockit() {
  if (LOCKED) return; const end = nowms() + 9000;
  for (;;) {
    let r; try { r = await store.set('lock', JSON.stringify({ t: nowms() }), { onlyIfNew: true }); } catch (e) { LOCKED = false; return; }
    if (r === undefined || r === null || r.modified !== false) { LOCKED = true; return; }
    try {
      const g = await store.getWithMetadata('lock', { type: 'json' });
      if (!g || !g.data || nowms() - (g.data.t || 0) > 12000) {
        const r2 = await store.set('lock', JSON.stringify({ t: nowms() }), g && g.etag ? { onlyIfMatch: g.etag } : { onlyIfNew: true });
        if (r2 === undefined || r2 === null || r2.modified !== false) { LOCKED = true; return; }
      }
    } catch (e) {}
    if (nowms() > end) return;   // ne bloque jamais le service
    await sleep(60 + Math.floor(Math.random() * 140));
  }
}
async function unlock() { if (LOCKED) { LOCKED = false; try { await store.delete('lock'); } catch (e) {} } }

/* ---------- mots de passe ---------- */
function hashPw(pw) { const s = randomBytes(16); return 'scrypt$' + s.toString('hex') + '$' + scryptSync(pw, s, 32).toString('hex'); }
function verifyPw(pw, h) {
  if (typeof h !== 'string' || !h.startsWith('scrypt$')) return false;
  const p = h.split('$'); if (p.length !== 3) return false;
  try { const a = scryptSync(pw, Buffer.from(p[1], 'hex'), 32), b = Buffer.from(p[2], 'hex'); return a.length === b.length && timingSafeEqual(a, b); } catch (e) { return false; }
}
const legacyHash = h => typeof h === 'string' && h.startsWith('$2');

/* ---------- clé administrateur ---------- */
async function okey() {
  const k = getp('key'); if (k.length < 16) return false;
  const f = await store.get('keysha', { type: 'text' }); if (!f) return false;
  const a = Buffer.from(f.trim()), b = Buffer.from(sha256(k)); return a.length === b.length && timingSafeEqual(a, b);
}

/* ---------- publication (pub.json) ---------- */
let PUB = null;   // { text, obj, pv, at }
async function pubload(ttl) {
  if (PUB && nowms() - PUB.at < (ttl || 0)) return PUB;
  const text = await store.get('pub', { type: 'text' });
  if (!text) { PUB = null; return null; }
  let obj = null; try { obj = JSON.parse(text); } catch (e) {}
  PUB = { text, obj: isObj(obj) ? obj : null, pv: text.length + '-' + createHash('md5').update(text).digest('hex'), at: nowms() };
  return PUB;
}
async function pubread() { const p = await pubload(0); return p ? p.obj : null; }
function norm_settings(s) { for (const k of ['tps', 'groups', 'weeks', 'contentBy', 'groupClass']) s[k] = (isObj(s[k]) && Object.keys(s[k]).length) ? s[k] : {}; }
async function pubwrite(pub) { if (isObj(pub.settings)) norm_settings(pub.settings); pub.t = nowms(); const text = JSON.stringify(pub); await store.set('pub', text); PUB = null; }

/* ---------- enseignants ---------- */
const teachers = () => jget('teachers', {});
async function pw_taken(ts, pw, except) { for (const id of Object.keys(ts)) { if (id !== except && verifyPw(pw, ts[id].hash)) return true; } return false; }
function clean_groups(g) { const o = []; if (Array.isArray(g)) for (let x of g) { x = String(x).trim(); if (x !== '' && x.length <= 80 && !o.includes(x)) o.push(x); } return o; }
async function tauth() {
  const tok = getp('tok');
  if (!/^[0-9a-f]{48}$/.test(tok)) out({ ok: false, error: 'session', code: 'session' }, 401);
  const key = 'tsess/' + sha256(tok); const s = await jget(key, null);
  if (!s || s.exp < nowms()) { await del(key); out({ ok: false, error: 'session expirée', code: 'session' }, 401); }
  const ts = await teachers(); if (!ts[s.tid]) { await del(key); out({ ok: false, error: 'compte retiré', code: 'session' }, 401); }
  return [s.tid, ts[s.tid], key];
}
function allowed_sids(pub, groups) { const o = []; if (pub && isObj(pub.students)) for (const sid of Object.keys(pub.students)) { const s = pub.students[sid]; if (has(s, 'group') && groups.includes(s.group)) o.push(sid); } return o; }
async function prog_of(sid) {
  const p = await jgetc('prog/' + sid, 3000); if (p) return p;
  const d = await jget('rep/' + sid, null); if (!d || !isObj(d.r)) return null;
  const o = { qs: has(d.r, 'qs') ? d.r.qs : {}, att: has(d.r, 'att') ? d.r.att : {}, rt: has(d, 'rt') ? d.rt : 0 };
  await jput('prog/' + sid, o); return o;
}
function qadd(q, key, item) {
  q.seq = (q.seq || 0) + 1; item.seq = q.seq; if (!isObj(q.items)) q.items = {};
  if (item.op === 'att' && q.items[key]) item.set = Object.assign({}, q.items[key].set, item.set);
  q.items[key] = item;
}
function clean_ses(v) {
  if (!isObj(v) || !['open', 'active', 'closed'].includes(v.state)) return null; const o = { state: v.state };
  for (const k of ['dur', 'start', 'end', 'closedAt']) if (has(v, k) && isNum(v[k])) o[k] = num(v[k]);
  if (has(o, 'dur')) o.dur = Math.max(1, Math.min(600, Math.trunc(o.dur)));
  if (o.state === 'active' && !has(o, 'end')) return null;
  return o;
}
const tqread = async () => { const q = await jget('tq', { seq: 0, items: {} }); if (!isObj(q.items)) q.items = {}; return q; };

/* ---------- traces des enseignants, évaluations, choix d'exercice ---------- */
async function tlog_read() { const L = await jget('tlog', {}); if (!Array.isArray(L.ses)) L.ses = []; if (!Array.isArray(L.ev)) L.ev = []; return L; }
async function tlog_write(L) { if (L.ses.length > 800) L.ses = L.ses.slice(-800); if (L.ev.length > 4000) L.ev = L.ev.slice(-4000); await jput('tlog', L); }
function tlog_ev(L, tid, name, k, x) { L.ev.push(Object.assign({ t: nowms(), tid, name, k, ip: client_ip() }, x)); }
const g_on = v => isObj(v) && !!v.active && !(isObj(v.ses) && v.ses.state === 'closed');
const exlist = sel => { const o = []; if (isObj(sel) && Array.isArray(sel.ex)) for (const e of sel.ex) o.push(Math.trunc(Number(e)) || 0); return o; };
function track_group(L, tid, name, g, old, nw) {
  const now = nowms(), wa = g_on(old), na = g_on(nw);
  const osel = (isObj(old) && isObj(old.sel)) ? old.sel : null, nsel = (isObj(nw) && isObj(nw.sel)) ? nw.sel : null;
  const oses = (isObj(old) && isObj(old.ses)) ? old.ses : null, nses = (isObj(nw) && isObj(nw.ses)) ? nw.ses : null;
  let oi = null; L.ses.forEach((s, i) => { if (has(s, 'g') && s.g === g && !s.end) oi = i; });
  const x = { g, tp: nsel ? Math.trunc(Number(nsel.tp)) || 0 : 0, ex: exlist(nsel), pick: !!(nsel && nsel.pick) };
  if (na) {
    if (oi !== null && L.ses[oi].tid !== tid) { L.ses[oi].end = now; oi = null; }
    if (oi === null) { L.ses.push({ id: 's' + hex(6), tid, name, g, start: now, end: 0, tp: 0, ex: [], hist: [], cs: 0, ce: 0, dur: 0, pick: false }); oi = L.ses.length - 1; }
    const s = L.ses[oi]; s.name = name; const ip = client_ip();
    if (ip !== '') { let ips = Array.isArray(s.ips) ? s.ips : []; if (!ips.includes(ip)) ips.push(ip); s.ips = ips.slice(-5); s.ip = ip; }
    s.tp = x.tp; s.ex = x.ex; s.pick = x.pick;
    if (x.tp) {
      const h = Array.isArray(s.hist) ? s.hist : []; let f = false;
      for (const it of h) { if (Math.trunc(Number(it.tp)) === x.tp) { it.ex = [...new Set([...exlist(it), ...x.ex])]; f = true; } }
      if (!f) h.push({ tp: x.tp, ex: x.ex }); s.hist = h;
    }
    if (nses && nses.state === 'active' && has(nses, 'start')) { s.cs = num(nses.start); s.ce = has(nses, 'end') ? num(nses.end) : 0; s.dur = has(nses, 'dur') ? Math.trunc(nses.dur) : 0; }
  } else if (wa && oi !== null) { L.ses[oi].end = now; }
  if (!wa && na) tlog_ev(L, tid, name, 'open', x);
  else if (wa && !na) tlog_ev(L, tid, name, (nses && nses.state === 'closed') ? 'close' : 'off', { g });
  else if (na && JSON.stringify(osel) !== JSON.stringify(nsel)) tlog_ev(L, tid, name, 'sel', x);
  if (na && nses && nses.state === 'active' && (!oses || oses.state !== 'active' || (has(oses, 'start') ? oses.start : 0) != (has(nses, 'start') ? nses.start : 0))) tlog_ev(L, tid, name, 'chrono', { g, tp: x.tp, dur: has(nses, 'dur') ? Math.trunc(nses.dur) : 0 });
  if (na && wa && nses && nses.state === 'open' && oses && oses.state === 'active') tlog_ev(L, tid, name, 'nochrono', { g, tp: x.tp });
}
async function pick_ctx(sid) {
  const pub = await pubread(); if (!sid || !pub || !has(pub.students, sid)) return null;
  const g = has(pub.students[sid], 'group') ? String(pub.students[sid].group) : '';
  const gs = (g !== '' && pub.settings && isObj(pub.settings.groups) && isObj(pub.settings.groups[g])) ? pub.settings.groups[g] : null;
  const sel = (gs && g_on(gs) && isObj(gs.sel) && gs.sel.pick && gs.sel.pk) ? gs.sel : null;
  return { pub, g, sel };
}
const claims_of = (C, g, pk) => (isObj(C[g]) && C[g].pk === pk) ? C[g] : { pk, map: {}, t: nowms() };
async function who_groups() {
  if (await okey()) return true;
  if (getp('tok') !== '') return await tauth();
  out({ ok: false, error: 'accès refusé' }, 403);
}

/* ---------- fichiers servis ---------- */
const asciiName = nm => nm.replace(/[^A-Za-z0-9._-]+/g, '_');
function fileResp(buf, nm) {
  return new Response(buf, { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store',
    'Content-Disposition': 'attachment; filename="' + asciiName(nm) + '"; filename*=UTF-8\'\'' + encodeURIComponent(nm) } });
}
function cleanName(nm) {
  nm = String(nm).replace(/\\/g, '/'); nm = nm.split('/').pop(); nm = nm.replace(/[\x00-\x1f\\/:*?"<>|]+/g, '_').trim(); return cut(nm, 120);
}

/* ---------- classes (base de données) ---------- */
function cls_ids(pub) { const o = []; const S = (pub && isObj(pub.settings)) ? pub.settings : {}; if (Array.isArray(S.classes)) for (const c of S.classes) { if (isObj(c) && has(c, 'id')) o.push(String(c.id)); } if (!o.length) return ['LCE1', 'LCS1', 'LCS2', 'LBC2']; return o; }
function cls_of(pub, g) {
  g = String(g); if (g === '') return ''; const S = (pub && isObj(pub.settings)) ? pub.settings : {}; const ids = cls_ids(pub);
  if (isObj(S.groupClass) && has(S.groupClass, g) && ids.includes(String(S.groupClass[g]))) return String(S.groupClass[g]);
  let best = ''; for (const id of ids) { if (id !== '' && g.toLowerCase().startsWith(id.toLowerCase()) && id.length > best.length) best = id; } return best;
}
async function dbf_ctx() {
  const pub = await pubread();
  if (await okey()) return ['admin', null, 'Administrateur'];
  if (getp('tok') !== '') { const a = await tauth(); const t = a[1]; const cs = []; for (const g of t.groups) { const c = cls_of(pub, g); if (c !== '' && !cs.includes(c)) cs.push(c); } return ['teacher', cs, String(t.name)]; }
  const sid = chk_sid(getp('sid'));
  if (sid && pub && has(pub.students, sid)) { const c = cls_of(pub, has(pub.students[sid], 'group') ? pub.students[sid].group : ''); return ['student', c === '' ? [] : [c], '']; }
  out({ ok: false, error: 'accès refusé' }, 403);
}
async function doc_ok() {
  if (await okey()) return true;
  if (getp('tok') !== '') { await tauth(); return true; }
  const sid = chk_sid(getp('sid')); const pub = await pubread();
  return !!(sid && pub && has(pub.students, sid));
}

/* ---------- actions ---------- */
async function handle() {
  const act = getp('action'); const raw = REQ.raw;
  const hdr = { ok: true };

  if (act === 'ping') out({ ok: true, now: nowms(), init: !!(await store.get('keysha', { type: 'text' })), ver: 'groupes-v7-netlify' });

  if (act === 'myrate') {
    const sid = chk_sid(getp('sid')); if (!sid) out({ ok: false }, 400);
    const R = await jget('ratings', {}); out({ ok: true, r: R[sid] ? { n: R[sid].n, txt: R[sid].txt, t: R[sid].t } : null });
  }
  if (act === 'rate') {
    const j = jbody(); const sid = isObj(j) ? chk_sid(j.sid) : null; const n = isObj(j) && has(j, 'n') ? Math.trunc(Number(j.n)) : 0; const tx = isObj(j) && has(j, 'txt') ? String(j.txt).trim() : '';
    if (!sid || !(n >= 1 && n <= 5) || raw.length > 12000) out({ ok: false, error: 'Évaluation invalide : choisissez de 1 à 5 étoiles.' }, 400);
    const pub = await pubread(); if (!pub || !has(pub.students, sid)) out({ ok: false, error: 'Compte étudiant inconnu.' }, 403);
    await lockit(); const R = await jget('ratings', {});
    if (R[sid]) out({ ok: false, error: 'Vous avez déjà évalué le site : votre évaluation est verrouillée.', locked: true, r: { n: R[sid].n, txt: R[sid].txt, t: R[sid].t } }, 409);
    const st = pub.students[sid];
    R[sid] = { n, txt: cut(tx, 1500), t: nowms(), nom: has(st, 'nom') ? String(st.nom) : '', prenom: has(st, 'prenom') ? String(st.prenom) : '', group: has(st, 'group') ? String(st.group) : '', email: has(st, 'email') ? String(st.email) : '' };
    await jput('ratings', R); out({ ok: true, r: { n, txt: R[sid].txt, t: R[sid].t } });
  }

  if (act === 'claims' || act === 'claim') {
    const j = act === 'claim' ? jbody() : null;
    const sid = chk_sid(act === 'claim' ? (isObj(j) ? j.sid : null) : getp('sid'));
    if (act === 'claim') await lockit();
    const c = await pick_ctx(sid); if (!c) out({ ok: false, error: 'Compte étudiant inconnu.' }, 403);
    if (!c.sel) out({ ok: true, pick: false });
    const sel = c.sel, g = c.g; const C = await jget('claims', {}); const cl = claims_of(C, g, sel.pk); const exs = exlist(sel);
    let mine = null; for (const e of Object.keys(cl.map)) { if (cl.map[e] === sid) mine = Number(e); }
    if (act === 'claim' && mine === null) {
      const ex = isObj(j) && has(j, 'ex') ? Math.trunc(Number(j.ex)) : -1;
      if (!exs.includes(ex)) out({ ok: false, error: 'Exercice invalide.' }, 400);
      if (has(cl.map, ex)) out({ ok: false, error: 'Cet exercice vient d’être choisi par un autre étudiant : choisissez un autre numéro.', taken: Object.keys(cl.map).map(Number) }, 409);
      cl.map[ex] = sid; C[g] = cl; await jput('claims', C); mine = ex;
      const PK = await jget('picks', {}); PK[sid] = { pk: sel.pk, oei: ex, g, t: nowms() }; await jput('picks', PK);
    }
    out({ ok: true, pick: true, pk: sel.pk, ex: exs, taken: Object.keys(cl.map).map(Number), mine });
  }
  if (act === 'claimlist' || act === 'claimreset') {
    const who = await who_groups(); const g = getp('g');
    if (who !== true && !who[1].groups.includes(g)) out({ ok: false, error: 'Groupe non autorisé' }, 403);
    if (act === 'claimreset') {
      await lockit(); const C = await jget('claims', {}); const pk = isObj(C[g]) && has(C[g], 'pk') ? C[g].pk : null; delete C[g]; await jput('claims', C);
      const PK = await jget('picks', {}); for (const s of Object.keys(PK)) { const p = PK[s]; if (has(p, 'g') && p.g === g && pk !== null && p.pk === pk) delete PK[s]; } await jput('picks', PK);
      if (who !== true) { const L = await tlog_read(); tlog_ev(L, who[0], who[1].name, 'reset', { g }); await tlog_write(L); }
      out({ ok: true });
    }
    const pub = await pubread(); const C = await jget('claims', {}); const cl = C[g] || null; const o = [];
    if (cl) for (const e of Object.keys(cl.map)) { const sid = cl.map[e]; const st = (pub && has(pub.students, sid)) ? pub.students[sid] : {}; o.push({ ex: Number(e), sid, nom: has(st, 'nom') ? st.nom : '', prenom: has(st, 'prenom') ? st.prenom : '' }); }
    out({ ok: true, pk: cl ? cl.pk : null, list: o });
  }

  /* publication lue par les étudiants */
  if (act === 'pub') {
    const p = await pubload(0); if (!p) out({ ok: false, error: 'pub.json absent' }, 404);
    return new Response(p.text, { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' } });
  }
  if (act === 'photo') {
    const sid = chk_sid(getp('sid')); if (!sid) out({ ok: false, error: 'pas de photo' }, 404);
    let key = getp('v') && /^\d{1,12}$/.test(getp('v')) ? 'photo/' + sid + '.' + getp('v') : null; let b = key ? await bget(key) : null;
    if (!b) { const ks = (await listKeys('photo/' + sid + '.')).sort(); if (ks.length) { key = ks[ks.length - 1]; b = await bget(key); } }
    if (!b) out({ ok: false, error: 'pas de photo' }, 404);
    const et = '"' + sha256(key).slice(0, 16) + '-' + b.length + '"';
    if (REQ.req.headers.get('if-none-match') === et) return new Response(null, { status: 304, headers: { ETag: et } });
    return new Response(b, { status: 200, headers: { 'Content-Type': 'image/jpeg', ETag: et, 'Cache-Control': 'private, max-age=300' } });
  }
  if (act === 'doclist') {
    if (!(await doc_ok())) out({ ok: false, error: 'accès refusé' }, 403);
    const o = []; const m = await jget('docs', {}); for (const id of Object.keys(m)) o.push({ id, name: m[id].name, size: m[id].size, t: m[id].t });
    o.sort((a, b) => b.t - a.t); out({ ok: true, docs: o });
  }
  if (act === 'docget') {
    if (!(await doc_ok())) out({ ok: false, error: 'accès refusé' }, 403);
    const id = getp('id'); const m = await jget('docs', {});
    if (!/^d[0-9a-f]{16}$/.test(id) || !m[id]) out({ ok: false, error: 'document introuvable' }, 404);
    const b = await bget('doc/' + id); if (!b) out({ ok: false, error: 'document introuvable' }, 404);
    return fileResp(b, m[id].name);
  }
  if (act === 'dbflist') {
    const [role, cs] = await dbf_ctx(); const want = getp('cls'); const o = []; const m = await jget('dbf', {});
    for (const id of Object.keys(m)) { const d = m[id]; if (cs !== null && !cs.includes(d.cls)) continue; if (want !== '' && d.cls !== want) continue; o.push({ id, name: d.name, size: d.size, t: d.t, cls: d.cls, by: has(d, 'by') ? d.by : '' }); }
    o.sort((a, b) => (a.cls + a.name < b.cls + b.name ? -1 : a.cls + a.name > b.cls + b.name ? 1 : 0)); out({ ok: true, files: o, classes: cs });
  }
  if (act === 'dbfget') {
    const [role, cs] = await dbf_ctx(); const id = getp('id'); const m = await jget('dbf', {});
    if (!/^f[0-9a-f]{16}$/.test(id) || !m[id]) out({ ok: false, error: 'fichier introuvable' }, 404);
    if (cs !== null && !cs.includes(m[id].cls)) out({ ok: false, error: 'accès refusé' }, 403);
    const b = await bget('dbf/' + id); if (!b) out({ ok: false, error: 'fichier introuvable' }, 404);
    return fileResp(b, m[id].name);
  }
  if (act === 'dbfadd') {
    const [role, cs, by] = await dbf_ctx(); if (role === 'student') out({ ok: false, error: 'accès refusé' }, 403);
    const cls = getp('cls'); if (!/^[A-Za-z0-9_-]{1,20}$/.test(cls)) out({ ok: false, error: 'Classe invalide.' }, 400);
    if (cs !== null && !cs.includes(cls)) out({ ok: false, error: 'Cette classe ne fait pas partie de vos groupes.' }, 403);
    const nm = cleanName(getp('name'));
    if (nm === '' || nm[0] === '.' || !/\.(csv|tsv|txt|xlsx|xls|json|parquet|xml|ods)$/i.test(nm)) out({ ok: false, error: 'Type de fichier non accepté (csv, xlsx, json, parquet, xml, ods).' }, 400);
    const body = REQ.buf; const n = body.length; if (n < 1) out({ ok: false, error: 'Fichier vide.' }, 400); if (n > MAXBIN) out({ ok: false, error: 'Fichier trop lourd (5 Mo maximum sur Netlify).' }, 413);
    await lockit(); const m = await jget('dbf', {});
    for (const oid of Object.keys(m)) { if (m[oid].cls === cls && m[oid].name.toLowerCase() === nm.toLowerCase()) { delete m[oid]; await del('dbf/' + oid); } }
    const id = 'f' + hex(8); await bput('dbf/' + id, body); m[id] = { name: nm, size: n, t: nowms(), cls, by }; await jput('dbf', m); out({ ok: true, id });
  }
  if (act === 'dbfdel') {
    const [role, cs] = await dbf_ctx(); if (role === 'student') out({ ok: false, error: 'accès refusé' }, 403);
    const j = jbody(); const id = isObj(j) && has(j, 'id') ? String(j.id) : ''; if (!/^f[0-9a-f]{16}$/.test(id)) out({ ok: false, error: 'identifiant invalide' }, 400);
    await lockit(); const m = await jget('dbf', {}); if (!m[id]) out({ ok: false, error: 'fichier introuvable' }, 404);
    if (cs !== null && !cs.includes(m[id].cls)) out({ ok: false, error: 'accès refusé' }, 403);
    delete m[id]; await jput('dbf', m); await del('dbf/' + id); out({ ok: true });
  }
  if (act === 'init') {
    const k = getp('key'); if (k.length < 16) out({ ok: false, status: 'badkey' }, 400);
    await lockit();
    if (!(await store.get('keysha', { type: 'text' }))) { await store.set('keysha', sha256(k)); out({ ok: true, status: 'created' }); }
    const ok = await okey(); out({ ok, status: ok ? 'exists' : 'locked' });
  }
  if (act === 'beat') {
    const j = jbody(); const sid = isObj(j) ? chk_sid(j.sid) : null;
    if (!sid || !isObj(j.d) || raw.length > 3000) out({ ok: false }, 400);
    const d = j.d; d.t = nowms();
    const p = await pubload(4000);
    const pv = p ? p.pv : '0'; const res = { ok: true, pv, now: nowms() };
    const cpv = has(j, 'pv') ? String(j.pv) : '';
    if (cpv !== pv && p && p.obj && isObj(p.obj.settings)) res.set = p.obj.settings;
    await jput('live/' + sid, d);
    out(res);
  }
  if (act === 'report') {
    const j = jbody(); const sid = isObj(j) ? chk_sid(j.sid) : null;
    if (!sid || !isObj(j.r) || raw.length > 5000000) out({ ok: false }, 400);
    const rt = nowms();
    await jput('rep/' + sid, { rt, r: j.r });
    await jput('prog/' + sid, { qs: has(j.r, 'qs') ? j.r.qs : {}, att: has(j.r, 'att') ? j.r.att : {}, rt });
    await store.set('rv/' + sid + '.' + rt, '1');
    for (const k of await listKeys('rv/' + sid + '.')) { if (k !== 'rv/' + sid + '.' + rt) await del(k); }
    out({ ok: true });
  }

  /* ---------- connexion enseignant délégué ---------- */
  if (act === 'tlogin') {
    const j = jbody(); const pw = isObj(j) && has(j, 'pw') ? String(j.pw) : '';
    const tf = 'thr/' + sha256(client_ip() || '?').slice(0, 24); let th = await jget(tf, { n: 0, t: 0 });
    if (nowms() - th.t > 600000) th = { n: 0, t: nowms() };
    if (th.n >= 15) out({ ok: false, error: 'Trop de tentatives : réessayez dans 10 minutes.' }, 429);
    let ts = await teachers(); let found = null;
    if (pw.length >= 1 && pw.length <= 200) for (const id of Object.keys(ts)) { if (verifyPw(pw, ts[id].hash)) { found = id; break; } }
    if (!found) {
      th.n++; th.t = th.t || nowms(); await jput(tf, th);
      const leg = Object.values(ts).some(t => legacyHash(t.hash));
      out({ ok: false, error: 'Mot de passe incorrect.' + (leg ? ' (Si votre compte vient de l’ancien site : demandez à l’administrateur de redéfinir votre mot de passe.)' : '') }, 403);
    }
    await lockit(); ts = await teachers(); if (!ts[found]) out({ ok: false, error: 'Mot de passe incorrect.' }, 403);
    const tok = hex(24); await jput('tsess/' + sha256(tok), { tid: found, exp: nowms() + 12 * 3600000 });
    ts[found].last = nowms(); await jput('teachers', ts);
    const TL = await tlog_read(); tlog_ev(TL, found, ts[found].name, 'login', {}); await tlog_write(TL); await jput('tlive/' + found, { t: nowms(), tab: 'dash', ip: client_ip() });
    for (const k of await listKeys('tsess/')) { const sd = await jget(k, null); if (!sd || sd.exp < nowms()) await del(k); }
    out({ ok: true, token: tok, name: ts[found].name, groups: [...ts[found].groups] });
  }
  if (act === 'tme') { const [tid, t] = await tauth(); out({ ok: true, name: t.name, groups: [...t.groups] }); }
  if (act === 'tlogout') { const [tid, t, sf] = await tauth(); await del(sf); await lockit(); const TL = await tlog_read(); tlog_ev(TL, tid, t.name, 'logout', {}); await tlog_write(TL); await del('tlive/' + tid); out({ ok: true }); }
  if (act === 'tpwself') {
    const [tid, t] = await tauth(); const j = jbody(); const pw = isObj(j) && has(j, 'pw') ? String(j.pw) : '';
    if (pw.length < 6 || pw.length > 200) out({ ok: false, error: 'Au moins 6 caractères.' }, 400);
    await lockit(); const ts = await teachers(); if (!ts[tid]) out({ ok: false }, 401);
    if (await pw_taken(ts, pw, tid)) out({ ok: false, error: 'Ce mot de passe est déjà utilisé : choisissez-en un autre.' }, 400);
    ts[tid].hash = hashPw(pw); await jput('teachers', ts); out({ ok: true });
  }
  if (act === 'tdata') {
    const [tid, t] = await tauth(); const pub = await pubread(); const groups = [...t.groups]; const sids = allowed_sids(pub, groups);
    const tab = getp('tab').replace(/[^a-z]/g, ''); await jput('tlive/' + tid, { t: nowms(), tab: tab.slice(0, 12), ip: client_ip() });
    const PKS = await jget('picks', {}); const picks = {}; const live = {}; const prog = {}; const att = {}; const ov = await jget('att', {});
    await Promise.all(sids.map(async sid => {
      const d = await jgetc('live/' + sid, 3000); if (d) live[sid] = d;
      const p = await prog_of(sid); const w = (p && isObj(p.att)) ? Object.assign({}, p.att) : {};
      if (p) prog[sid] = { sid, qs: isObj(p.qs) ? p.qs : {}, last: has(p, 'rt') ? p.rt : 0 };
      if (ov[sid] && isObj(ov[sid].w)) for (const k of Object.keys(ov[sid].w)) { const v = ov[sid].w[k]; if (v === 'x') delete w[k]; else w[k] = v; }
      if (Object.keys(w).length) att[sid] = { sid, group: pub.students[sid].group, w };
      if (PKS[sid]) picks[sid] = PKS[sid];
    }));
    const set = pub && isObj(pub.settings) ? pub.settings : {}; norm_settings(set);
    out({ ok: true, now: nowms(), name: t.name, groups, settings: set, live, progress: prog, att, picks });
  }
  if (act === 'tcodes') {
    const [tid, t] = await tauth(); const sid = chk_sid(getp('sid')); const pub = await pubread();
    if (!sid || !allowed_sids(pub, t.groups).includes(sid)) out({ ok: false, error: 'accès refusé' }, 403);
    const d = await jget('rep/' + sid, null); out({ ok: true, codes: (d && isObj(d.r) && isObj(d.r.codes)) ? d.r.codes : {} });
  }
  if (act === 'tspw') {
    const [tid, t] = await tauth(); const pub = await pubread(); const sids = allowed_sids(pub, t.groups);
    const b = await jget('base', null); const docs = (b && isObj(b.docs)) ? b.docs : {};
    const q = await tqread(); const o = {};
    for (const sid of sids) {
      let pw = (docs['secrets/' + sid] && has(docs['secrets/' + sid], 'password')) ? String(docs['secrets/' + sid].password) : null;
      if (q.items['pw:' + sid] && has(q.items['pw:' + sid], 'pw')) pw = String(q.items['pw:' + sid].pw);
      if (pw !== null) o[sid] = pw;
    }
    out({ ok: true, pw: o });
  }
  if (act === 'tpwset') {
    const [tid, t] = await tauth(); const j = jbody(); const sid = isObj(j) ? chk_sid(j.sid) : null; const pw = isObj(j) && has(j, 'pw') ? String(j.pw) : '';
    if (pw.length < 6 || pw.length > 100) out({ ok: false, error: 'Le mot de passe doit contenir entre 6 et 100 caractères.' }, 400);
    await lockit(); const pub = await pubread();
    if (!sid || !pub || !has(pub.students, sid) || !allowed_sids(pub, t.groups).includes(sid)) out({ ok: false, error: 'Étudiant hors de vos groupes' }, 403);
    const salt = hex(16); const h = pbkdf2Sync(pw, Buffer.from(salt, 'hex'), 60000, 32, 'sha256').toString('hex');   // même schéma que le navigateur : PBKDF2-SHA256, 60000 itérations
    pub.students[sid].salt = salt; pub.students[sid].hash = h;
    const q = await tqread(); qadd(q, 'pw:' + sid, { op: 'pw', sid, pw, salt, hash: h });
    await pubwrite(pub); await jput('tq', q); out({ ok: true });
  }
  if (act === 'tset') {
    const [tid, t] = await tauth(); const j = jbody();
    if (!isObj(j) || !Array.isArray(j.ops) || j.ops.length > 60 || raw.length > 100000) out({ ok: false, error: 'requête invalide' }, 400);
    await lockit(); const pub = await pubread(); if (!pub || !has(pub, 'settings')) out({ ok: false, error: 'Aucune donnée publiée : l’administrateur doit d’abord publier.' }, 409);
    const S = pub.settings; const q = await tqread(); const ov = await jget('att', {}); const G = t.groups;
    let touchedAtt = false; const TL = await tlog_read(); let touchedLog = false;
    for (const o of j.ops) {
      if (!isObj(o) || !has(o, 'op')) continue; const op = o.op;
      if (op === 'tp' || op === 'thr' || op === 'req') continue;   // réglages globaux réservés à l'administrateur
      if (op === 'group') {
        const g = has(o, 'g') ? String(o.g) : ''; if (!G.includes(g)) out({ ok: false, error: 'Groupe non autorisé : ' + g }, 403);
        const v = isObj(o.val) ? o.val : {}; let sel = null;
        if (isObj(v.sel) && has(v.sel, 'tp') && Math.trunc(Number(v.sel.tp)) > 0) {
          const ex = []; if (Array.isArray(v.sel.ex)) for (const e of v.sel.ex) ex.push(Math.trunc(Number(e)) || 0); sel = { tp: Math.trunc(Number(v.sel.tp)), ex };
          if (v.sel.pick && sel.tp === 7) { const pk = has(v.sel, 'pk') ? String(v.sel.pk) : ''; sel.pick = true; sel.pk = /^[a-z0-9]{4,24}$/.test(pk) ? pk : hex(6).slice(0, 10); }
        }
        const val = { active: !!v.active, sel }; const ses = has(v, 'ses') ? clean_ses(v.ses) : null; if (ses) val.ses = ses;
        if (!isObj(S.groups)) S.groups = {}; const oldg = has(S.groups, g) ? S.groups[g] : null;
        S.groups[g] = val; qadd(q, 'group:' + g, { op: 'group', g, val });
        if (JSON.stringify(oldg) !== JSON.stringify(val)) { track_group(TL, tid, has(t, 'name') ? String(t.name) : 'Enseignant', g, oldg, val); touchedLog = true; }
      } else if (op === 'week') {
        const g = has(o, 'g') ? String(o.g) : ''; if (!G.includes(g)) out({ ok: false, error: 'Groupe non autorisé : ' + g }, 403);
        const v = isObj(o.val) ? o.val : null; let val = null;
        if (v) { const w = has(v, 'w') ? Math.trunc(Number(v.w)) : 0; if (!(w >= 1 && w <= 14)) out({ ok: false, error: 'semaine invalide' }, 400); val = { w, open: !!v.open, t: has(v, 't') && isNum(v.t) ? num(v.t) : nowms() }; if (has(v, 'end') && isNum(v.end)) val.end = num(v.end); }
        if (!isObj(S.weeks)) S.weeks = {}; if (val) S.weeks[g] = val; else delete S.weeks[g];
        qadd(q, 'week:' + g, { op: 'week', g, val });
        if (val && val.open) { for (const sid of allowed_sids(pub, [g])) { if (ov[sid] && ov[sid].w && ov[sid].w[val.w] === 'a') { delete ov[sid].w[val.w]; touchedAtt = true; qadd(q, 'att:' + sid, { op: 'att', sid, set: { [val.w]: 'x' } }); } } }
      } else if (op === 'rem') {
        if (!Array.isArray(S.reminders)) S.reminders = []; const act2 = has(o, 'act') ? o.act : '';
        if (act2 === 'add') {
          const v = isObj(o.val) ? o.val : {}; const g = has(v, 'g') ? String(v.g) : ''; const id = has(v, 'id') ? String(v.id) : ''; let tx = has(v, 'text') ? String(v.text).trim() : '';
          if (!G.includes(g)) out({ ok: false, error: 'Groupe non autorisé : ' + g }, 403);
          if (!/^r[a-z0-9]{4,20}$/.test(id) || tx === '') out({ ok: false, error: 'rappel invalide' }, 400);
          tx = cut(tx, 300);
          if (S.reminders.some(r0 => has(r0, 'id') && r0.id === id)) continue;
          const r = { id, text: tx, g, t: nowms(), by: has(t, 'name') ? String(t.name) : 'Enseignant', tid };
          S.reminders.push(r); if (S.reminders.length > 100) S.reminders.shift();
          qadd(q, 'rem:' + id, { op: 'rem', act: 'add', rem: r });
        } else if (act2 === 'del') {
          const id = has(o, 'id') ? String(o.id) : '';
          S.reminders = S.reminders.filter(r0 => !(has(r0, 'id') && r0.id === id && has(r0, 'tid') && r0.tid === tid));
          qadd(q, 'rem:' + id, { op: 'rem', act: 'del', id });
        } else out({ ok: false, error: 'opération rappel inconnue' }, 400);
      } else if (op === 'att') {
        const sid = chk_sid(o.sid); if (!sid || !has(pub.students, sid) || !G.includes(has(pub.students[sid], 'group') ? pub.students[sid].group : '')) out({ ok: false, error: 'Étudiant hors de vos groupes' }, 403);
        const set = {}; if (isObj(o.set)) for (const k0 of Object.keys(o.set)) { const k = Math.trunc(Number(k0)); if (!(k >= 1 && k <= 14)) continue; const v = o.set[k0]; set[k] = (v === 'p' || v === 'a') ? v : 'x'; }
        if (!Object.keys(set).length) continue; if (!ov[sid] || !isObj(ov[sid].w)) ov[sid] = { w: {} }; for (const k of Object.keys(set)) ov[sid].w[k] = set[k]; ov[sid].t = nowms(); touchedAtt = true;
        qadd(q, 'att:' + sid, { op: 'att', sid, set });
      } else out({ ok: false, error: 'opération inconnue' }, 400);
    }
    pub.settings = S; await pubwrite(pub); await jput('tq', q); if (touchedAtt) await jput('att', ov); if (touchedLog) await tlog_write(TL);
    const S2 = Object.assign({}, S); norm_settings(S2); out({ ok: true, settings: S2 });
  }

  /* ---------- vérification du mot de passe administrateur (depuis un autre PC) ---------- */
  if (act === 'acheck') {
    const tf = 'thr/a' + sha256(client_ip() || '?').slice(0, 23); let th = await jget(tf, { n: 0, t: 0 });
    if (nowms() - th.t > 600000) th = { n: 0, t: nowms() };
    if (th.n >= 15) out({ ok: false, error: 'Trop de tentatives : réessayez dans 10 minutes.' }, 429);
    if (await okey()) out({ ok: true });
    th.n++; await jput(tf, th); out({ ok: false, error: (await store.get('keysha', { type: 'text' })) ? 'Mot de passe administrateur incorrect.' : 'Aucune installation administrateur sur ce serveur.' }, 403);
  }

  /* ---------- actions de l'administrateur (clé) ---------- */
  if (!(await okey())) out({ ok: false, error: 'clé enseignant invalide' }, 403);

  if (act === 'list') {
    const live = {}; const ks = await listKeys('live/'); const old = nowms() - 3 * 86400000;
    await Promise.all(ks.map(async k => { const d = await jgetc(k, 3000); const sid = k.slice(5); if (isObj(d)) { if ((d.t || 0) < old) { await del(k); } else live[sid] = d; } }));
    const rv = {}; for (const k of await listKeys('rv/')) { const m = /^rv\/(u[0-9a-f]{24})\.(\d+)$/.exec(k); if (m && (!rv[m[1]] || rv[m[1]] < Number(m[2]))) rv[m[1]] = Number(m[2]); }
    const q = await tqread(); const items = Object.values(q.items).sort((a, b) => a.seq - b.seq);
    out({ ok: true, now: nowms(), live, rv, tq: items, tseq: q.seq || 0, picks: await jget('picks', {}) });
  }
  if (act === 'rekey') {
    const j = jbody(); const nk = isObj(j) && has(j, 'nk') ? String(j.nk) : ''; if (nk.length < 16 || nk.length > 200) out({ ok: false, error: 'clé invalide' }, 400);
    await lockit(); await store.set('keysha', sha256(nk)); out({ ok: true });
  }
  if (act === 'getbase') { const b = await jget('base', null); if (!b) out({ ok: true, empty: true, t: 0 }); out({ ok: true, t: b.t, docs: b.docs }); }
  if (act === 'putbase') {
    const j = jbody(); if (!isObj(j) || !isObj(j.docs) || raw.length > 5800000) out({ ok: false, error: 'données invalides (5,8 Mo maximum sur Netlify)' }, 400);
    await lockit(); const b = await jget('base', null); const since = has(j, 'since') ? Math.trunc(Number(j.since)) || 0 : 0;
    if (b && b.t > since) out({ ok: false, error: 'newer', t: b.t }, 409);
    const t = nowms(); await jput('base', { t, docs: j.docs }); out({ ok: true, t });
  }
  if (act === 'photoset') {
    const j = jbody(); const sid = isObj(j) ? chk_sid(j.sid) : null; const img = isObj(j) && has(j, 'img') ? String(j.img) : ''; const pre = 'data:image/jpeg;base64,';
    if (!sid || !img.startsWith(pre)) out({ ok: false, error: 'Image JPEG invalide.' }, 400);
    const bin = Buffer.from(img.slice(pre.length), 'base64');
    if (bin.length < 200 || bin.length > 300000 || bin[0] !== 0xFF || bin[1] !== 0xD8) out({ ok: false, error: 'Image illisible ou trop lourde.' }, 400);
    const v = Math.floor(nowms() / 1000); await bput('photo/' + sid + '.' + v, bin);
    for (const k of await listKeys('photo/' + sid + '.')) { if (k !== 'photo/' + sid + '.' + v) await del(k); }
    out({ ok: true, v });
  }
  if (act === 'photodel') { const j = jbody(); const sid = isObj(j) ? chk_sid(j.sid) : null; if (!sid) out({ ok: false }, 400); for (const k of await listKeys('photo/' + sid + '.')) await del(k); out({ ok: true }); }
  if (act === 'photolist') { const o = {}; for (const k of await listKeys('photo/')) { const m = /^photo\/(u[0-9a-f]{24})\.(\d+)$/.exec(k); if (m) o[m[1]] = Number(m[2]); } out({ ok: true, photos: o }); }
  if (act === 'purge') {
    const j = jbody(); const sids = isObj(j) && Array.isArray(j.sids) ? j.sids : []; await lockit();
    const ov = await jget('att', {}); const q = await tqread(); const ok = {}; let n = 0;
    for (const x of sids) { const sid = chk_sid(x); if (!sid) continue; ok[sid] = 1; n++;
      for (const k of ['rep/' + sid, 'prog/' + sid, 'live/' + sid]) await del(k);
      for (const k of [...await listKeys('photo/' + sid + '.'), ...await listKeys('rv/' + sid + '.')]) await del(k);
      delete ov[sid]; }
    for (const k of Object.keys(q.items)) { const it = q.items[k]; if (has(it, 'sid') && ok[it.sid]) delete q.items[k]; }
    await jput('att', ov); await jput('tq', q); out({ ok: true, n });
  }
  if (act === 'docadd') {
    const nm = cleanName(getp('name')); if (nm === '' || nm[0] === '.') out({ ok: false, error: 'Nom de fichier invalide.' }, 400);
    const body = REQ.buf; const n = body.length; if (n < 1) out({ ok: false, error: 'Fichier vide.' }, 400); if (n > MAXBIN) out({ ok: false, error: 'Fichier trop lourd (5 Mo maximum sur Netlify).' }, 413);
    await lockit(); const m = await jget('docs', {}); const id = 'd' + hex(8);
    await bput('doc/' + id, body); m[id] = { name: nm, size: n, t: nowms() }; await jput('docs', m); out({ ok: true, id });
  }
  if (act === 'docdel') {
    const j = jbody(); const id = isObj(j) && has(j, 'id') ? String(j.id) : ''; if (!/^d[0-9a-f]{16}$/.test(id)) out({ ok: false }, 400);
    await lockit(); const m = await jget('docs', {}); delete m[id]; await jput('docs', m); await del('doc/' + id); out({ ok: true });
  }
  if (act === 'tack') {
    await lockit(); const upto = Math.trunc(Number(getp('upto'))) || 0; const q = await tqread();
    for (const k of Object.keys(q.items)) { if (q.items[k].seq <= upto) delete q.items[k]; }
    await jput('tq', q); out({ ok: true, left: Object.keys(q.items).length });
  }
  if (act === 'getreport') { const sid = chk_sid(getp('sid')); if (!sid) out({ ok: false }, 404); const d = await jget('rep/' + sid, null); if (!d) out({ ok: false }, 404); out({ ok: true, rt: d.rt, r: d.r }); }
  if (act === 'publish') {
    const j = jbody(); if (!isObj(j) || !has(j, 'students') || raw.length > 5800000) out({ ok: false, error: 'données invalides' }, 400);
    await lockit(); const q = await tqread();
    if (Object.keys(q.items).length) out({ ok: false, error: 'sync', pending: Object.keys(q.items).length }, 409);
    await store.set('pub', raw); PUB = null; out({ ok: true, n: Object.keys(j.students).length });
  }
  if (act === 'ratelist') { const o = []; const R = await jget('ratings', {}); for (const sid of Object.keys(R)) { const r = Object.assign({}, R[sid]); r.sid = sid; o.push(r); } out({ ok: true, ratings: o }); }
  if (act === 'ratedel') {
    const j = jbody(); await lockit();
    if (isObj(j) && j.all) { await jput('ratings', {}); out({ ok: true }); }
    const sid = isObj(j) ? chk_sid(j.sid) : null; if (!sid) out({ ok: false }, 400);
    const R = await jget('ratings', {}); delete R[sid]; await jput('ratings', R); out({ ok: true });
  }
  if (act === 'ttrack') {
    const pub = await pubread(); const G = (pub && pub.settings && isObj(pub.settings.groups)) ? pub.settings.groups : {}; const o = [];
    for (const [id, t] of Object.entries(await teachers())) {
      const lv = await jget('tlive/' + id, null); const cur = {};
      for (const g of t.groups) { if (G[g]) cur[g] = G[g]; }
      o.push({ id, name: t.name, groups: [...t.groups], last: has(t, 'last') ? t.last : 0, seen: lv && has(lv, 't') ? lv.t : 0, tab: lv && has(lv, 'tab') ? lv.tab : '', ip: lv && has(lv, 'ip') ? lv.ip : '', cur });
    }
    o.sort((a, b) => a.name.toLowerCase() < b.name.toLowerCase() ? -1 : a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0);
    const L = await tlog_read(); out({ ok: true, now: nowms(), teachers: o, ses: L.ses, ev: L.ev.slice(-1500) });
  }
  if (act === 'tlogdel') {
    const j = jbody(); await lockit(); const L = await tlog_read();
    if (isObj(j) && j.all) { await jput('tlog', { ses: [], ev: [] }); out({ ok: true }); }
    const id = isObj(j) && has(j, 'id') ? String(j.id) : ''; const tid = isObj(j) && has(j, 'tid') ? String(j.tid) : '';
    if (id !== '') L.ses = L.ses.filter(s => s.id !== id);
    else if (tid !== '') { L.ses = L.ses.filter(s => s.tid !== tid); L.ev = L.ev.filter(e => e.tid !== tid); }
    else out({ ok: false }, 400);
    await tlog_write(L); out({ ok: true });
  }
  if (act === 'tlist') {
    const o = []; for (const [id, t] of Object.entries(await teachers())) o.push({ id, name: t.name, groups: [...t.groups], created: t.created, last: has(t, 'last') ? t.last : 0, reset: legacyHash(t.hash) || !t.hash });
    o.sort((a, b) => a.name.toLowerCase() < b.name.toLowerCase() ? -1 : a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0); out({ ok: true, teachers: o });
  }
  if (act === 'tadd') {
    const j = jbody(); const name = isObj(j) && has(j, 'name') ? String(j.name).trim() : ''; const pw = isObj(j) && has(j, 'pw') ? String(j.pw) : '';
    if (name === '' || name.length > 60) out({ ok: false, error: 'Indiquez le nom de l’enseignant (60 caractères max).' }, 400);
    if (pw.length < 6 || pw.length > 200) out({ ok: false, error: 'Le mot de passe doit contenir au moins 6 caractères.' }, 400);
    await lockit(); const ts = await teachers();
    if (await pw_taken(ts, pw, '')) out({ ok: false, error: 'Ce mot de passe est déjà utilisé par un autre enseignant : choisissez-en un autre.' }, 400);
    const id = 't' + hex(6); ts[id] = { name, hash: hashPw(pw), groups: clean_groups(j.groups), created: nowms() };
    await jput('teachers', ts); out({ ok: true, id });
  }
  if (act === 'tpw') {
    const j = jbody(); const id = isObj(j) && has(j, 'id') ? String(j.id) : ''; const pw = isObj(j) && has(j, 'pw') ? String(j.pw) : '';
    if (pw.length < 6 || pw.length > 200) out({ ok: false, error: 'Le mot de passe doit contenir au moins 6 caractères.' }, 400);
    await lockit(); const ts = await teachers(); if (!ts[id]) out({ ok: false, error: 'Enseignant introuvable.' }, 404);
    if (await pw_taken(ts, pw, id)) out({ ok: false, error: 'Ce mot de passe est déjà utilisé par un autre enseignant : choisissez-en un autre.' }, 400);
    ts[id].hash = hashPw(pw); await jput('teachers', ts);
    for (const k of await listKeys('tsess/')) { const sd = await jget(k, null); if (sd && sd.tid === id) await del(k); }
    out({ ok: true });
  }
  if (act === 'tgroups') {
    const j = jbody(); const id = isObj(j) && has(j, 'id') ? String(j.id) : '';
    await lockit(); const ts = await teachers(); if (!ts[id]) out({ ok: false, error: 'Enseignant introuvable.' }, 404);
    if (has(j, 'groups')) ts[id].groups = clean_groups(j.groups);
    if (has(j, 'name') && String(j.name).trim() !== '') ts[id].name = String(j.name).trim().slice(0, 60);
    await jput('teachers', ts); out({ ok: true });
  }
  if (act === 'tdel') {
    const j = jbody(); const id = isObj(j) && has(j, 'id') ? String(j.id) : '';
    await lockit(); const ts = await teachers(); if (!ts[id]) out({ ok: false, error: 'Enseignant introuvable.' }, 404);
    delete ts[id]; await jput('teachers', ts);
    for (const k of await listKeys('tsess/')) { const sd = await jget(k, null); if (sd && sd.tid === id) await del(k); }
    out({ ok: true });
  }

  /* ---------- migration depuis la version PHP (administrateur) : copie brute de clés vers le stockage ---------- */
  if (act === 'importput') {
    const j = jbody(); if (!isObj(j) || !Array.isArray(j.items)) out({ ok: false, error: 'requête invalide' }, 400);
    await lockit(); let n = 0;
    for (const it of j.items) {
      if (!isObj(it) || typeof it.k !== 'string' || !/^[A-Za-z0-9_./-]{1,120}$/.test(it.k) || it.k === 'keysha' || it.k === 'lock') continue;
      if (it.t === 'b64') await store.set(it.k, ab(Buffer.from(String(it.v), 'base64')));
      else await store.set(it.k, typeof it.v === 'string' ? it.v : JSON.stringify(it.v));
      MC.delete(it.k); if (it.k === 'pub') PUB = null; n++;
    }
    out({ ok: true, n });
  }
  if (act === 'importstat') {
    const o = {}; for (const k of ['pub', 'teachers', 'base', 'docs', 'att', 'ratings', 'tlog']) o[k] = !!(await store.get(k, { type: 'text' }));
    o.photos = (await listKeys('photo/')).length; o.reports = (await listKeys('rep/')).length; out({ ok: true, have: o });
  }

  out({ ok: false, error: 'action inconnue' }, 400);
}

/* ---------- point d'entrée ---------- */
export default async (req, context) => {
  const url = new URL(req.url); const buf = Buffer.from(await req.arrayBuffer());
  REQ = { req, ctx: context, url, buf, raw: buf.toString('utf8') }; LOCKED = false;
  try {
    const r = await handle();
    if (r instanceof Response) { return r; }
    return new Response('{"ok":false}', { status: 500, headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    if (e instanceof Out) return new Response(JSON.stringify(e.a), { status: e.c, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    console.error('api error', e && e.stack || e);
    return new Response(JSON.stringify({ ok: false, error: 'erreur serveur' }), { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
  } finally { await unlock(); }
};

// End-to-end test of the alert flow. Run: npm test
process.env.NO_PERSIST = '1';
process.env.ANSWER_SECONDS = '2';
process.env.ADMIN_PASSWORD = 'test-admin-pass';
process.env.MAX_ALERTS_PER_HOUR = '6';
const assert = require('node:assert/strict');
const WebSocket = require('ws');
const { server } = require('./server');

let base, wsBase;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function api(path, token, body, method) {
  const r = await fetch(base + '/api' + path, {
    method: method || (body ? 'POST' : 'GET'),
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}
function openWS(token) {
  return new Promise((resolve) => {
    const ws = new WebSocket(wsBase + '/ws?token=' + token);
    ws.msgs = [];
    ws.on('message', (d) => ws.msgs.push(JSON.parse(d)));
    ws.on('open', () => setTimeout(() => resolve(ws), 50));
  });
}
async function waitFor(ws, type, ms = 3000) {
  const t = Date.now();
  while (Date.now() - t < ms) {
    const i = ws.msgs.findIndex((m) => m.type === type);
    if (i >= 0) return ws.msgs.splice(i, 1)[0];
    await sleep(25);
  }
  throw new Error('timed out waiting for ' + type);
}
let passed = 0;
const ok = (name) => { passed++; console.log('  ok  ' + name); };

(async () => {
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  base = 'http://127.0.0.1:' + port; wsBase = 'ws://127.0.0.1:' + port;

  // --- accounts
  let r = await api('/signup', null, { name: 'Ana Caller', email: 'ana@x.com', password: 'password1', role: 'caller', acceptTerms: true });
  assert.equal(r.status, 200); const caller = r.body.token; ok('caller signs up');
  r = await api('/signup', null, { name: 'Ana Caller', email: 'ana@x.com', password: 'password1', acceptTerms: true });
  assert.equal(r.status, 409); ok('duplicate email rejected');
  r = await api('/signup', null, { name: 'Bad', email: 'bad@x.com', password: 'short', acceptTerms: true });
  assert.equal(r.status, 400); ok('short password rejected');
  r = await api('/signup', null, { name: 'Pablo Protector', email: 'pablo@x.com', password: 'password1', role: 'protector', languages: 'es,en', acceptTerms: true, acceptAgreement: true, experienceType: 'Firefighter', experienceYears: '10', experienceRef: 'Chief X 600000000' });
  const pabloTok = r.body.token, pabloId = r.body.user.id;
  assert.equal(r.body.user.status, 'pending'); ok('protector starts as pending');
  r = await api('/signup', null, { name: 'Marta Protector', email: 'marta@x.com', password: 'password1', role: 'protector', acceptTerms: true, acceptAgreement: true, experienceType: 'Firefighter', experienceYears: '10', experienceRef: 'Chief X 600000000' });
  const martaTok = r.body.token, martaId = r.body.user.id;

  r = await api('/protector/available', pabloTok, { available: true });
  assert.equal(r.status, 403); ok('unapproved protector cannot go available');
  r = await api('/admin/users', caller);
  assert.equal(r.status, 403); ok('caller cannot use admin API');

  // --- admin vetting
  r = await api('/login', null, { email: 'admin@sfe.local', password: 'test-admin-pass' });
  const admin = r.body.token;
  r = await api('/admin/users/' + pabloId + '/approve', admin, {});
  assert.equal(r.status, 400); ok('approval blocked until all five checks are done');
  for (const id of [pabloId, martaId]) {
    for (const k of ['id', 'record', 'references', 'experience', 'training']) await api('/admin/users/' + id + '/checks', admin, { [k]: true });
    r = await api('/admin/users/' + id + '/approve', admin, {});
    assert.equal(r.body.status, 'approved');
  }
  ok('admin completes checks and approves two protectors');

  // --- no protectors online -> immediate fallback
  r = await api('/alerts', caller, { note: 'test', location: { lat: 39.57, lng: 2.65 } });
  assert.equal(r.body.status, 'unanswered'); assert.equal(r.body.reason, 'no_protectors_online');
  ok('no protectors online -> caller told to call 112 immediately');

  // --- ring all, first to accept wins
  r = await api('/protector/available', pabloTok, { available: true }); assert.equal(r.status, 200);
  r = await api('/protector/available', martaTok, { available: true });
  const wsC = await openWS(caller), wsP = await openWS(pabloTok), wsM = await openWS(martaTok);
  r = await api('/availability', caller); assert.equal(r.body.protectorsOnline, 2); ok('availability count shows 2 online');

  r = await api('/alerts', caller, { note: 'Someone is following me', location: { lat: 39.57, lng: 2.65 } });
  assert.equal(r.body.ringing, 2); const alertId = r.body.alertId;
  const aP = await waitFor(wsP, 'alert'), aM = await waitFor(wsM, 'alert');
  assert.equal(aP.caller, 'Ana'); assert.equal(aP.note, 'Someone is following me'); ok('both protectors are rung, caller shown by first name only');
  r = await api('/alerts', caller, {});
  assert.equal(r.status, 409); ok('second simultaneous alert blocked');

  const [accA, accB] = await Promise.all([api('/alerts/' + alertId + '/accept', pabloTok, {}), api('/alerts/' + alertId + '/accept', martaTok, {})]);
  const winners = [accA, accB].filter((x) => x.status === 200), losers = [accA, accB].filter((x) => x.status === 409);
  assert.equal(winners.length, 1); assert.equal(losers.length, 1); ok('simultaneous accepts: exactly one protector wins');
  const winnerWs = accA.status === 200 ? wsP : wsM, loserWs = accA.status === 200 ? wsM : wsP;
  const accepted = await waitFor(wsC, 'accepted'); assert.ok(['Pablo', 'Marta'].includes(accepted.protector));
  await waitFor(loserWs, 'taken'); ok('caller notified, other protector told call was taken');
  assert.equal(winners[0].body.location.lat, 39.57); ok('winning protector receives caller location');

  // --- signalling + 112 log
  wsC.send(JSON.stringify({ type: 'signal', alertId, data: { sdp: { type: 'offer', sdp: 'x' } } }));
  const sig = await waitFor(winnerWs, 'signal'); assert.equal(sig.data.sdp.type, 'offer'); ok('WebRTC signalling relayed caller -> protector');
  await sleep(100); assert.ok(!loserWs.msgs.find((m) => m.type === 'signal')); ok('signalling not leaked to the other protector');
  r = await api('/alerts/' + alertId + '/escalate', caller, {}); assert.equal(r.status, 200);
  await waitFor(winnerWs, 'escalated'); ok('112 tap logged and shown to protector');

  r = await api('/alerts/' + alertId + '/called112', caller, {}); assert.equal(r.status, 200);
  await waitFor(winnerWs, 'called112'); ok('caller confirms 112 called, protector told');

  // --- end, rate, report
  const winnerTok = accA.status === 200 ? pabloTok : martaTok;
  r = await api('/alerts/' + alertId + '/end', winnerTok, {}); assert.equal(r.body.status, 'ended');
  await waitFor(wsC, 'ended'); ok('protector ends call, caller notified');
  r = await api('/alerts/' + alertId + '/rate', caller, { stars: 5 }); assert.equal(r.status, 200);
  r = await api('/alerts/' + alertId + '/rate', caller, { stars: 1 }); assert.equal(r.status, 409); ok('rating works once');
  r = await api('/alerts/' + alertId + '/report', caller, { reason: 'Asked for my number' }); assert.equal(r.status, 200);
  r = await api('/admin/reports', admin); assert.equal(r.body.length, 1); assert.equal(r.body[0].reason, 'Asked for my number'); ok('report reaches admin');

  // --- timeout fallback
  r = await api('/alerts', caller, { note: 'again' }); const a2 = r.body.alertId;
  await waitFor(wsP, 'alert'); await waitFor(wsM, 'alert');
  const un = await waitFor(wsC, 'unanswered', 4000); assert.equal(un.reason, 'timeout');
  await waitFor(wsP, 'taken'); await waitFor(wsM, 'taken'); ok('nobody answers -> caller told after timeout, protectors released');
  r = await api('/alerts/' + a2 + '/accept', pabloTok, {}); assert.equal(r.status, 409); ok('late accept refused');

  // --- cancel while ringing
  r = await api('/alerts', caller, {}); const a3 = r.body.alertId; await waitFor(wsP, 'alert'); await waitFor(wsM, 'alert');
  await api('/alerts/' + a3 + '/end', caller, {});
  await waitFor(wsP, 'taken'); ok('caller cancel releases protectors');

  // --- stats and suspension
  r = await api('/admin/stats', admin);
  assert.equal(r.body.alerts, 4); assert.equal(r.body.answered, 1); assert.equal(r.body.escalatedTo112, 1); ok('pilot metrics computed');
  r = await api('/admin/users/' + pabloId + '/suspend', admin, {}); assert.equal(r.body.status, 'suspended');
  r = await api('/login', null, { email: 'pablo@x.com', password: 'password1' }); assert.equal(r.status, 403); ok('suspended protector cannot log in');

  // --- hourly alert cap (6 total in this test)
  let capped = false;
  for (let i = 0; i < 6 && !capped; i++) {
    const x = await api('/alerts', caller, {});
    if (x.status === 429) capped = true;
    else { assert.equal(x.status, 200); await api('/alerts/' + x.body.alertId + '/end', caller, {}); }
  }
  assert.ok(capped); ok('hourly alert cap enforced');

  // --- consent, export, delete, retention, legal pages
  r = await api('/signup', null, { name: 'No Exp', email: 'ne@x.com', password: 'password1', role: 'protector', acceptTerms: true, acceptAgreement: true });
  assert.equal(r.status, 400); ok('protector sign-up refused without experience details');
  r = await api('/signup', null, { name: 'No Consent', email: 'nc@x.com', password: 'password1' });
  assert.equal(r.status, 400); ok('sign-up refused without accepting terms');
  r = await api('/signup', null, { name: 'No Agree', email: 'na@x.com', password: 'password1', role: 'protector', acceptTerms: true });
  assert.equal(r.status, 400); ok('protector sign-up refused without accepting the agreement');
  r = await api('/admin/users', admin);
  assert.ok(r.body.find((u) => u.id === pabloId).acceptedAgreement.version); ok('agreement acceptance (time + version) visible to admin');
  for (const p of ['/privacy', '/terms', '/protector-agreement']) {
    const t = await (await fetch(base + p)).text(); assert.ok(t.includes('Pilot version') && !t.includes('lawyer review.')); }
  ok('legal pages served');
  r = await api('/me/export', caller); assert.equal(r.status, 200); assert.ok(r.body.alerts.length > 0 && !r.body.account.passHash); ok('data export works and omits password hash');
  const { db, sweep } = require('./server');
  const oldLen = db.alerts.length; db.alerts[0].createdAt = Date.now() - 400 * 86400000;
  assert.equal(sweep().alerts, 1); assert.equal(db.alerts.length, oldLen - 1); ok('retention sweep removes alerts older than 12 months');
  r = await api('/me/delete', caller, { password: 'wrong' }); assert.equal(r.status, 401); ok('delete needs correct password');
  r = await api('/me/delete', caller, { password: 'password1' }); assert.equal(r.status, 200);
  r = await api('/me', caller); assert.equal(r.status, 401);
  assert.ok(!db.users.find((u) => u.email === 'ana@x.com') && db.alerts.every((a) => a.callerId !== 'ana' && !a.note)); ok('account deleted, notes and locations erased');
  console.log(`\n${passed} checks passed`);
  [wsC, wsP, wsM].forEach((w) => w.close());
  server.close(); process.exit(0);
})().catch((e) => { console.error('\nFAILED:', e.message); process.exit(1); });

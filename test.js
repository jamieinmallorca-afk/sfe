// End-to-end test of the alert flow. Run: npm test
process.env.NO_PERSIST = '1';
process.env.ANSWER_SECONDS = '2';
process.env.ADMIN_PASSWORD = 'test-admin-pass';
process.env.MAX_ALERTS_PER_HOUR = '6';
process.env.MAIL_CAPTURE = '1';
process.env.GOOGLE_CLIENT_ID = 'test-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'test-secret';
const assert = require('node:assert/strict');
const WebSocket = require('ws');
const http = require('node:http');
let server, mailOutbox;

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

// stand-in for Google's token endpoint: the code is just the email name to sign in as
function mockGoogle() {
  return new Promise((resolve) => {
    const s = http.createServer((req, res) => {
      let body = ''; req.on('data', (d) => (body += d));
      req.on('end', () => {
        const p = new URLSearchParams(body); const code = p.get('code');
        if (p.get('client_secret') !== 'test-secret' || code === 'bad') { res.writeHead(400); return res.end('{}'); }
        const email = code + (code === 'ana' ? '@x.com' : '@gmail.test');
        const payload = { iss: 'https://accounts.google.com', aud: 'test-client-id', exp: Math.floor(Date.now() / 1000) + 600, email, email_verified: code !== 'unverifiedgoogle', name: code + ' Google', sub: 'sub-' + code };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id_token: 'x.' + Buffer.from(JSON.stringify(payload)).toString('base64url') + '.y' }));
      });
    });
    s.listen(0, () => resolve(s));
  });
}
async function verifyEmail(email) {
  const m = [...mailOutbox].reverse().find((x) => x.type === 'verify' && x.to === email);
  assert.ok(m, 'no verification email for ' + email);
  const r = await fetch(m.link, { redirect: 'manual' });
  assert.equal(r.status, 302); return r.headers.get('location');
}
const google = async (code, expectStatus = 302) => {
  const a = await fetch(base + '/auth/google', { redirect: 'manual' });
  const state = new URL(a.headers.get('location')).searchParams.get('state');
  const cookie = a.headers.get('set-cookie').split(';')[0];
  const r = await fetch(base + '/auth/google/callback?code=' + code + '&state=' + state, { redirect: 'manual', headers: { cookie } });
  assert.equal(r.status, expectStatus); return r;
};

(async () => {
  const gs = await mockGoogle();
  process.env.GOOGLE_TOKEN_URL = 'http://127.0.0.1:' + gs.address().port + '/token';
  ({ server, mailOutbox } = require('./server'));
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
  r = await api('/alerts', caller, {}); assert.equal(r.status, 403); assert.equal(r.body.code, 'email_unverified'); ok('unconfirmed email cannot send alerts');
  r = await api('/resend-verification', caller, {}); assert.equal(r.status, 429); ok('confirmation email can be resent only once a minute');

  // --- admin vetting
  r = await api('/login', null, { email: 'admin@sfe.local', password: 'test-admin-pass' });
  const admin = r.body.token;
  r = await api('/admin/users/' + pabloId + '/approve', admin, {});
  assert.equal(r.status, 400); assert.match(r.body.error, /confirmed their email/); ok('protector cannot be approved before confirming email');
  for (const e of ['ana@x.com', 'pablo@x.com', 'marta@x.com']) assert.ok((await verifyEmail(e)).includes('verified=1'));
  assert.ok((await verifyEmail('ana@x.com')).includes('verified=0')); ok('confirmation links work once');
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

  // --- forgot / reset password
  r = await api('/signup', null, { name: 'Reset Me', email: 'reset@x.com', password: 'oldpassword1', acceptTerms: true }); const resetTok = r.body.token;
  const before = mailOutbox.length;
  r = await api('/forgot', null, { email: 'nobody@x.com' }); assert.equal(r.status, 200); assert.equal(mailOutbox.length, before); ok('forgot password gives the same answer for unknown emails, sends nothing');
  r = await api('/forgot', null, { email: 'reset@x.com' }); assert.equal(r.status, 200);
  const rm = mailOutbox.filter((m) => m.type === 'reset' && m.to === 'reset@x.com').pop(); assert.ok(rm);
  r = await api('/reset', null, { token: rm.token, password: 'short' }); assert.equal(r.status, 400);
  r = await api('/reset', null, { token: rm.token, password: 'newpassword1' }); assert.equal(r.status, 200);
  r = await api('/reset', null, { token: rm.token, password: 'another-pass1' }); assert.equal(r.status, 400); ok('reset link works once');
  r = await api('/me', resetTok); assert.equal(r.status, 401); ok('reset signs out old sessions');
  r = await api('/login', null, { email: 'reset@x.com', password: 'oldpassword1' }); assert.equal(r.status, 401);
  r = await api('/login', null, { email: 'reset@x.com', password: 'newpassword1' }); assert.equal(r.status, 200); assert.equal(r.body.user.emailVerified, true); ok('new password works, old one does not');

  // --- Google sign-in
  r = await fetch(base + '/api/config').then((x) => x.json()); assert.equal(r.googleEnabled, true);
  await google('bad', 302).then((x) => assert.ok(x.headers.get('location').includes('gerror'))); ok('failed Google exchange sends the user back with an error');
  const bad = await fetch(base + '/auth/google/callback?code=x&state=nope', { redirect: 'manual' }); assert.equal(bad.status, 400); ok('Google callback with wrong state refused');
  let g = await google('newuser'); let loc = g.headers.get('location'); assert.ok(loc.startsWith('/#google='));
  const gtok = loc.split('=')[1];
  r = await api('/google/pending?token=' + gtok); assert.equal(r.body.email, 'newuser@gmail.test');
  r = await api('/google/complete', null, { token: gtok, role: 'caller' }); assert.equal(r.status, 400); ok('Google sign-up needs the terms ticked');
  r = await api('/google/complete', null, { token: gtok, role: 'caller', acceptTerms: true }); assert.equal(r.status, 200); assert.equal(r.body.user.emailVerified, true);
  const gSession = r.body.token; assert.ok(r.body.user.acceptedTerms.version); ok('Google sign-up creates a confirmed account with terms recorded');
  g = await google('newuser'); assert.ok(g.headers.get('location').startsWith('/#token=')); ok('returning Google user is signed in');
  r = await api('/google/complete', null, { token: gtok, role: 'caller', acceptTerms: true }); assert.equal(r.status, 400); ok('Google sign-up link cannot be reused');
  r = await api('/signup', null, { name: 'Victim', email: 'victim@gmail.test', password: 'attackerpass1', acceptTerms: true }); const atk = r.body.token;
  g = await google('victim'); assert.ok(g.headers.get('location').startsWith('/#token='));
  r = await api('/login', null, { email: 'victim@gmail.test', password: 'attackerpass1' }); assert.equal(r.status, 401);
  r = await api('/me', atk); assert.equal(r.status, 401); ok('Google sign-in takes over an unconfirmed account and removes the old password');
  r = await api('/me/delete', gSession, { confirmEmail: 'wrong@x.com' }); assert.equal(r.status, 401);
  r = await api('/me/delete', gSession, { confirmEmail: 'newuser@gmail.test' }); assert.equal(r.status, 200); ok('Google-only account can be deleted by typing its email');

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

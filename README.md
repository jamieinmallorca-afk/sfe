# sfe prototype

A working prototype of sfe: people who feel unsafe tap SOS and ring vetted volunteer "protectors". The first to answer
talks with them by in-browser voice call. A 112 button is always on screen. This is a prototype for a small supervised
pilot. It is NOT ready for public launch (see "Before real use").

## Run it
    npm install
    ADMIN_PASSWORD='choose-a-strong-one' npm start      # http://localhost:3000
    npm test                                             # 27 end-to-end checks of the alert flow

Open the site on two devices (or two browser windows):
1. Sign up as a protector. Log in as the admin (admin@sfe.local + your ADMIN_PASSWORD), open Applications, tick the four
   vetting checks and Approve. Approval is refused until all four are ticked.
2. Log in as the protector, tick Available, and keep the page open.
3. Sign up as a caller and press SOS. The protector hears a tone, taps Answer, and the voice call connects.

Admin has tabs for applications, protectors (suspend/reinstate), reports, and pilot metrics (time to answer,
answered within 30 s, share that tapped 112, ratings).

## What is built
- Accounts, protector applications, four-check vetting gate, admin approve/reject/suspend
- SOS: rings every available protector at once; first to accept wins (race-safe); others are released
- 30 s no-answer fallback (and instant fallback when nobody is online) telling the caller to call 112
- In-browser voice via WebRTC, signalled over WebSocket; no phone numbers are ever exchanged
- Caller location shared live with the protector (optional, caller can switch it off)
- Ratings, reporting, hourly alert cap, login rate limit, protector script and 112 reminders on screen

## Before real use (not done yet)
- HTTPS hosting in the EU. Microphone and location need HTTPS except on localhost.
- TURN server for calls over mobile networks and strict firewalls (set ICE_SERVERS as JSON). Only STUN is configured.
- Alerts only arrive while the protector's page is open. Real silent-mode alerts need a native app with push
  notifications (iOS Critical Alerts entitlement, Android high-priority channel).
- Replace db.json with a real database, and add backups, logging and monitoring.
- Email verification, password reset, stronger session handling, a professional security and penetration review.
- GDPR work: privacy notice, consent records, data retention, a data protection impact assessment.
- Real vetting and training processes, insurance, and Spanish legal sign-off (see the business plan).
- Run only small, supervised pilots until these are done.

## Files
- server.js: API, alert logic, WebSocket signalling
- public/index.html: the whole mobile-first app (caller, protector and admin screens)
- test.js: automated end-to-end test


## Legal texts and account tools

- `legal/*.md` are served at `/privacy`, `/terms`, `/protector-agreement`. Edit the markdown, bump `LEGAL_VERSION` in `server.js`, redeploy.
- Sign-up records acceptance (time + version). Users can download their data and delete their account from the footer. A retention job removes alerts older than 12 months and resolved reports older than 24 months.

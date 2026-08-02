# BurnChat — Security Notes

## What's genuinely good here

**End-to-end encryption design.** The server never sees plaintext or raw
symmetric keys:
- Each message is AES-256-GCM encrypted via ChaosKey, producing a
  per-message symmetric key.
- That symmetric key is then wrapped twice with RSA-OAEP: once under the
  recipient's public key, once under the sender's own public key (so the
  sender can also decrypt their own sent messages on any device).
- RSA private keys are generated **client-side** in the browser
  (`crypto.subtle.generateKey`) and never transmitted in raw form. What
  *is* sent to the server is an AES-GCM-encrypted "vault" blob (private
  key encrypted under a PBKDF2-derived key from the user's password),
  so the server only ever stores ciphertext it can't open.
- This means: if the database is dumped, the attacker gets message
  ciphertext and wrapped keys, not plaintext — as long as passwords are
  strong (PBKDF2 100k iterations is on the low side, see below).

**Auth basics are right**: bcrypt with a real salt+cost factor, session
cookies rather than passing credentials on every request, `require_login`
enforced on every sensitive route, password comparison for the fallback
path uses `hmac.compare_digest` (constant-time) rather than `==`.

**The ChaosKey API key never reaches the browser.** `/proxy/encrypt` and
`/proxy/decrypt` are server-side relays — the client calls your server,
your server calls ChaosKey with a key it holds. That's the correct shape
for "don't ship a secret to a de-obfuscatable client."

## Real weaknesses — in rough order of severity

1. **The server is a fully trusted party despite the E2EE framing.**
   The server brokers *every* RSA key exchange (`/user/key`,
   `/user/keys_bulk`) with no verification. A malicious or compromised
   server can trivially MITM: swap in a public key it controls when
   Alice asks for Bob's key, and Alice's client will happily encrypt to
   the attacker. There's no key fingerprint verification, no
   TOFU/pinning, no out-of-band verification UI. This is the standard
   gap between "encrypted so the DB dump is safe" and "actually
   end-to-end secure against the server operator" — worth being explicit
   about which one you're promising users.

2. **PBKDF2 iteration count (100,000) is dated.** OWASP's current
   guidance for PBKDF2-HMAC-SHA256 is closer to 600,000 iterations, or
   switching to Argon2id, which resists GPU/ASIC cracking much better.
   If a vault blob leaks, an attacker cracking a weak password is
   meaningfully easier at 100k than at OWASP's current number.

3. **RSA private key sits in `localStorage` in plaintext (unwrapped)
   between sessions**, cached via `_cachePrivKey`/`bc_priv_<email>`.
   Anything that achieves script execution in that origin — a future XSS
   bug, a malicious browser extension, a compromised CDN script — reads
   every private key ever cached there, permanently, with no
   expiration. `localStorage` also isn't cleared on logout in the
   current flow beyond in-memory state.

4. **CORS + credentialed cookies is a dangerous combination if ever
   deployed with a wildcard origin.** `CORS(app, supports_credentials=True)`
   with no explicit `origins=` allowlist means Flask-CORS may reflect
   whatever `Origin` header the browser sends, which — combined with
   session cookies — is close to CSRF-by-design. This needs an explicit
   origin allowlist before this ever leaves localhost.

5. **No CSRF protection on state-changing POST routes.** Session cookies
   + no CSRF token means a malicious page a logged-in user visits can
   fire POSTs to `/msg/send`, `/msg/burn`, `/auth/update_ck_key`, etc.,
   using the ambient cookie. `SameSite=Lax` (Flask's session cookie
   default) mitigates simple cases but isn't a substitute for a real
   CSRF token, especially once CORS is loosened for a real frontend
   origin.

6. **No rate limiting anywhere** — login, signup, and `/msg/search_user`
   are all unthrottled. Login is brute-forceable; `search_user` allows
   silent enumeration of every registered email/display name.

7. **SECRET_KEY defaults to a freshly-random value per process start**
   if the env var isn't set. Convenient for a demo, but it means: (a)
   restarting the server or running multiple workers invalidates every
   session silently, and (b) if someone deploys this as-is without
   setting `SECRET_KEY`, that's at least a functional footgun, and in a
   multi-process deployment (gunicorn with >1 worker) different workers
   would sign cookies with different keys, causing random logouts —
   this needs to be a required, explicitly-set env var in production.

8. **Bcrypt fallback path.** If the `bcrypt` package isn't installed,
   the code silently falls back to a hand-rolled `salt + sha256`
   scheme. SHA-256 is fast, which is exactly the wrong property for
   password hashing (cheap to brute-force at scale on GPUs). This
   fallback should either not exist, or fail loudly rather than quietly
   degrading security.

9. **Burn thread is a real DELETE, but there's no confirmation the
   recipient's copy is also gone in any stronger sense than DB rows** —
   there's no true "disappearing messages" guarantee (e.g. nothing stops
   a client from having cached decrypted plaintext in memory, or a
   screenshot). That's a UX/expectations issue more than a bug, but
   "Burn" as a name invites users to assume more than the system
   guarantees.

10. **No input length limits on `ciphertext`/`nonce`/etc.** at the
    application layer — those go straight into SQL params (safe from
    injection, since they're parameterized), but there's no cap
    preventing someone from sending an enormous "message" and bloating
    storage, short of whatever ChaosKey enforces upstream.

## Priority if you're taking this to production

1. Lock down CORS to an explicit origin allowlist.
2. Add CSRF tokens to state-changing requests.
3. Add rate limiting to `/auth/login`, `/auth/signup`, `/msg/search_user`.
4. Require `SECRET_KEY` to be set (fail startup if missing) rather than
   silently generating one.
5. Bump PBKDF2 iterations or move to Argon2id for the vault key
   derivation.
6. Decide explicitly whether you're promising "safe if the DB leaks" or
   "safe even from us" — if the latter, you need key verification
   (safety numbers / fingerprint comparison UI), not just key exchange.
7. Remove the SHA-256 password-hash fallback, or make it refuse to start
   instead of silently degrading.

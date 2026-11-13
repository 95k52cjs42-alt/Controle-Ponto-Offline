# Security deployment checklist

The application is configured through environment variables. Production needs
`PUBLIC_BASE_URL=https://ponto.example.com`, `COOKIE_SECURE=true`, a strong
`SECRET_KEY` (at least 32 characters, generated, never copied from docs), and a
comma-separated `TRUSTED_HOSTS` list containing the public host. The app refuses
to start in production when any of these is missing or weak.

On Heroku (the `DYNO` variable is present) production mode and
`TRUST_PROXY_HEADERS` are the defaults, so a forgotten `APP_ENV` fails closed:
the release phase (`init-db`) aborts the deploy instead of running with
development settings. Elsewhere set `APP_ENV=production` explicitly.

```dotenv
APP_ENV=production
PUBLIC_BASE_URL=https://ponto.example.com
TRUSTED_HOSTS=ponto.example.com
COOKIE_SECURE=true
SECRET_KEY=<output of: python -c "import secrets; print(secrets.token_hex(32))">
AUTO_INIT_DB=false
TRUST_PROXY_HEADERS=true
```

`TRUST_PROXY_HEADERS=true` is safe only when exactly one trusted reverse proxy
(such as the Heroku router) appends the client address to `X-Forwarded-For`
and sets `X-Forwarded-Proto`. With it on, production redirects plain HTTP to
HTTPS and sends HSTS.

Create/migrate tables during deployment, then create the first administrator
explicitly:

```text
flask --app app init-db
flask --app app bootstrap-admin --email admin@example.com --nome "Administrador"
```

## What the app enforces

- **Tokens.** Password reset and invite tokens are opaque, purpose-bound,
  expiring, hashed at rest and single-use. Setting a password by any route
  voids the user's other pending links.
- **Sessions.** Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure`
  in production. Password and role changes end open sessions.
- **CSRF.** All state-changing form and JSON requests require the CSRF token.
- **Login limits.** Login is rate-limited per IP (POST attempts only). There
  is also a per-account lockout stored in the database: 5 failures in 15
  minutes, counted for unknown e-mails too, so it does not reveal which
  accounts exist.
- **Audit log.** Logins, failed logins, logouts and password resets are
  written to it.
- **Content Security Policy.** Scripts need a per-request nonce or must be one
  of the pinned CDN files, which also carry SRI hashes. Inline event handlers
  are blocked. When adding a CDN script, add its exact URL to `_CDN_SCRIPTS` in
  `app.py` and its `integrity` hash to the tag.
- **Separation of duties.**
  - Nobody grants themselves a new role.
  - RH cannot reset the password of, or delete, RH or TI accounts.
  - Nobody edits, approves or deletes entries on their own timesheet, or
    their own leave records.
- **Push notifications.** Only endpoints of real push services (FCM, Mozilla,
  WNS, Apple) are accepted, with at most 5 devices per user.

Run the isolated regression suite without touching the application database:

```text
python -m unittest discover -s tests -p "test_*.py" -v
```

The suite uses a temporary SQLite database and temporary upload directory.
Dependencies are pinned in `requirements.txt`; upgrade them deliberately and
rerun the suite.

# Security deployment checklist

The application is configured through environment variables. Production must be
explicit: `APP_ENV=production`, `PUBLIC_BASE_URL=https://ponto.example.com`,
`COOKIE_SECURE=true`, a strong `SECRET_KEY` (at least 32 characters), and a
comma-separated `TRUSTED_HOSTS` list containing the public host.

```dotenv
APP_ENV=production
PUBLIC_BASE_URL=https://ponto.example.com
TRUSTED_HOSTS=ponto.example.com
COOKIE_SECURE=true
SECRET_KEY=2d757d696d5190632b338f929beaf23dd7043c4eb35d9ad3cdb1dff19e6937ea
AUTO_INIT_DB=false
TRUST_PROXY_HEADERS=true
```

`TRUST_PROXY_HEADERS=true` is safe only when exactly one trusted reverse proxy
removes client-supplied `X-Forwarded-For` and `X-Forwarded-Proto` values and
sets its own. The proxy must terminate TLS and pass traffic to Gunicorn only
over the trusted network.

Create/migrate tables during deployment, then create the first administrator
explicitly:

```text
flask --app app init-db
flask --app app bootstrap-admin --email admin@example.com --nome "Administrador"
```

The public registration flow never promotes its first user to administrator.
Password/reset/invite/confirmation tokens are opaque, purpose-bound, expiring,
hashed at rest, and single-use. Session cookies are `HttpOnly`, `SameSite=Lax`,
and `Secure` in production. All state-changing form and JSON requests require
the CSRF token.

Run the isolated regression suite without touching the application database:

```text
python -m unittest discover -s tests -p "test_*.py" -v
```

The suite uses a temporary SQLite database and temporary upload directory.

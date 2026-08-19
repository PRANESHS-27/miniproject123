# 🔐 Security Notes

- **Secrets** — never commit `.env` files; rotate `SECRET_KEY` and DB credentials in production.
- **JWT** — access tokens default to 24h; shorten for high-security environments.
- **HTTPS** — always terminate TLS at Nginx or the load balancer (Let's Encrypt).
- **CORS** — `allow_origins=["*"]` is for dev only; in prod, set explicit origins in `app/main.py`.
- **Postgres** — restrict network access (Security Groups / VPC); use a least-privilege user.
- **API rate-limiting** — for production, add `slowapi` or run Nginx `limit_req` zone.
- **NVD API key** — request a free key from NIST for higher rate limits.
- **Audit** — every search is logged to `search_logs` for compliance.
- **Dependency updates** — `pip-audit` and `npm audit` should be part of CI.

## Reporting vulnerabilities

Please email `security@vulnwatch.local` with details.
# TDCI Discipleship API

Backend service for the TDCI Discipleship app. It stores each member's cloud tracker privately and supports branch-specific monthly goals and church links across the TDCI network.

## Deploy on Render

1. Create a Render Blueprint from this repository and apply `render.yaml`.
2. The blueprint creates the Node web service and PostgreSQL database in Frankfurt.
3. Set `ADMIN_EMAILS` to the comma-separated emails allowed to manage plans and church links. Do this before those people create accounts.
4. Wait for `/api/health` to report healthy, then enter the service's HTTPS address in the app's cloud settings.

The blueprint generates `SESSION_SECRET` and connects `DATABASE_URL` to its managed database. Keep both in Render's environment settings. Do not commit `.env` files or credentials. The first church admin can publish the official prayer and messages Telegram links in the app.

## Scaling

- Member activity is stored as rows keyed by member and entry ID. Month views use indexed, keyset-paginated queries capped at 250 entries per response. Sign-in loads private metadata and the selected month, rather than downloading every year of activity.
- App instances are stateless: sessions and member records live in PostgreSQL, so additional API instances can serve the same accounts without sticky sessions.
- Each member selects one branch at signup. Plans and Telegram resources are keyed by branch and month. Existing accounts, plans, and links are migrated into the default `main` branch. Allowlisted TDCI administrators can add branches and manage plans and links across the network; delegated branch-only admin roles are a future extension.
- `PG_POOL_MAX` and `PG_CONNECTION_TIMEOUT_MS` tune each instance's PostgreSQL pool. Before increasing Render instance count, keep `instance count × PG_POOL_MAX` within the database connection limit, leaving capacity for migrations and maintenance. Increase pool size only when database capacity supports it.
- The Blueprint starts with one Starter API instance and a small paid database. Increase the API and database plans in Render as usage grows; enable additional API instances only after checking the database's connection and storage capacity. Keep the API and database in the same region.
- PostgreSQL backups and restore procedures should be enabled and reviewed in Render before launch with real member data.

## Local run

Requires Node.js 22–24 and PostgreSQL.

```powershell
cd server
npm ci
$env:DATABASE_URL="postgres://…"
$env:SESSION_SECRET="a-long-random-secret"
npm start
```

The service listens on `PORT` (default `10000`). Set `ADMIN_EMAILS` and `ALLOWED_ORIGINS` as needed. For the Android app, retain the `capacitor://localhost` origin. Avoid wildcard origins.

## API overview

- `GET /api/health` — service and database health
- `GET /api/branches` — active branch directory for sign-up
- `POST /api/branches` — admin-only branch creation
- Member accounts: `POST /api/auth/register`, `POST /api/auth/login`
- Church admin accounts: `POST /api/auth/admin/register`, `POST /api/auth/admin/login`; admin email must be in `ADMIN_EMAILS`
- `GET /api/auth/me`, `POST /api/auth/logout`
- `GET /api/me/state?includeEntries=false`, `PUT /api/me/state` — private member metadata and legacy migration path
- `GET /api/me/entries/:YYYY-MM?limit=100&afterDate=YYYY-MM-DD&afterId=...`, `PUT /api/me/entries`, `DELETE /api/me/entries/:id` — private activity records and paginated month reads
- `GET /api/church/resources?branchId=main` — published branch prayer and messages links
- `PUT /api/church/resources?branchId=main` — admin-only branch links editor
- `GET /api/plans/:YYYY-MM?branchId=main` — branch monthly goals
- `PUT /api/plans/:YYYY-MM?branchId=main` — admin-only branch monthly goals
- `POST /api/auth/delete`, `/delete-account` — account deletion
- `/privacy` — privacy policy

Passwords are stored as scrypt hashes. Session tokens are stored as hashes and sent in secure, HTTP-only cookies. Member activity and metadata are scoped to the authenticated account.

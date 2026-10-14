# TDCI Discipleship API

Backend service for the TDCI Discipleship app. It stores each member's cloud tracker privately and lets TDCI administrators publish monthly discipleship goals.

## Deploy on Render

1. In Render, create a **Blueprint** from this repository and apply `render.yaml`.
2. The blueprint creates the Node web service and PostgreSQL database in Frankfurt.
3. In the service environment, set `ADMIN_EMAILS` to the comma-separated email addresses allowed to manage monthly plans. Set it before those users create accounts.
4. Wait for `/api/health` to return `{"ok":true,...}`. Enter the service's `https://…onrender.com` URL in the app's cloud settings.

The blueprint generates `SESSION_SECRET` and connects `DATABASE_URL` to its managed database. Keep both values in Render's environment settings. Do not commit `.env` files or credentials. After the first church admin signs in, they can publish the official prayer and messages Telegram links from the app's Monthly plan screen.

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

- `GET /api/health` — service/database health
- Member accounts use `POST /api/auth/register` and `POST /api/auth/login`.
- Church administrators use the separate `POST /api/auth/admin/register` and `POST /api/auth/admin/login` endpoints. Admin registration and login require the email to be listed in `ADMIN_EMAILS`.
- `GET /api/auth/me`, `POST /api/auth/logout`
- `GET`/`PUT /api/me/state` — signed-in member's private tracker
- `GET /api/church/resources` — published church prayer and messages links (public)
- `PUT /api/church/resources` — admin-only church links editor
- `GET /api/plans/:YYYY-MM` — monthly goals
- `PUT /api/plans/:YYYY-MM` — admin-only monthly goals
- `POST /api/auth/delete`, `/delete-account` — account deletion
- `/privacy` — privacy policy

Passwords are stored as scrypt hashes. Session tokens are stored as hashes and sent in secure, HTTP-only cookies. Member state is keyed to the authenticated account.

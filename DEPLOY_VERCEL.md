# Deploy Frontend + Backend On Vercel

This project can be deployed from a single repo:
- frontend: Vite static output from `dist`
- backend: Vercel serverless functions in `api/*`

## 1. Push repo to GitHub

Run in project root:

```powershell
git init
git add .
git commit -m "Prepare Vercel deployment"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

## 2. Create project on Vercel

1. Go to Vercel dashboard.
2. Click `Add New...` -> `Project`.
3. Import your GitHub repo.
4. Framework preset: Vite (auto-detected).

`vercel.json` already sets:
- Build Command: `npm run build`
- Output Directory: `dist`

## 3. Add environment variables in Vercel

Project -> Settings -> Environment Variables

Required:

- `ACCESS_CODE` = your access code (example: `S@OSINT*#`)
- `LOOKUP_KEY` = your lookup key
- `ACCESS_TOKEN_SECRET` = long random string

Optional but recommended:

- `GOOGLE_SHEETS_WEBHOOK_URL` = your Apps Script `/exec` URL
- `ALLOWED_ORIGIN` = your Vercel app URL (example: `https://your-app.vercel.app`)
- `COOKIE_SECURE` = `true`
- `SESSION_TTL_MS` = `300000` (5 minutes)
- `VERIFY_LIMIT_WINDOW_MS` = `60000`
- `VERIFY_LIMIT_MAX` = `5`

## 4. Deploy

Click `Deploy` in Vercel.

After deploy:
- frontend runs at `/`
- backend endpoints:
  - `/api/verify`
  - `/api/session`
  - `/api/logout`
  - `/api/lookup`

## 5. Verify quickly

1. Open deployed URL.
2. Enter access code.
3. Run a search.
4. Confirm result appears in UI.
5. If configured, confirm a row is added in Google Sheets.

## Notes

- Local `server.cjs` can still be used for local development.
- On Vercel, the `api/*` functions are used instead of the local Node server process.
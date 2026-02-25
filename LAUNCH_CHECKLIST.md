# HuntAO Launch Checklist

## 1) Environment Variables (Production)
Set all of these in your host:

- `NODE_ENV=production`
- `APP_BASE_URL=https://hunt-ao.com`
- `CORS_ORIGIN=https://hunt-ao.com`
- `AUTH_SECRET=<long random string>`
- `ADMIN_EXPORT_KEY=<long random string>`
- `RESEND_API_KEY=<your resend key>`
- `EMAIL_FROM=noreply@hunt-ao.com`
- `FEEDBACK_TO_EMAIL=ethanprebleco@gmail.com`

Use `.env.production.example` as your template.

## 2) Domain + DNS
- Point `hunt-ao.com` to your hosting provider
- Add `www` if desired (redirect to apex or vice versa)

## 3) Email Deliverability
In Resend:
- Verify domain `hunt-ao.com`
- Add all DNS records Resend asks for (SPF/DKIM)
- Confirm sender `noreply@hunt-ao.com` is valid

## 4) Smoke Test (Production URL)
- Open app URL and ensure map loads
- Create account (new email)
- Verify email link works
- Login after verification succeeds
- Request password reset and reset password
- Submit report using "Report Problem" and verify email arrives

## 5) Security Checks
- Confirm `/data/app-data.json` is blocked
- Confirm `/server.js` is blocked
- Confirm admin routes require `x-admin-key` in production

## 6) Optional Local Preflight Script
From project root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\prelaunch-check.ps1 -BaseUrl "http://localhost:5173" -AdminKey "<your-admin-key>"
```

## 7) Go/No-Go
Go live only if all checks above pass.

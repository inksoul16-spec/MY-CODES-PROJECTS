# BJC MEDIA STUDIO

BJC MEDIA STUDIO is a complete starter marketplace where a cameraman uploads images/videos and customers can browse, download during a 30-day free trial, then continue via per-asset purchase or premium subscription.

## Features
- Cameraman admin login with protected upload page.
- Upload image/video files with title, description, and price.
- Buyer registration/login.
- Automatic 30-day free trial on buyer signup.
- Trial + premium + single purchase access rules for downloads.
- Buyer dashboard with subscription status and purchase history.
- Ready to deploy to any Node.js hosting service.

## Tech stack
- Node.js + Express
- EJS templates
- SQLite (better-sqlite3)
- File uploads with multer
- Session auth with express-session + SQLite store

## Quick start
1. Install dependencies:
   ```bash
   npm install
   ```
2. Configure environment:
   ```bash
   cp .env.example .env
   ```
3. Edit `.env` values, especially `SESSION_SECRET` and `ADMIN_PASSWORD`.
4. Start server:
   ```bash
   npm start
   ```
5. Open `http://localhost:3000`.

## Deployment checklist
- Set strong values for `SESSION_SECRET` and `ADMIN_PASSWORD`.
- Attach persistent storage for SQLite DB and `uploads/` folder.
- Run behind HTTPS.
- Replace demo payment buttons with real gateway integration (Stripe/PayPal).

## User flows
### Cameraman (admin)
- Go to `/admin/login`.
- Login with `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
- Upload media at `/admin/upload`.

### Buyer
- Register from `/register` and get a 30-day trial automatically.
- Download any media during trial.
- After trial, either:
  - Buy individual media on asset page, or
  - Subscribe premium from dashboard (`$19.99` demo charge).

## Important note
This project includes **demo checkout logic** only (records purchases locally). To accept real payments, integrate a payment provider and verify payments server-side before granting access.

# CHESTER TECHNOLOGIES — starter platform

A responsive, dark emerald-themed full-stack starter for the first CHESTER TECHNOLOGIES milestone: user panel + admin panel.

## Included
- User registration, login and logout
- Password hashing with bcrypt
- Persistent SQLite database
- SQLite-backed session storage
- User profile editing API and password change API
- User overview, department preview, service request form and support tickets
- Admin overview, user suspension/reactivation, plan assignment, ticket management, order status management
- Admin-editable public support helpline (initially +44 7888 370178)
- Basic security headers, login/register rate limiting and server-side role checks

## Run on Replit
1. Create a new **Node.js** Replit project.
2. Upload this ZIP and extract its contents into the project root (so `package.json` and `server.js` are at the root).
3. Open **Tools → Secrets** (or the Secrets panel) and add:
   - `SESSION_SECRET`: a long, random secret (at least 32 random characters).
   - `ADMIN_EMAIL`: your chosen administrator email.
   - `ADMIN_PASSWORD`: a strong, unique password of at least 12 characters.
4. Optional: set `SUPPORT_PHONE` to the public support number.
5. In the Shell, run `npm install`.
6. Click Run. The app starts on the port supplied by Replit.

The first administrator is created from `ADMIN_EMAIL` and `ADMIN_PASSWORD` when the server starts for the first time. Keep these secrets private. If you change the admin password environment variable later, the existing database account is not automatically overwritten; change it through a secure password-management workflow.

## Local run
- Install Node.js 20 or newer.
- Copy `.env.example` to `.env` and set strong secret values.
- Install dependencies with `npm install`.
- Run `npm start`.
- Open `http://localhost:3000`.

This project does not automatically load `.env`; on Replit, add values through Secrets. For local development, export environment variables in your shell or use a dotenv runner.

## Important limitations before public launch
This is a working foundation/prototype, not a fully audited production service.
- The wallet is display-only and always shows $0. No deposits, withdrawals or payments are processed.
- Orders are requests only. No real hosting, data bundles, airtime or third-party services are fulfilled.
- Subscription plans are labels only. No billing or paid entitlement enforcement is connected.
- The department cards are previews; the four departments are not yet integrated.
- Email verification, password reset delivery, MFA, CSRF protection, administrator audit trails, automated backups and production monitoring still need implementation and security review.
- The profile and password APIs exist; a full profile/password settings screen is a later UI task.
- Use HTTPS in production. Set `NODE_ENV=production` and a strong `SESSION_SECRET`.
- Back up the `data/` directory. Do not delete it if you want to preserve accounts and sessions.
- Before accepting real users or money, arrange a security review and implement the remaining production controls.

## Project layout
- `server.js` — Express API, authentication, database and admin authorization
- `public/` — website interface
- `data/` — created automatically for persistent SQLite data

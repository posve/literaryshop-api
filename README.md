# literaryshop-api — Local setup

This small README explains how to bootstrap a local Postgres database and run the API for development without changing runtime code.

Prerequisites
- Node 18+ (the project engines specify >=18)
- PostgreSQL locally, or a hosted Postgres (Neon, Supabase, etc.)
- `psql` CLI if you want to run the SQL files locally

Quickstart
1. Copy the example env and fill in values:

   cp .env.example .env
   # then edit .env and set DATABASE_URL and any overrides

2. Create the database (if using a local Postgres):

   createdb literaryshop
   # or use your preferred DB creation method

3. Apply schema:

   psql "$DATABASE_URL" -f db/schema.sql

4. Seed sample data:

   psql "$DATABASE_URL" -f db/seed.sql

5. Install dependencies and run the server:

   npm install
   npm run dev

Notes
- The schema creates a simple `order_seq` and uses `ORD-XXXXXXXX` style `order_id` strings by default so the API returns readable order IDs.
- This repository does not change the server runtime; these files are helper artifacts intended to make local development and testing reproducible.
- For hosted Postgres (Neon), set `DATABASE_URL` in your project/secret settings and run the SQL files via the platform or `psql`.

Security
- The default admin credentials in `.env.example` are development defaults. Do not use them in production. Use secure secrets management for deployment.

If you want, I can also add a simple `npm` script to run the schema/seed steps locally (low-risk). Let me know.
-- Schema for literaryshop-api
-- Run: psql <DATABASE_URL> -f db/schema.sql

-- Sequence for human-friendly order IDs
CREATE SEQUENCE IF NOT EXISTS order_seq START 10000000;

-- Books table
CREATE TABLE IF NOT EXISTS books (
  isbn text PRIMARY KEY,
  title text NOT NULL,
  author text NOT NULL,
  description text,
  price numeric(10,2) NOT NULL,
  stock integer NOT NULL DEFAULT 0,
  image_url text,
  category text
);

-- Orders table: uses a text order_id like ORD-00000001 by default
CREATE TABLE IF NOT EXISTS orders (
  order_id text PRIMARY KEY DEFAULT ('ORD-' || lpad(nextval('order_seq')::text,8,'0')),
  customer_name text NOT NULL,
  customer_email text NOT NULL,
  customer_address text NOT NULL,
  customer_city text NOT NULL,
  customer_postal_code text NOT NULL,
  customer_country text NOT NULL,
  delivery_option text NOT NULL,
  total numeric(10,2) NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Order items
CREATE TABLE IF NOT EXISTS order_items (
  id serial PRIMARY KEY,
  order_id text NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
  isbn text REFERENCES books(isbn),
  quantity integer NOT NULL,
  price numeric(10,2) NOT NULL
);

-- Admin users table for authentication
CREATE TABLE IF NOT EXISTS admin_users (
  id serial PRIMARY KEY,
  username text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  email text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_books_title ON books (lower(title));
CREATE INDEX IF NOT EXISTS idx_books_author ON books (lower(author));
CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users (username);

-- Seed data for literaryshop-api
-- Run: psql <DATABASE_URL> -f db/seed.sql

INSERT INTO books (isbn, title, author, description, price, stock, image_url, category)
VALUES
('978-0-06-112008-4', 'To Kill a Mockingbird', 'Harper Lee', 'A classic of modern American literature', 24.99, 15, 'https://images.unsplash.com/photo-1543002588-bfa74002ed7e?w=400', 'Fiction')
ON CONFLICT (isbn) DO UPDATE SET title = EXCLUDED.title, author = EXCLUDED.author, price = EXCLUDED.price, stock = EXCLUDED.stock;

INSERT INTO books (isbn, title, author, description, price, stock, image_url, category)
VALUES
('978-0-14-028329-3', '1984', 'George Orwell', 'A dystopian social science fiction novel', 19.99, 23, 'https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=400', 'Fiction')
ON CONFLICT (isbn) DO UPDATE SET title = EXCLUDED.title, author = EXCLUDED.author, price = EXCLUDED.price, stock = EXCLUDED.stock;

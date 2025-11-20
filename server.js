// server.js - Complete Backend Server
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { uploadImage, extractKeyFromUrl } = require('./scaleway-storage');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection error:', err.stack);
  } else {
    console.log('✅ Database connected successfully');
    release();
  }
});

// Trust proxy - needed for rate limiting to work correctly on Render/Vercel
app.set('trust proxy', 1);

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// Multer configuration for image uploads (stores in memory)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB max
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, WebP, and GIF allowed'));
    }
  }
});

// ============================================================================
// RATE LIMITING & MIDDLEWARE
// ============================================================================

// Rate limiting for login endpoint (5 attempts per 15 minutes)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV !== 'production', // Skip rate limiting in development
});

// Rate limiting for general API (100 requests per 15 minutes)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: (req) => req.method === 'GET', // Skip rate limiting for GET requests
  standardHeaders: true,
  legacyHeaders: false,
});

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
};

// CSRF Token validation middleware
const validateCsrfToken = (req, res, next) => {
  const csrfToken = req.headers['x-csrf-token'];

  if (!csrfToken) {
    return res.status(403).json({
      success: false,
      message: 'CSRF token required'
    });
  }

  try {
    const decoded = jwt.verify(csrfToken, JWT_SECRET);
    // Check if token is not too old (additional security check)
    const tokenAge = Date.now() - decoded.timestamp;
    const maxAge = 60 * 60 * 1000; // 1 hour

    if (tokenAge > maxAge) {
      return res.status(403).json({
        success: false,
        message: 'CSRF token expired'
      });
    }

    req.csrfValid = true;
    next();
  } catch (err) {
    return res.status(403).json({
      success: false,
      message: 'Invalid CSRF token'
    });
  }
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '');
};

const isValidISBN = (isbn) => {
  const cleaned = isbn.replace(/[-\s]/g, '');
  return /^\d{10}(\d{3})?$/.test(cleaned);
};

const isValidEmail = (email) => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

// ============================================================================
// PUBLIC ROUTES
// ============================================================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString()
  });
});

// Get all books
app.get('/api/books', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM books ORDER BY title ASC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching books:', err);
    res.status(500).json({ error: 'Failed to fetch books' });
  }
});

// Get single book
app.get('/api/books/:isbn', async (req, res) => {
  try {
    const { isbn } = req.params;
    
    if (!isValidISBN(isbn)) {
      return res.status(400).json({ error: 'Invalid ISBN format' });
    }

    const result = await pool.query('SELECT * FROM books WHERE isbn = $1', [isbn]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Book not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching book:', err);
    res.status(500).json({ error: 'Failed to fetch book' });
  }
});

// Create order (with CSRF protection)
app.post('/api/orders', validateCsrfToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { customer_info, items, delivery_option, total } = req.body;
    
    // Validation
    if (!customer_info || !items || !delivery_option || !total) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!customer_info.name || !customer_info.email || !customer_info.address ||
        !customer_info.city || !customer_info.postalCode || !customer_info.country) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Incomplete customer information' });
    }

    if (!isValidEmail(customer_info.email)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid email address' });
    }

    if (!Array.isArray(items) || items.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Order must contain at least one item' });
    }

    // Sanitize inputs
    const sanitizedInfo = {
      name: sanitizeInput(customer_info.name),
      email: sanitizeInput(customer_info.email),
      address: sanitizeInput(customer_info.address),
      city: sanitizeInput(customer_info.city),
      postalCode: sanitizeInput(customer_info.postalCode),
      country: sanitizeInput(customer_info.country)
    };
    
    // Insert order
    const orderResult = await client.query(
      `INSERT INTO orders (
        customer_name, customer_email, customer_address, 
        customer_city, customer_postal_code, customer_country, 
        delivery_option, total, status
      ) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending') 
      RETURNING order_id`,
      [
        sanitizedInfo.name,
        sanitizedInfo.email,
        sanitizedInfo.address,
        sanitizedInfo.city,
        sanitizedInfo.postalCode,
        sanitizedInfo.country,
        delivery_option,
        total
      ]
    );
    
    const orderId = orderResult.rows[0].order_id;
    
    // Process items
    for (const item of items) {
      if (!item.isbn || !item.quantity || !item.price) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Invalid item data' });
      }

      // Check stock
      const bookCheck = await client.query(
        'SELECT stock FROM books WHERE isbn = $1',
        [item.isbn]
      );

      if (bookCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          error: `Book with ISBN ${item.isbn} not found` 
        });
      }

      if (bookCheck.rows[0].stock < item.quantity) {
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          error: `Insufficient stock for ISBN ${item.isbn}` 
        });
      }

      // Add to order_items
      await client.query(
        'INSERT INTO order_items (order_id, isbn, quantity, price) VALUES ($1, $2, $3, $4)',
        [orderId, item.isbn, item.quantity, item.price]
      );
      
      // Update stock
      await client.query(
        'UPDATE books SET stock = stock - $1 WHERE isbn = $2',
        [item.quantity, item.isbn]
      );
    }
    
    await client.query('COMMIT');
    
    res.status(201).json({ 
      orderId, 
      message: 'Order created successfully' 
    });
    
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error creating order:', err);
    res.status(500).json({ error: 'Failed to create order' });
  } finally {
    client.release();
  }
});

// Get all orders
app.get('/api/orders', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        o.*,
        json_agg(
          json_build_object(
            'isbn', oi.isbn,
            'quantity', oi.quantity,
            'price', oi.price,
            'title', b.title,
            'author', b.author
          )
        ) as items
      FROM orders o
      LEFT JOIN order_items oi ON o.order_id = oi.order_id
      LEFT JOIN books b ON oi.isbn = b.isbn
      GROUP BY o.order_id
      ORDER BY o.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching orders:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// ============================================================================
// ADMIN ROUTES
// ============================================================================

// Admin login - with rate limiting and JWT
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password required'
      });
    }

    // Fetch admin user from database
    const result = await pool.query(
      'SELECT id, username, password_hash FROM admin_users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      // Delay response to prevent username enumeration
      await new Promise(resolve => setTimeout(resolve, 1000));
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const user = result.rows[0];

    // Compare provided password with hashed password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      // Delay response to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, 1000));
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate JWT token (expires in 7 days)
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      expiresIn: '7d'
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

// Add book (protected route)
app.post('/api/books', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { isbn, title, author, description, price, stock, image_url, category } = req.body;
    
    if (!isbn || !title || !author || !price) {
      return res.status(400).json({ 
        error: 'ISBN, title, author, and price required' 
      });
    }

    if (!isValidISBN(isbn)) {
      return res.status(400).json({ error: 'Invalid ISBN format' });
    }

    if (isNaN(price) || price < 0) {
      return res.status(400).json({ error: 'Invalid price' });
    }

    const sanitized = {
      isbn: sanitizeInput(isbn),
      title: sanitizeInput(title),
      author: sanitizeInput(author),
      description: sanitizeInput(description || ''),
      price: parseFloat(price),
      stock: parseInt(stock) || 0,
      image_url: sanitizeInput(image_url || ''),
      category: sanitizeInput(category || '')
    };
    
    const result = await pool.query(
      `INSERT INTO books (isbn, title, author, description, price, stock, image_url, category)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [
        sanitized.isbn, sanitized.title, sanitized.author,
        sanitized.description, sanitized.price, sanitized.stock,
        sanitized.image_url, sanitized.category
      ]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error adding book:', err);
    if (err.code === '23505') {
      res.status(400).json({ error: 'Book with this ISBN already exists' });
    } else {
      res.status(500).json({ error: 'Failed to add book' });
    }
  }
});

// Update book (protected route)
app.put('/api/books/:isbn', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { isbn } = req.params;
    const { title, author, description, price, stock, image_url, category } = req.body;
    
    if (!title || !author || !price) {
      return res.status(400).json({ error: 'Title, author, and price required' });
    }

    if (isNaN(price) || price < 0) {
      return res.status(400).json({ error: 'Invalid price' });
    }

    const sanitized = {
      title: sanitizeInput(title),
      author: sanitizeInput(author),
      description: sanitizeInput(description || ''),
      price: parseFloat(price),
      stock: parseInt(stock) || 0,
      image_url: sanitizeInput(image_url || ''),
      category: sanitizeInput(category || '')
    };
    
    const result = await pool.query(
      `UPDATE books 
       SET title = $1, author = $2, description = $3, 
           price = $4, stock = $5, image_url = $6, category = $7
       WHERE isbn = $8 RETURNING *`,
      [
        sanitized.title, sanitized.author, sanitized.description,
        sanitized.price, sanitized.stock, sanitized.image_url,
        sanitized.category, isbn
      ]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Book not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating book:', err);
    res.status(500).json({ error: 'Failed to update book' });
  }
});

// Delete book (protected route)
app.delete('/api/books/:isbn', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { isbn } = req.params;
    
    const result = await pool.query(
      'DELETE FROM books WHERE isbn = $1 RETURNING *',
      [isbn]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Book not found' });
    }
    
    res.json({ message: 'Book deleted successfully' });
  } catch (err) {
    console.error('Error deleting book:', err);
    res.status(500).json({ error: 'Failed to delete book' });
  }
});

// Update order status (protected route)
app.patch('/api/orders/:orderId/status', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;

    const validStatuses = ['pending', 'processing', 'sent', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await pool.query(
      'UPDATE orders SET status = $1 WHERE order_id = $2 RETURNING *',
      [status, orderId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating order:', err);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// Upload book image (protected route)
app.post('/api/books/:isbn/images', authenticateToken, apiLimiter, upload.single('image'), async (req, res) => {
  try {
    const { isbn } = req.params;
    const { altText, isPrimary } = req.body;

    // Validate ISBN
    if (!isValidISBN(isbn)) {
      return res.status(400).json({ error: 'Invalid ISBN format' });
    }

    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    // Check if book exists
    const bookCheck = await pool.query(
      'SELECT isbn FROM books WHERE isbn = $1',
      [isbn]
    );

    if (bookCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Book not found' });
    }

    // Generate unique file name
    const timestamp = Date.now();
    const fileName = `book-images/${isbn}-${timestamp}-${req.file.originalname}`;

    // Upload to Scaleway
    const imageUrl = await uploadImage(
      req.file.buffer,
      fileName,
      req.file.mimetype
    );

    // Get current sort order for this ISBN
    const sortOrderResult = await pool.query(
      'SELECT MAX(sort_order) as max_order FROM book_images WHERE isbn = $1',
      [isbn]
    );
    const nextSortOrder = (sortOrderResult.rows[0]?.max_order || -1) + 1;

    // If setting as primary, unset all other primary images for this book
    const isPrimaryFlag = isPrimary === 'true' || isPrimary === true;
    if (isPrimaryFlag) {
      await pool.query(
        'UPDATE book_images SET is_primary = false WHERE isbn = $1',
        [isbn]
      );
    }

    // Insert image record into database
    const result = await pool.query(
      `INSERT INTO book_images (isbn, scaleway_url, alt_text, sort_order, is_primary)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [
        isbn,
        imageUrl,
        sanitizeInput(altText || ''),
        nextSortOrder,
        isPrimaryFlag
      ]
    );

    res.status(201).json({
      success: true,
      image: result.rows[0],
      message: 'Image uploaded successfully'
    });

  } catch (err) {
    console.error('Error uploading image:', err);
    res.status(500).json({
      error: 'Failed to upload image',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Get book images (public route)
app.get('/api/books/:isbn/images', async (req, res) => {
  try {
    const { isbn } = req.params;

    if (!isValidISBN(isbn)) {
      return res.status(400).json({ error: 'Invalid ISBN format' });
    }

    const result = await pool.query(
      'SELECT * FROM book_images WHERE isbn = $1 ORDER BY sort_order ASC',
      [isbn]
    );

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching images:', err);
    res.status(500).json({ error: 'Failed to fetch images' });
  }
});

// Delete book image (protected route)
app.delete('/api/books/:isbn/images/:imageId', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { isbn, imageId } = req.params;

    if (!isValidISBN(isbn)) {
      return res.status(400).json({ error: 'Invalid ISBN format' });
    }

    // Get image record to find Scaleway URL
    const imageResult = await pool.query(
      'SELECT scaleway_url FROM book_images WHERE id = $1 AND isbn = $2',
      [imageId, isbn]
    );

    if (imageResult.rows.length === 0) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const imageUrl = imageResult.rows[0].scaleway_url;

    // Delete from database
    await pool.query(
      'DELETE FROM book_images WHERE id = $1',
      [imageId]
    );

    // Delete from Scaleway (optional - if it fails, don't fail the whole request)
    try {
      const fileKey = extractKeyFromUrl(imageUrl);
      const { deleteImage } = require('./scaleway-storage');
      await deleteImage(fileKey);
    } catch (err) {
      console.warn('Warning: Could not delete image from Scaleway:', err.message);
    }

    res.json({
      success: true,
      message: 'Image deleted successfully'
    });
  } catch (err) {
    console.error('Error deleting image:', err);
    res.status(500).json({ error: 'Failed to delete image' });
  }
});

// ============================================================================
// SECURITY ENDPOINTS
// ============================================================================

// CSRF Token Endpoint - Generate and return a CSRF token
app.get('/api/csrf-token', (req, res) => {
  try {
    const crypto = require('crypto');
    // Generate a secure random CSRF token
    const token = crypto.randomBytes(32).toString('hex');

    // Store token in session (in production, use Redis or session middleware)
    // For now, we'll sign it with JWT and validate it on the order endpoint
    const signedToken = jwt.sign(
      { token, timestamp: Date.now() },
      JWT_SECRET,
      { expiresIn: '1h' } // CSRF token expires in 1 hour
    );

    res.json({
      success: true,
      token: signedToken
    });
  } catch (err) {
    console.error('Error generating CSRF token:', err);
    res.status(500).json({ error: 'Failed to generate CSRF token' });
  }
});

// Payment Info Endpoint - Return securely stored payment information
app.get('/api/payment-info', (req, res) => {
  try {
    // In production, retrieve this from environment variables or secure vault
    const paymentInfo = {
      bank: process.env.PAYMENT_BANK || 'National Trust Bank',
      accountName: process.env.PAYMENT_ACCOUNT_NAME || 'Ciengarnia Ltd.',
      accountNumber: process.env.PAYMENT_ACCOUNT_NUMBER || '1234-5678-9012-3456',
      swiftCode: process.env.PAYMENT_SWIFT_CODE || 'NTBKUS33'
    };

    res.json({
      success: true,
      ...paymentInfo
    });
  } catch (err) {
    console.error('Error fetching payment info:', err);
    res.status(500).json({ error: 'Failed to fetch payment information' });
  }
});

// ============================================================================
// ERROR HANDLERS
// ============================================================================

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 API: http://localhost:${PORT}/api`);
});

process.on('SIGTERM', () => {
  pool.end(() => {
    process.exit(0);
  });
});
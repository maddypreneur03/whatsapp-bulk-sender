const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors());
app.use(express.json());

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Helper function to get plan limits
function getPlanLimit(plan) {
  const limits = {
    'free': 50,
    'pro': 2000,
    'enterprise': 10000
  };
  return limits[plan] || 50;
}

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: error.message });
  }
});

// ============================================================================
// AUTH ENDPOINTS
// ============================================================================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const result = await pool.query(
      'INSERT INTO users (name, email, password, plan, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, name, email, plan',
      [name, email, hashedPassword, 'free']
    );
    
    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET);
    
    res.json({ token, user });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET);
    
    // Get user stats
    const statsQuery = await pool.query(`
      SELECT 
        COALESCE(SUM(c.sent_count), 0) as messages_sent,
        COUNT(c.id) as total_campaigns,
        COUNT(CASE WHEN c.status = 'running' THEN 1 END) as active_campaigns
      FROM campaigns c 
      WHERE c.user_id = $1
    `, [user.id]);
    
    const stats = statsQuery.rows[0];
    
    res.json({ 
      token, 
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        plan: user.plan,
        messagesUsed: parseInt(stats.messages_sent),
        messageLimit: getPlanLimit(user.plan),
        groupsConnected: 0
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ============================================================================
// CAMPAIGN ENDPOINTS
// ============================================================================

app.get('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        c.*,
        COUNT(ct.id) as target_count
      FROM campaigns c
      LEFT JOIN campaign_targets ct ON c.id = ct.campaign_id
      WHERE c.user_id = $1
      GROUP BY c.id
      ORDER BY c.created_at DESC
    `, [req.user.userId]);
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('Error fetching campaigns:', error);
    res.status(500).json({ error: 'Failed to fetch campaigns' });
  }
});

app.get('/api/campaigns/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get campaign details
    const campaignResult = await pool.query(`
      SELECT * FROM campaigns WHERE id = $1 AND user_id = $2
    `, [id, req.user.userId]);
    
    if (campaignResult.rows.length === 0) {
      return res.status(404).json({ error: 'Campaign not found' });
    }
    
    const campaign = campaignResult.rows[0];
    
    // Get targets
    const targetsResult = await pool.query(`
      SELECT * FROM campaign_targets WHERE campaign_id = $1
    `, [id]);
    
    campaign.targets = targetsResult.rows;
    
    res.json(campaign);
    
  } catch (error) {
    console.error('Error fetching campaign:', error);
    res.status(500).json({ error: 'Failed to fetch campaign' });
  }
});

app.post('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const { 
      name, 
      message, 
      targets, 
      settings, 
      scheduledAt 
    } = req.body;
    
    // Check plan limits
    const user = await pool.query('SELECT plan FROM users WHERE id = $1', [req.user.userId]);
    const planLimit = getPlanLimit(user.rows[0].plan);
    
    if (targets.length > planLimit) {
      return res.status(400).json({ 
        error: `Plan limit exceeded. Your plan allows ${planLimit} messages per campaign.` 
      });
    }
    
    // Create campaign
    const campaignResult = await pool.query(`
      INSERT INTO campaigns (
        user_id, name, message, settings, status, 
        scheduled_at, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
      RETURNING *
    `, [
      req.user.userId, 
      name, 
      message, 
      JSON.stringify(settings), 
      scheduledAt ? 'scheduled' : 'ready',
      scheduledAt
    ]);
    
    const campaign = campaignResult.rows[0];
    
    // Add targets
    for (const target of targets) {
      await pool.query(`
        INSERT INTO campaign_targets (campaign_id, name, number, type)
        VALUES ($1, $2, $3, $4)
      `, [campaign.id, target.name, target.number, target.type]);
    }
    
    res.json(campaign);
    
  } catch (error) {
    console.error('Error creating campaign:', error);
    res.status(500).json({ error: 'Failed to create campaign' });
  }
});

app.post('/api/campaigns/:id/progress', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { sent, failed, currentIndex, total } = req.body;
    
    // Update campaign progress
    await pool.query(`
      UPDATE campaigns 
      SET sent_count = $1, failed_count = $2, current_index = $3, 
          updated_at = NOW(), status = CASE WHEN $1 + $2 >= $4 THEN 'completed' ELSE status END
      WHERE id = $5 AND user_id = $6
    `, [sent, failed, currentIndex, total, id, req.user.userId]);
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Error updating progress:', error);
    res.status(500).json({ error: 'Failed to update progress' });
  }
});

// ============================================================================
// GROUPS & CONTACTS ENDPOINTS
// ============================================================================

app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM whatsapp_groups WHERE user_id = $1 ORDER BY name
    `, [req.user.userId]);
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('Error fetching groups:', error);
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

app.post('/api/sync-whatsapp-data', authenticateToken, async (req, res) => {
  try {
    const { groups, contacts } = req.body;
    
    // Clear existing data
    await pool.query('DELETE FROM whatsapp_groups WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM whatsapp_contacts WHERE user_id = $1', [req.user.userId]);
    
    // Insert groups
    for (const group of groups) {
      await pool.query(`
        INSERT INTO whatsapp_groups (user_id, name, member_count, category)
        VALUES ($1, $2, $3, $4)
      `, [req.user.userId, group.name, group.memberCount, group.category || 'General']);
    }
    
    // Insert contacts
    for (const contact of contacts) {
      await pool.query(`
        INSERT INTO whatsapp_contacts (user_id, name, number)
        VALUES ($1, $2, $3)
      `, [req.user.userId, contact.name, contact.number]);
    }
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Error syncing WhatsApp data:', error);
    res.status(500).json({ error: 'Failed to sync data' });
  }
});

// ============================================================================
// SUBSCRIPTION ENDPOINTS
// ============================================================================

app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const { planType } = req.body;
    
    const priceMap = {
      'pro': process.env.STRIPE_PRO_PRICE_ID,
      'enterprise': process.env.STRIPE_ENTERPRISE_PRICE_ID
    };
    
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price: priceMap[planType],
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL}/dashboard?success=true`,
      cancel_url: `${process.env.FRONTEND_URL}/settings?canceled=true`,
      client_reference_id: req.user.userId.toString(),
    });
    
    res.json({ url: session.url });
    
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

async function initializeDatabase() {
  try {
    // Create tables if they don't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        plan VARCHAR(50) DEFAULT 'free',
        stripe_customer_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        settings JSONB DEFAULT '{}',
        status VARCHAR(50) DEFAULT 'ready',
        sent_count INTEGER DEFAULT 0,
        failed_count INTEGER DEFAULT 0,
        current_index INTEGER DEFAULT 0,
        scheduled_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS campaign_targets (
        id SERIAL PRIMARY KEY,
        campaign_id INTEGER REFERENCES campaigns(id) ON DELETE CASCADE,
        name VARCHAR(255),
        number VARCHAR(50) NOT NULL,
        type VARCHAR(50) DEFAULT 'contact',
        status VARCHAR(50) DEFAULT 'pending',
        sent_at TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS whatsapp_groups (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        member_count INTEGER DEFAULT 0,
        category VARCHAR(100) DEFAULT 'General',
        last_synced TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS whatsapp_contacts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255),
        number VARCHAR(50) NOT NULL,
        last_synced TIMESTAMP DEFAULT NOW()
      )
    `);

    console.log('Database tables created successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Initialize database when server starts
initializeDatabase();

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`WhatsApp Bulk Sender API running on port ${PORT}`);
});

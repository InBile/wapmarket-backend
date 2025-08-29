import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

dotenv.config();
const { Pool } = pg;

// ======== ENV ========
// Railway sets PORT automatically. Set variables in Railway → Variables.
const PORT = Number(process.env.PORT || 8080);
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'change-me';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);

// ======== DB POOL ========
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE ? { rejectUnauthorized: false } : false,
});

// ======== MIGRATION ========
async function migrate(){
  const sql = `
  CREATE TABLE IF NOT EXISTS businesses (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    phone TEXT,
    location TEXT,
    business_type TEXT NOT NULL CHECK (business_type IN ('verified','unverified')) DEFAULT 'unverified',
    api_key_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    business_id INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    price_xaf INTEGER,
    image_url TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now()
  );

  CREATE INDEX IF NOT EXISTS idx_products_search
  ON products USING GIN (to_tsvector('spanish', coalesce(title,'') || ' ' || coalesce(description,'')));
  CREATE INDEX IF NOT EXISTS idx_products_category ON products (category);
  CREATE INDEX IF NOT EXISTS idx_products_active ON products (active);
  CREATE INDEX IF NOT EXISTS idx_businesses_type ON businesses (business_type);
  `;
  await pool.query(sql);
  console.log('DB migrate: OK');
}

// ======== APP ========
const app = express();
app.set('trust proxy', 1);

app.use(cors({
  origin: function(origin, cb){
    if (!origin) return cb(null, true);
    if (CORS_ORIGINS.length === 0 || CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'), false);
  }
}));
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use('/api/public', limiter);

// ======== HELPERS ========
function requireAdmin(req, res, next){
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token || token !== ADMIN_SECRET){
    return res.status(401).json({ error: 'No autorizado' });
  }
  next();
}

async function requireBusiness(req, res, next){
  try {
    const header = req.headers['authorization'] || '';
    const apiKey = header.startsWith('Bearer ') ? header.slice(7) : null;
    const id = Number(req.headers['x-business-id'] || 0);
    if (!apiKey) return res.status(401).json({ error: 'Falta API key' });
    if (!id) return res.status(400).json({ error: 'Falta X-Business-Id' });
    const { rows } = await pool.query('SELECT id, api_key_hash FROM businesses WHERE id=$1', [id]);
    if (!rows.length || !rows[0].api_key_hash) return res.status(401).json({ error: 'Negocio no autorizado' });
    const ok = await bcrypt.compare(apiKey, rows[0].api_key_hash);
    if (!ok) return res.status(401).json({ error: 'API key inválida' });
    req.businessId = id;
    next();
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
}

function visibilityOrder(){
  return `
    (CASE b.business_type WHEN 'verified' THEN 2 ELSE 1 END) DESC,
    p.created_at DESC
  `;
}

// ======== ROUTES ========
app.get('/health', (req, res)=> res.json({ ok: true }));

// Admin
app.post('/api/admin/businesses', requireAdmin, async (req, res)=>{
  try {
    const { name, email, phone, location, business_type } = req.body;
    if(!name) return res.status(400).json({ error: 'Nombre requerido' });
    const type = business_type === 'verified' ? 'verified' : 'unverified';
    const { rows } = await pool.query(
      `INSERT INTO businesses(name, email, phone, location, business_type)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, name, email, phone, location, business_type, created_at`,
      [name, email||null, phone||null, location||null, type]
    );
    res.json({ business: rows[0] });
  } catch(e){
    if (String(e).includes('duplicate key')) {
      res.status(409).json({ error: 'Email ya existe' });
    } else {
      console.error(e);
      res.status(500).json({ error: 'Error del servidor' });
    }
  }
});

app.get('/api/admin/businesses', requireAdmin, async (req, res)=>{
  try {
    const { rows } = await pool.query('SELECT id, name, email, phone, location, business_type, created_at FROM businesses ORDER BY created_at DESC LIMIT 500');
    res.json({ items: rows });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/admin/businesses/:id/issue-key', requireAdmin, async (req, res)=>{
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'ID inválido' });
    const apiKey = crypto.randomBytes(24).toString('hex');
    const hash = await bcrypt.hash(apiKey, 10);
    const { rows } = await pool.query(
      'UPDATE businesses SET api_key_hash=$1 WHERE id=$2 RETURNING id, name, business_type',
      [hash, id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Negocio no encontrado' });
    res.json({ api_key: apiKey, business: rows[0] }); // mostrar una vez
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Business product management
app.post('/api/products', requireBusiness, async (req, res)=>{
  try {
    const { title, description, category, price_xaf, image_url, active } = req.body;
    if (!title) return res.status(400).json({ error: 'Título requerido' });
    const { rows } = await pool.query(
      `INSERT INTO products(business_id, title, description, category, price_xaf, image_url, active)
       VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7, TRUE))
       RETURNING *`,
      [req.businessId, title, description||null, category||null, price_xaf||null, image_url||null, active]
    );
    res.json({ product: rows[0] });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.put('/api/products/:id', requireBusiness, async (req, res)=>{
  try {
    const id = Number(req.params.id);
    const fields = ['title','description','category','price_xaf','image_url','active'];
    const updates = [];
    const values = [];
    let idx = 1;
    for (const f of fields){
      if (f in req.body){
        updates.push(f + '=$' + idx);
        values.push(req.body[f]);
        idx++;
      }
    }
    if (!updates.length) return res.status(400).json({ error: 'Nada para actualizar' });
    values.push(req.businessId); idx++; values.push(id);
    const sql = `UPDATE products SET ${updates.join(',')} WHERE business_id=$${idx-1} AND id=$${idx} RETURNING *`;
    const { rows } = await pool.query(sql, values);
    if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json({ product: rows[0] });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.delete('/api/products/:id', requireBusiness, async (req, res)=>{
  try {
    const id = Number(req.params.id);
    const { rowCount } = await pool.query('DELETE FROM products WHERE business_id=$1 AND id=$2', [req.businessId, id]);
    if (!rowCount) return res.status(404).json({ error: 'No encontrado' });
    res.json({ ok: true });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Public search (no auth)
app.get('/api/public/products', async (req, res)=>{
  try {
    const q = String(req.query.q || '').trim();
    const category = String(req.query.category || '').trim();
    const location = String(req.query.location || '').trim();
    const limit = Math.max(1, Math.min(50, Number(req.query.limit || 24)));
    const offset = Math.max(0, Number(req.query.offset || 0));

    const params = [];
    let where = 'p.active = TRUE';
    if (q) { params.push(q); where += ` AND to_tsvector('spanish', coalesce(p.title,'') || ' ' || coalesce(p.description,'')) @@ plainto_tsquery('spanish', $${params.length})`; }
    if (category) { params.push(category); where += ` AND p.category = $${params.length}`; }
    if (location) { params.push(location); where += ` AND b.location = $${params.length}`; }

    params.push(limit); params.push(offset);
    const sql = `
      SELECT p.*, b.name as business_name, b.phone, b.email, b.location, b.business_type
      FROM products p
      JOIN businesses b ON b.id = p.business_id
      WHERE ${where}
      ORDER BY ${visibilityOrder()}
      LIMIT $${params.length-1} OFFSET $${params.length}
    `;
    const { rows } = await pool.query(sql, params);
    res.json({ items: rows, limit, offset });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ======== START ========
migrate()
  .then(()=> app.listen(PORT, ()=> console.log('wapmarket backend on :' + PORT)))
  .catch((e)=>{
    console.error('Migration failed', e);
    process.exit(1);
  });

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
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { Pool } = pg;

const PORT = Number(process.env.PORT || 8080);
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'change-me';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || ''; // ej: https://tu-backend.up.railway.app
const DELIVERY_FEE_XAF = Number(process.env.DELIVERY_FEE_XAF || 2000);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE ? { rejectUnauthorized: false } : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false),
});

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

  CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    group_id TEXT,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    business_id INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    qty INTEGER NOT NULL DEFAULT 1 CHECK (qty > 0),
    customer_name TEXT,
    customer_phone TEXT,
    address TEXT,
    note TEXT,
    delivery BOOLEAN DEFAULT FALSE,
    delivery_fee_xaf INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','accepted','rejected','fulfilled')),
    created_at TIMESTAMPTZ DEFAULT now()
  );

  CREATE INDEX IF NOT EXISTS idx_products_search
  ON products USING GIN (to_tsvector('spanish', coalesce(title,'') || ' ' || coalesce(description,'')));
  CREATE INDEX IF NOT EXISTS idx_products_category ON products (category);
  CREATE INDEX IF NOT EXISTS idx_products_active ON products (active);
  CREATE INDEX IF NOT EXISTS idx_businesses_type ON businesses (business_type);
  CREATE INDEX IF NOT EXISTS idx_orders_business ON orders (business_id, status, created_at DESC);
  `;
  await pool.query(sql);
  console.log('DB migrate: OK');
}

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
app.use(express.json({ limit: '2mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 180 });
app.use('/api/public', limiter);

// static for uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

// Multer storage
const storage = multer.diskStorage({
  destination: (req,file,cb)=> cb(null, uploadDir),
  filename: (req,file,cb)=>{
    const ext = path.extname(file.originalname || '').toLowerCase();
    const name = crypto.randomBytes(10).toString('hex') + ext;
    cb(null, name);
  }
});
const upload = multer({ storage, limits: { fileSize: 6 * 1024 * 1024 } }); // 6MB

function absoluteUrl(req, filename){
  const base = PUBLIC_BASE_URL || (req.protocol + '://' + req.get('host'));
  return `${base}/uploads/${filename}`;
}

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

app.get('/health', (req, res)=> res.json({ ok: true, delivery_fee_xaf: DELIVERY_FEE_XAF }));

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
    res.json({ api_key: apiKey, business: rows[0] });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Image upload (business)
app.post('/api/business/upload-image', requireBusiness, upload.single('image'), async (req, res)=>{
  try {
    if (!req.file) return res.status(400).json({ error: 'Falta imagen' });
    const url = absoluteUrl(req, req.file.filename);
    res.json({ url });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error subiendo imagen' });
  }
});

// Product management
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

// Public search & single order
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

app.post('/api/public/orders', async (req, res)=>{
  try {
    const { product_id, qty, customer_name, customer_phone, address, note, delivery } = req.body;
    if (!product_id || !qty || !customer_phone) return res.status(400).json({ error: 'Campos requeridos: product_id, qty, customer_phone' });
    const { rows: pRows } = await pool.query('SELECT id, business_id, price_xaf FROM products WHERE id=$1 AND active=TRUE', [product_id]);
    if (!pRows.length) return res.status(404).json({ error: 'Producto no encontrado' });
    const bizId = pRows[0].business_id;
    const fee = delivery ? DELIVERY_FEE_XAF : 0;
    const { rows } = await pool.query(
      `INSERT INTO orders(group_id, product_id, business_id, qty, customer_name, customer_phone, address, note, delivery, delivery_fee_xaf, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'new')
       RETURNING *`,
      [crypto.randomUUID(), product_id, bizId, Math.max(1, Number(qty)), customer_name||null, customer_phone, address||null, note||null, !!delivery, fee]
    );
    res.json({ order: rows[0], delivery_fee_xaf: fee });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error creando pedido' });
  }
});

// Cart checkout (multiple items)
app.post('/api/public/cart/checkout', async (req, res)=>{
  try {
    const { items, customer_name, customer_phone, address, note, delivery } = req.body || {};
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Carrito vacío' });
    if (!customer_phone) return res.status(400).json({ error: 'Falta teléfono' });
    const groupId = crypto.randomUUID();
    const fee = delivery ? DELIVERY_FEE_XAF : 0;

    // Fetch product info
    const ids = items.map(i => Number(i.product_id)).filter(Boolean);
    const { rows: products } = await pool.query(`SELECT id, business_id, price_xaf FROM products WHERE id = ANY($1::int[]) AND active=TRUE`, [ids]);
    const map = new Map(products.map(p => [p.id, p]));

    const created = [];
    for (const it of items){
      const p = map.get(Number(it.product_id));
      if (!p) continue;
      const qty = Math.max(1, Number(it.qty || 1));
      const { rows } = await pool.query(
        `INSERT INTO orders(group_id, product_id, business_id, qty, customer_name, customer_phone, address, note, delivery, delivery_fee_xaf, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'new') RETURNING *`,
        [groupId, p.id, p.business_id, qty, customer_name||null, customer_phone, address||null, note||null, !!delivery, fee]
      );
      created.push(rows[0]);
    }
    if (!created.length) return res.status(400).json({ error: 'Los productos ya no están disponibles' });

    // Totals
    let subTotal = 0;
    for (const o of created){
      const prod = map.get(o.product_id);
      const price = Number(prod?.price_xaf || 0);
      subTotal += price * Number(o.qty);
    }
    const total = subTotal + fee;

    res.json({ group_id: groupId, orders: created, subtotal_xaf: subTotal, delivery_fee_xaf: fee, total_xaf: total });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error en checkout' });
  }
});

// Business order management
app.get('/api/business/orders', requireBusiness, async (req, res)=>{
  try {
    const { rows } = await pool.query(
      `SELECT o.*, p.title, p.price_xaf FROM orders o
       JOIN products p ON p.id = o.product_id
       WHERE o.business_id=$1
       ORDER BY o.created_at DESC
       LIMIT 300`, [req.businessId]);
    res.json({ items: rows, delivery_fee_xaf: DELIVERY_FEE_XAF });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error' });
  }
});

app.put('/api/business/orders/:id', requireBusiness, async (req, res)=>{
  try {
    const id = Number(req.params.id);
    const { status } = req.body;
    const allowed = ['new','accepted','rejected','fulfilled'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Estado inválido' });
    const { rows } = await pool.query(
      `UPDATE orders SET status=$1 WHERE id=$2 AND business_id=$3 RETURNING *`,
      [status, id, req.businessId]
    );
    if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json({ order: rows[0] });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error' });
  }
});

migrate()
  .then(()=> app.listen(PORT, ()=> console.log('wapmarket backend on :' + PORT)))
  .catch((e)=>{ console.error('Migration failed', e); process.exit(1); });

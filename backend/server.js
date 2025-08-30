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
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from "node-fetch";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.error('❌ Falta DATABASE_URL en variables de entorno');
  process.exit(1);
}

const PORT = Number(process.env.PORT || 8080);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@wapmarket.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || '';
const DELIVERY_FEE_XAF = Number(process.env.DELIVERY_FEE_XAF || 2000);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE 
    ? { rejectUnauthorized: false } 
    : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false),
});

// 👉 Configuración de multer
const upload = multer();

// 👉 Ruta para subir imágenes a ImgBB
// Se usa en productos o negocios para guardar la URL
const app = express();
app.post("/api/upload", upload.single("image"), async (req, res) => {
  try {
    const apiKey = process.env.IMGBB_KEY; // agrega tu API key en Railway
    if (!apiKey) return res.status(500).json({ error: "Falta IMGBB_KEY en variables de entorno" });

    const imageBuffer = req.file.buffer.toString("base64");

    const response = await fetch(`https://api.imgbb.com/1/upload?key=${apiKey}`, {
      method: "POST",
      body: new URLSearchParams({ image: imageBuffer }),
    });

    const result = await response.json();
    if (!result.success) return res.status(400).json({ error: "Error subiendo a ImgBB" });

    // Devuelve la URL que puedes guardar en products.image_url o businesses.logo_url
    res.json({ url: result.data.url });
  } catch (err) {
    console.error("❌ Error en subida ImgBB:", err);
    res.status(500).json({ error: "Fallo en la subida" });
  }
});

export default router;


dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.error('❌ Falta DATABASE_URL en variables de entorno');
  process.exit(1);
}

const PORT = Number(process.env.PORT || 8080);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@wapmarket.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || '';
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
    login_email TEXT UNIQUE,
    password_hash TEXT,
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
  console.log('✅ DB migrate: OK');
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

// Static uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

const storage = multer.diskStorage({
  destination: (req,file,cb)=> cb(null, uploadDir),
  filename: (req,file,cb)=>{
    const ext = path.extname(file.originalname || '').toLowerCase();
    const name = crypto.randomBytes(10).toString('hex') + ext;
    cb(null, name);
  }
});
const upload = multer({ storage, limits: { fileSize: 6 * 1024 * 1024 } });

function absoluteUrl(req, filename){
  const base = PUBLIC_BASE_URL || (req.protocol + '://' + req.get('host'));
  return `${base}/uploads/${filename}`;
}

// ---- AUTH HELPERS ----
function signToken(payload){
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
function requireAdmin(req, res, next){
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
    const data = jwt.verify(token, JWT_SECRET);
    if (!data || data.role !== 'admin') return res.status(401).json({ error: 'No autorizado' });
    req.admin = { email: data.email };
    next();
  } catch(e){ return res.status(401).json({ error: 'No autorizado' }); }
}
function requireBusiness(req, res, next){
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
    const data = jwt.verify(token, JWT_SECRET);
    if (!data || data.role !== 'business') return res.status(401).json({ error: 'No autorizado' });
    req.businessId = Number(data.business_id);
    next();
  } catch(e){ return res.status(401).json({ error: 'No autorizado' }); }
}

app.get('/health', (req, res)=> res.json({ ok: true, delivery_fee_xaf: DELIVERY_FEE_XAF }));

// ---- ADMIN AUTH ----
app.post('/api/admin/login', (req, res)=>{
  const { email, password } = req.body || {};
  if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD){
    return res.json({ token: signToken({ role:'admin', email }) });
  }
  res.status(401).json({ error: 'Credenciales inválidas' });
});

// ---- BUSINESS AUTH ----
app.post('/api/business/login', async (req, res)=>{
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Faltan credenciales' });
    const { rows } = await pool.query('SELECT id, login_email, password_hash FROM businesses WHERE login_email=$1', [email]);
    if (!rows.length || !rows[0].password_hash) return res.status(401).json({ error: 'Credenciales inválidas' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });
    const token = signToken({ role:'business', business_id: rows[0].id, email });
    res.json({ token, business_id: rows[0].id });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ---- ADMIN: Businesses CRUD ----
app.post('/api/admin/businesses', requireAdmin, async (req, res)=>{
  try {
    const { name, email, phone, location, login_email, password } = req.body;
    let { business_type } = req.body;

    if (!name) return res.status(400).json({ error: 'Nombre requerido' });
    if (!login_email || !password) return res.status(400).json({ error: 'Login y contraseña requeridos' });

    // Normalizamos tipo
    if (business_type !== 'verified') business_type = 'unverified';

    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO businesses(name, email, phone, location, business_type, login_email, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, name, email, phone, location, business_type, login_email, created_at`,
      [name, email || null, phone || null, location || null, business_type, login_email, hash]
    );
    res.json({ business: rows[0] });
  } catch (e) {
    if (String(e).includes('duplicate key')) {
      res.status(409).json({ error: 'Email o login_email ya existe' });
    } else {
      console.error('❌ Error creando negocio:', e);
      res.status(500).json({ error: 'Error del servidor' });
    }
  }
});

app.get('/api/admin/businesses', requireAdmin, async (req, res)=>{
  try {
    const { rows } = await pool.query(
      'SELECT id, name, email, phone, location, business_type, login_email, created_at FROM businesses ORDER BY created_at DESC LIMIT 500'
    );
    res.json({ items: rows });
  } catch (e) {
    console.error('❌ Error listando negocios:', e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.put('/api/admin/businesses/:id', requireAdmin, async (req, res)=>{
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'ID inválido' });

    const fields = ['name','email','phone','location','business_type','login_email'];
    const updates = [];
    const values = [];
    let idx = 1;

    for (const f of fields){
      if (f in req.body){
        if (f === 'business_type' && req.body[f] !== 'verified') {
          // normalizamos
          req.body[f] = 'unverified';
        }
        updates.push(`${f}=$${idx}`);
        values.push(req.body[f]);
        idx++;
      }
    }
    if ('password' in req.body && req.body.password){
      updates.push(`password_hash=$${idx}`);
      values.push(await bcrypt.hash(req.body.password, 10));
      idx++;
    }
    if (!updates.length) return res.status(400).json({ error: 'Nada para actualizar' });

    values.push(id);
    const sql = `UPDATE businesses SET ${updates.join(',')} WHERE id=$${idx} RETURNING id,name,login_email,business_type`;
    const { rows } = await pool.query(sql, values);
    if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json({ business: rows[0] });
  } catch (e) {
    console.error('❌ Error actualizando negocio:', e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ---- PUBLIC: list businesses & products ----
app.get('/api/public/businesses', async (req, res)=>{
  try {
    const { rows } = await pool.query(
      `SELECT id, name, location, phone, business_type
       FROM businesses
       ORDER BY (CASE business_type WHEN 'verified' THEN 2 ELSE 1 END) DESC, created_at DESC`
    );
    res.json({ items: rows });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
});

app.get('/api/public/products', async (req, res)=>{
  try {
    const q = String(req.query.q || '').trim();
    const category = String(req.query.category || '').trim();
    const business_id = Number(req.query.business_id || 0);
    const limit = Math.max(1, Math.min(50, Number(req.query.limit || 24)));
    const offset = Math.max(0, Number(req.query.offset || 0));

    const params = [];
    let where = 'p.active = TRUE';
    if (business_id){ params.push(business_id); where += ` AND p.business_id = $${params.length}`; }
    if (q) { params.push(q); where += ` AND to_tsvector('spanish', coalesce(p.title,'') || ' ' || coalesce(p.description,'')) @@ plainto_tsquery('spanish', $${params.length})`; }
    if (category) { params.push(category); where += ` AND p.category = $${params.length}`; }

    params.push(limit); params.push(offset);
    const sql = `
      SELECT p.*, b.name as business_name, b.phone, b.location, b.business_type
      FROM products p
      JOIN businesses b ON b.id = p.business_id
      WHERE ${where}
      ORDER BY p.created_at DESC
      LIMIT $${params.length-1} OFFSET $${params.length}
    `;
    const { rows } = await pool.query(sql, params);
    res.json({ items: rows, limit, offset });
  } catch(e){
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ---- BUSINESS: uploads & products ----
app.post('/api/business/upload-image', requireBusiness, upload.single('image'), async (req, res)=>{
  try {
    if (!req.file) return res.status(400).json({ error: 'Falta imagen' });
    const url = absoluteUrl(req, req.file.filename);
    res.json({ url });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Error subiendo imagen' }); }
});

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
  } catch(e){ console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
});

// ---- PUBLIC: orders + cart (single business) ----
app.post('/api/public/cart/checkout', async (req, res)=>{
  try {
    const { items, customer_name, customer_phone, address, note, delivery } = req.body || {};
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Carrito vacío' });
    if (!customer_phone) return res.status(400).json({ error: 'Falta teléfono' });

    const ids = items.map(i => Number(i.product_id)).filter(Boolean);
    const { rows: products } = await pool.query(
      `SELECT id, business_id, price_xaf FROM products WHERE id = ANY($1::int[]) AND active=TRUE`,
      [ids]
    );
    if (!products.length) return res.status(400).json({ error: 'Productos no válidos' });
    const bizId = products[0].business_id;
    if (products.some(p => p.business_id !== bizId)) {
      return res.status(400).json({ error: 'Solo puedes comprar productos de un negocio a la vez' });
    }

    const groupId = crypto.randomUUID();
    const fee = delivery ? DELIVERY_FEE_XAF : 0;
    const created = [];

    for (const it of items){
      const p = products.find(x => x.id === Number(it.product_id));
      if (!p) continue;
      const qty = Math.max(1, Number(it.qty || 1));
      const { rows } = await pool.query(
        `INSERT INTO orders(group_id, product_id, business_id, qty, customer_name, customer_phone, address, note, delivery, delivery_fee_xaf, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'new') RETURNING *`,
        [groupId, p.id, bizId, qty, customer_name||null, customer_phone, address||null, note||null, !!delivery, fee]
      );
      created.push(rows[0]);
    }
    if (!created.length) return res.status(400).json({ error: 'No se pudo crear el pedido' });

    let subTotal = 0;
    for (const o of created){
      const prod = products.find(pp=>pp.id===o.product_id);
      subTotal += Number(prod?.price_xaf||0) * Number(o.qty||1);
    }
    const total = subTotal + fee;
    res.json({ group_id: groupId, orders: created, subtotal_xaf: subTotal, delivery_fee_xaf: fee, total_xaf: total, business_id: bizId });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Error en checkout' }); }
});

// ---- BUSINESS: orders ----
app.get('/api/business/orders', requireBusiness, async (req, res)=>{
  try {
    const { rows } = await pool.query(
      `SELECT o.*, p.title, p.price_xaf FROM orders o
       JOIN products p ON p.id = o.product_id
       WHERE o.business_id=$1
       ORDER BY o.created_at DESC LIMIT 300`, [req.businessId]);
    res.json({ items: rows, delivery_fee_xaf: DELIVERY_FEE_XAF });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Error' }); }
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
  } catch(e){ console.error(e); res.status(500).json({ error: 'Error' }); }
});

// --- 404 JSON para /api ---
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});

// --- Manejador global de errores ---
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ error: 'Error del servidor' });
});

migrate()
  .then(()=> app.listen(PORT, ()=> console.log('🚀 wapmarket backend on :' + PORT)))
  .catch((e)=>{ console.error('Migration failed', e); process.exit(1); });

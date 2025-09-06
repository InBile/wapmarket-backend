<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Vendedor — WapMarket</title>
  <link rel="stylesheet" href="/styles.css">

<style>
:root{
  --amz-dark:#131921;
  --amz-light:#232f3e;
  --amz-yellow:#febd69;
  --amz-border:#e6e6e6;
  --link:#007185;
}
*{box-sizing:border-box}
body{margin:0;background:#eaeded;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#111}
.header{position:sticky;top:0;z-index:50;background:var(--amz-dark);padding:10px 0}
.wrapper{max-width:1200px;margin:0 auto;padding:0 16px}
.row{display:flex;align-items:center;gap:12px}
.logo{color:#fff;font-weight:800;letter-spacing:.2px}
.logout-btn{background:transparent;border:1px solid rgba(255,255,255,.25);color:#fff}
.logout-btn:hover{background:rgba(255,255,255,.08)}
/* Business identity */
.biz-head{color:#fff;margin-left:auto;display:flex;align-items:center;gap:8px}
.biz-badge{display:inline-flex;align-items:center;gap:6px;color:#fff;font-weight:700}
.biz-badge .v{width:18px;height:18px;border-radius:50%;background:#12b886;display:inline-flex;align-items:center;justify-content:center;font-size:12px;color:#fff}

/* Cards */
.card{background:#fff;border:1px solid var(--amz-border);border-radius:0;box-shadow:none;margin:16px 0}
h3{margin:0 0 12px}
label{display:block;margin:10px 0;font-weight:600}
input,select,textarea{width:100%;height:40px;padding:8px;border:1px solid var(--amz-border);border-radius:4px;background:#fff}
textarea{height:88px;resize:vertical}
.btn{height:38px;border-radius:20px;padding:0 16px;border:1px solid #d5d9d9;background:var(--amz-yellow);font-weight:700;color:#111;cursor:pointer}
.btn.ghost{background:#fff;border:1px solid var(--amz-border);}
.btn.danger{background:#fff;border:1px solid #b12704;color:#b12704}
.btn.small{height:30px;border-radius:14px;padding:0 10px;font-size:.9rem}

/* Tables */
.table{width:100%;border-collapse:collapse}
.table th,.table td{border-bottom:1px solid var(--amz-border);padding:10px;vertical-align:middle;text-align:left;background:#fff}
.table th{background:#f8f8f8}
.table img{border-radius:4px}
.table-actions{display:flex;gap:8px;flex-wrap:wrap}

/* Responsive: make tables scroll on small screens */
.table-wrap{overflow:auto}
@media (max-width: 900px){
  .row.wrap{flex-wrap:wrap}
  .biz-head{order:3;width:100%;justify-content:flex-start;margin:6px 0 0}
}
@media (max-width: 640px){
  .wrapper{padding:0 10px}
  .table th,.table td{padding:8px}
}
</style>

</head>
<body>
<header class="header">
  <div class="row wrapper">
    <div class="logo">WapMarket</div><div class="biz-head"><span id="bizName">Mi negocio</span><span id="bizVerified" class="biz-badge" style="display:none"><span class="v">✓</span> Verificado</span></div><button id="logoutBtn" class="btn logout-btn">Cerrar sesión</button>
  </div>
</header>

<main class="wrapper">
  <!-- Login -->
  <div class="card" style="padding:16px;max-width:800px" id="loginBox">
    <h3>Login de Negocio</h3>
    <form onsubmit="return false;">
      <label>Email <input id="lemail" type="email" required></label>
      <label>Contraseña <input id="lpass" type="password" required></label>
      <button class="btn" id="btnLogin">Entrar</button>
    </form>
  </div>

  <!-- Panel negocio -->
  <div id="panel" style="display:none">
    <!-- Publicar producto -->
    <div class="card" style="padding:16px;max-width:800px">
      <h3>Publicar producto</h3>
      <form id="prodForm" onsubmit="return false;">
        <label>Título <input id="title" required></label>
        <label>Descripción <textarea id="description"></textarea></label>
        <label>Categoría
          <select id="category">
            <option>Servicios</option><option>Comida</option><option>Tiendas</option>
            <option>Salud</option><option>Transporte</option><option>Tecnología</option>
          </select>
        </label>
        <label>Precio (XAF) <input id="price" type="number" min="0"></label>
        <label>Imagen (archivo) <input id="image" type="file" accept="image/*"></label>
        <button class="btn" id="btnPublicar">Publicar</button>
      </form>
    </div>

    <!-- Pedidos -->
    <div class="card" style="padding:16px;max-width:1100px">
      <h3>Pedidos</h3>
      <div class="table-wrap"><table class="table" id="ordersTable">
        <thead><tr><th>ID</th><th>Grupo</th><th>Producto</th><th>Precio</th><th>Cant.</th>
        <th>Cliente</th><th>Teléfono</th><th>Envío</th><th>Dirección</th><th>Estado</th><th>Acciones</th></tr></thead>
        <tbody></tbody>
      </table></div>
    </div>

    <!-- Productos -->
    <div class="card" style="padding:16px;max-width:1100px">
      <h3>Mis Productos</h3>
      <div class="table-wrap"><table class="table" id="productsTable">
        <thead>
          <tr>
            <th>ID</th><th>Título</th><th>Categoría</th><th>Precio</th><th>Imagen</th><th>Creado</th><th>Acciones</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table></div>
    </div>
  </div>
</main>

<script src="/api.js"></script>
<script>

// API DELETE polyfill si no existe
if (!API.delete){
  API.delete = function(url, opts){ opts = opts||{}; opts.method='DELETE'; return API.request(url, null, opts); };
}

let token = null; 
let business_id = null;
function authHeaders(){ return token ? { 'Authorization':'Bearer '+token } : {}; }


// ============= PERFIL DEL NEGOCIO (nombre e insignia) =============
async function loadProfile(){
  try{
    let me = await API.get('/business/me', { headers: authHeaders() });
    if (me && me.name){ document.getElementById('bizName').textContent = me.name; }
    if (me && (me.verified || me.is_verified)){ document.getElementById('bizVerified').style.display='inline-flex'; }
    if (me && me.info){ document.getElementById('bizName').title = me.info; }
  }catch(e){
    // fallback silencioso si el endpoint no existe
    console.warn('No se pudo cargar el perfil del negocio', e);
  }
}

// ============= UTIL: mapa de pedidos para acciones rápidas =============
const ordersMap = {};

// ============= ENVIAR WHATSAPP AL CLIENTE =============
function sendWhatsAppForOrder(order, newStatus){
  try{
    if(!order) return;
    const phone = String(order.customer_phone||'').replace(/[^0-9]/g,'');
    if(!phone) return;
    const delivery = order.delivery ? `Sí (+${Number(order.delivery_fee_xaf||0).toLocaleString()} XAF)` : 'No';
    const total = (Number(order.price_xaf||0) * Number(order.qty||1)) + Number(order.delivery ? (order.delivery_fee_xaf||0):0);
    const text = [
      'WapMarket — Confirmación de pedido',
      `Negocio: ${document.getElementById('bizName').textContent}`,
      `Pedido #${order.id} (grupo ${order.group_id||'-'})`,
      `Producto: ${order.title}`,
      `Cantidad: ${order.qty}`,
      `Envío: ${delivery}`,
      `Total: ${total.toLocaleString()} XAF`,
      `Estado: ${newStatus}`,
      '',
      'Gracias por su compra.'
    ].join('\n');
    const url = `https://wa.me/${phone}?text=${encodeURIComponent(text)}`;
    window.open(url, '_blank');
  }catch(err){ console.warn('WhatsApp falló', err); }
}

// ================== LOGIN ==================
document.getElementById('btnLogin').addEventListener('click', async ()=>{
  const res = await API.post('/business/login', { email: lemail.value, password: lpass.value });
  if (res.error){ alert(res.error); return; }
  token = res.token; business_id = res.business_id;
  localStorage.setItem('bizToken', token);
  localStorage.setItem('bizId', String(business_id));
  document.getElementById('loginBox').style.display='none';
  document.getElementById('panel').style.display='block';
  loadOrders();
  loadProducts(); // ✅ cargar productos al entrar
  loadProfile();
});

// Autologin si ya hay token guardado
token = localStorage.getItem('bizToken'); 
business_id = Number(localStorage.getItem('bizId')||0);
if (token && business_id){ 
  document.getElementById('loginBox').style.display='none'; 
  document.getElementById('panel').style.display='block'; 
  loadOrders(); 
  loadProducts(); // ✅ también aquí
  loadProfile();
}

// ================== PUBLICAR PRODUCTO ==================
document.getElementById('btnPublicar').addEventListener('click', async ()=>{
  if (!token) return alert('Primero inicia sesión');
  let imageUrl = '';
  const file = document.getElementById('image').files[0];
  if (file){
    const fd = new FormData(); 
    fd.append('image', file);
    const up = await API.upload('/business/upload-image', fd, { headers: authHeaders() });
    if (up.error) return alert(up.error);
    imageUrl = up.url;
  }
  const payload = {
    title: title.value, 
    description: description.value, 
    category: category.value,
    price_xaf: Number(price.value || 0), 
    image_url: imageUrl
  };
  const res = await API.post('/business/products', payload, { headers: authHeaders() });
  if (res.error){ alert(res.error); return; }
  alert('Producto publicado');
  document.getElementById('prodForm').reset();
  loadProducts(); // ✅ refrescar lista tras publicar
});

// ================== CARGAR PEDIDOS ==================
async function loadOrders(){
  if (!token) return;
  const data = await API.get('/business/orders', { headers: authHeaders() });
  const tb = document.querySelector('#ordersTable tbody'); 
  tb.innerHTML='';
  
(data.items||[]).forEach(o=>{
  const tr = document.createElement('tr');
  const deliveryTxt = o.delivery ? ('Sí (+'+Number(o.delivery_fee_xaf||0).toLocaleString()+' XAF)') : 'No';
  tr.innerHTML = `<td>${o.id}</td><td>${o.group_id||''}</td><td>${o.title}</td><td>${Number(o.price_xaf||0).toLocaleString()} XAF</td><td>${o.qty}</td>
                  <td>${o.customer_name||''}</td><td>${o.customer_phone||''}</td><td>${deliveryTxt}</td><td>${o.address||''}</td>
                  <td><span class="small">${o.status}</span></td>
                  <td class="table-actions">
                    <button class="btn small" data-id="${o.id}" data-s="accepted">Aceptar</button>
                    <button class="btn small ghost" data-id="${o.id}" data-s="rejected">Rechazar</button>
                    <button class="btn small" data-id="${o.id}" data-s="fulfilled">Entregado</button>
                  </td>`;
  tb.appendChild(tr);
  ordersMap[o.id] = o;
});

  tb.onclick = async (e)=>{
    const btn = e.target.closest('button.btn'); if (!btn) return;
    const id = btn.getAttribute('data-id'); 
    const s = btn.getAttribute('data-s');
    const r = await API.put('/business/orders/'+id, { status:s }, { headers: authHeaders() });
    if (r.error) return alert(r.error);
    try{ sendWhatsAppForOrder(ordersMap[id], s); }catch(_){}
    loadOrders();
  };
}

// ================== CARGAR PRODUCTOS ==================
async function loadProducts(){
  if (!token) return;
  const data = await API.get('/business/products', { headers: authHeaders() });
  console.log("Productos del negocio:", data); // 🔎 debug
  const tb = document.querySelector('#productsTable tbody');
  tb.innerHTML='';
  (data.items||[]).forEach(p=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${p.id}</td>
      <td>${p.title}</td>
      <td>${p.category||''}</td>
      <td>${Number(p.price_xaf||0).toLocaleString()} XAF</td>
      <td>${p.image_url ? `<img src="${p.image_url}" style="max-height:50px">` : ''}</td>
      <td>${new Date(p.created_at).toLocaleString()}</td>
    `;
    tb.appendChild(tr);
  });
}
  // ================== CERRAR SESIÓN ==================
document.getElementById('logoutBtn').addEventListener('click', ()=>{
  localStorage.removeItem('bizToken');
  localStorage.removeItem('bizId');
  token = null;
  business_id = null;
  // Mostrar login otra vez y ocultar el panel
  document.getElementById('loginBox').style.display = 'block';
  document.getElementById('panel').style.display = 'none';
  });
</script>
</body>
</html>

<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>WapMarket — Marketplace GE</title>
  <link rel="stylesheet" href="/styles.css">

  <!-- Fuente Futura PT -->
  <style>
    @import url('https://fonts.cdnfonts.com/css/futura-pt');

    /* ====== TOKENS ====== */
    :root{
      --gap:16px;
      --aside-w:300px;
      --radius:16px;
      --shadow: 0 10px 30px rgba(0,0,0,.08);
      --shadow-lg: 0 18px 50px rgba(0,0,0,.12);
      --bg: #f5f7fb;
      --card: #ffffff;
      --text: #111;
      --muted: #5c6370;
      --brand1:#5b8cff;
      --brand2:#8a5bff;
      --accent:#ff7a18;
      --ok:#12b886;
      --warn:#ffa94d;
    }
    @media (prefers-color-scheme: dark){
      :root{
        --bg:#0c0f14;
        --card:#10151d;
        --text:#e6e6eb;
        --muted:#9aa3b2;
        --brand1:#7aa2ff;
        --brand2:#a87aff;
        --accent:#ff9157;
        --shadow: 0 14px 40px rgba(0,0,0,.35);
        --shadow-lg: 0 24px 60px rgba(0,0,0,.45);
      }
    }

    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0;
      padding:0;
      background:
        radial-gradient(1200px 600px at 100% -10%,rgba(138,91,255,.06),transparent 60%),
        radial-gradient(1200px 600px at -10% 110%,rgba(91,140,255,.06),transparent 60%),
        var(--bg);
      font-family:'Futura PT', system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial;
      color:var(--text);
      display:flex;
      flex-direction:column;
      min-height:100vh;
    }

    .wrapper{max-width:1200px;margin:0 auto;padding:16px}

    /* ====== HEADER ====== */
    .header {
      position: sticky; top: 0; z-index: 20;
      backdrop-filter: saturate(180%) blur(8px);
      background: linear-gradient(90deg, #131921 0%, #1a2440 100%);
      border-bottom: 1px solid rgba(255,255,255,.06);
    }
    .row {display:flex; align-items:center; gap:12px; flex-wrap:wrap}
    .logo {
      font-family: Arial, sans-serif;
      font-weight: 900;
      letter-spacing:.3px;
      font-size: 1.5rem;
      color: #fff;
      display:flex; align-items:center; gap:8px;
    }
    .logo:after{
      content:"";
      width:10px;height:10px;border-radius:50%;
      background:linear-gradient(45deg,var(--brand1),var(--brand2));
      box-shadow:0 0 0 4px rgba(255,255,255,.08);
    }

    /* buscador */
    .search {display:flex; flex:1; max-width: 720px; position:relative}
    .search input {
      flex:1; padding:12px 44px 12px 14px;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.08);
      color:#fff;
      border-radius: 999px;
      outline:none;
    }
    .search input::placeholder{color:#d5d9e3}
    #btnBuscar {
      position:absolute; right:6px; top:6px; bottom:6px;
      background: linear-gradient(90deg, var(--brand1), var(--brand2));
      color: #fff; border: none; padding: 0 16px;
      font-weight: 800; cursor: pointer; display: inline-flex; align-items: center; justify-content:center;
      border-radius: 999px; box-shadow: var(--shadow);
      transition: transform .15s ease;
    }
    #btnBuscar:active{ transform: scale(.98) }

    /* ====== BOTÓN CARRITO ====== */
    #btnOpenCart {
      position: relative; display: inline-flex; align-items: center; justify-content: center;
      background: rgba(255,255,255,.1); color: #fff;
      border: 1px solid rgba(255,255,255,.18);
      border-radius: 12px; height: 42px; padding: 0 12px; margin-left: 4px;
      transition: transform .15s ease, background .2s ease;
    }
    #btnOpenCart:hover{ transform: translateY(-1px); background: rgba(255,255,255,.16); }
    #btnOpenCart img { width: 22px; height: 22px; object-fit: contain; filter: brightness(1.2) }
    #btnOpenCart[data-has-items="true"]::after {
      content: ""; position: absolute; top: 4px; right: 4px; width: 8px; height: 8px; border-radius: 50%;
      background: #ff3b30; box-shadow: 0 0 0 4px rgba(255,59,48,.25);
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse{0%{transform:scale(1)}50%{transform:scale(1.3)}100%{transform:scale(1)}}

    /* ====== LAYOUT ====== */
    .layout{display:grid;grid-template-columns: var(--aside-w) 1fr; gap:var(--gap); flex:1}
    aside{margin-left:-4px}
    .card{
      background: var(--card);
      border:1px solid rgba(0,0,0,.06);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow:hidden;
    }
    .card .body{padding:14px 14px}

    #bizList{display:flex;flex-direction:column;gap:10px}
    #bizList.scrolling{max-height:420px;overflow:auto;border-top:1px dashed rgba(0,0,0,.1);padding-top:8px}

    section .card{background:transparent;border:none;box-shadow:none}
    #results.grid{display:grid;grid-template-columns: repeat(4, minmax(0,1fr));gap:var(--gap)}

    /* ====== PRODUCTOS ====== */
    .product-item{
      background:var(--card); border:1px solid rgba(0,0,0,.06); border-radius:16px; box-shadow: var(--shadow); overflow:hidden;
      transition: transform .18s ease, box-shadow .18s ease;
    }
    .product-item:hover{ transform: translateY(-4px); box-shadow: var(--shadow-lg); }
    .product-item .thumb{width:100%;aspect-ratio:4/3;object-fit:cover;display:block;filter:saturate(1.05)}
    .product-item .meta{padding:10px 12px}
    .badge{display:inline-block;font-size:12px;padding:4px 8px;border:1px solid rgba(0,0,0,.08);border-radius:999px;background:rgba(0,0,0,.03)}
    .price{font-weight:900;margin:6px 0;font-size:1.05rem}

    /* ====== CHIPS DE FILTRO ====== */
    .chips{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 2px}
    .chip{
      background:linear-gradient(90deg, rgba(91,140,255,.12), rgba(138,91,255,.12));
      border:1px solid rgba(91,140,255,.25);
      color:var(--text);
      padding:6px 10px; border-radius:999px; cursor:pointer; font-weight:700; font-size:.92rem;
      transition: transform .15s ease, background .2s ease;
      user-select:none;
    }
    .chip:hover{ transform: translateY(-1px) }
    .chip.active{ background: linear-gradient(90deg, var(--brand1), var(--brand2)); color:#fff; border-color: transparent }

    /* ====== CONTENEDOR PUBLICITARIO (oculto para conservar) ====== */
    .ads-container{display:none !important}

    /* ====== VERIFICADO ====== */
    .verified-badge{display:inline-flex;align-items:center;margin-left:10px;vertical-align:middle}
    .verified-badge img{width:22px;height:22px;object-fit:contain}

    /* ====== FOOTER ====== */
    .footer{
      background: linear-gradient(90deg, rgba(91,140,255,.08), rgba(138,91,255,.08));
      border-top:1px solid rgba(0,0,0,.06);
      padding:14px;text-align:center;margin-top:auto;color:var(--muted)
    }
    .footer a{margin:0 8px;color:inherit;text-decoration:underline;transition:opacity .2s}
    .footer a:hover{opacity:.8}

    /* ====== RESPONSIVE GRID ====== */
    @media (max-width:1100px){#results.grid{grid-template-columns: repeat(3,minmax(0,1fr));}:root{--aside-w:260px}}
    @media (max-width:900px){.layout{grid-template-columns:1fr}aside{order:2}section{order:1}#results.grid{grid-template-columns: repeat(2,minmax(0,1fr));}}
    @media (max-width:520px){
      .row{flex-direction:column;align-items:stretch}
      .search{width:100%}
      #results.grid{grid-template-columns:1fr}
      .logo{justify-content:center}
    }

    /* ====== MODALES / DRAWER CARRITO ====== */
    .modal{position:fixed;inset:0;background:rgba(0,0,0,.35);display:none;align-items:stretch;justify-content:flex-end;padding:0;z-index:40}
    .dialog{
      background:var(--card); width:min(480px, 100%); height:100%; overflow:auto;
      box-shadow: var(--shadow-lg); border-left:1px solid rgba(0,0,0,.08);
      padding:16px 16px 24px;
      animation: slideIn .25s ease both;
    }
    @keyframes slideIn{from{transform:translateX(30px); opacity:0} to{transform:translateX(0); opacity:1}}
    .small{font-size:.92em;color:var(--muted)}
    .kbd{font-family:ui-monospace,Menlo,Consolas,monospace}

    /* ====== BOTONES GENÉRICOS ====== */
    .btn{
      background: linear-gradient(90deg, var(--accent), #af002d 85%);
      color:#fff; border:none; padding:10px 14px; border-radius:12px; cursor:pointer; font-weight:800;
      box-shadow: var(--shadow); transition: transform .12s ease, filter .2s ease;
    }
    .btn:hover{ transform: translateY(-1px) }
    .btn:active{ transform: translateY(1px) }
    .btn.ghost{
      background: transparent; color:var(--text);
      border:1px solid rgba(0,0,0,.12);
    }

    /* ====== WHATSAPP CARRUSEL (mantenido y mejorado) ====== */
    .wa-ads{margin:22px 0;padding:0;background:transparent;border:none}
    .wa-ads h3{margin:0 0 10px;font-size:18px;color:var(--text);font-weight:900}
    .wa-carousel-wrap{position:relative;overflow:hidden;border:1px solid rgba(0,0,0,.08);background:var(--card);border-radius:16px;box-shadow:var(--shadow)}
    .wa-carousel{display:flex;transition:transform .45s ease;will-change:transform}
    .wa-slide{min-width:100%;flex-shrink:0;text-align:center}
    .wa-slide a{display:block;text-decoration:none;color:inherit}
    .wa-slide img{width:100%;height:240px;object-fit:cover;display:block;filter:saturate(1.05)}
    .wa-slide p{margin:8px 0 12px;font-size:14px}
    .wa-nav{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:8px}
    .wa-btn{background:linear-gradient(90deg,var(--brand1),var(--brand2));color:#fff;border:none;width:36px;height:36px;border-radius:50%;cursor:pointer;box-shadow:var(--shadow)}
    .wa-dots{display:flex;gap:6px;flex:1;justify-content:center}
    .wa-dot{width:8px;height:8px;border-radius:50%;background:#cfcfcf;border:none}
    .wa-dot.active{background:linear-gradient(90deg,var(--brand1),var(--brand2))}
    @media (max-width:520px){.wa-slide img{height:190px} .wa-btn{width:40px;height:40px}}

    /* ====== SUGERENCIAS BUSCADOR ====== */
    .sugg{
      position:absolute; top:48px; left:0; right:0; background:var(--card); border:1px solid rgba(0,0,0,.1);
      border-radius:12px; box-shadow:var(--shadow); overflow:hidden; display:none; z-index:25;
      max-height:280px; overflow:auto;
    }
    .sugg li{list-style:none; padding:10px 12px; display:flex; gap:10px; align-items:center; cursor:pointer}
    .sugg li:hover{background:rgba(91,140,255,.08)}
    .sugg img{width:40px;height:40px;object-fit:cover;border-radius:8px;border:1px solid rgba(0,0,0,.06)}
  
/* ===================== AMAZON-LIKE THEME OVERRIDES ===================== */
/* Palette */
:root{
  --amz-dark:#131921;
  --amz-light:#232f3e;
  --amz-yellow:#febd69;
  --amz-orange:#f3a847;
  --amz-link:#007185;
  --amz-border:#e6e6e6;
}

/* Header => Amazon navbar style */
.header{
  position: sticky; top:0; z-index: 50;
  background: var(--amz-dark) !important;
  border-bottom: none !important;
  backdrop-filter: none !important;
}
.logo{
  color:#fff !important;
  font-weight: 800 !important;
  letter-spacing:.2px !important;
}
.logo:after{ display:none !important; }

/* Search: light input + yellow button, joined corners */
.search{ max-width: 900px !important; }
.search input{
  background:#fff !important;
  border:1px solid var(--amz-border) !important;
  color:#111 !important;
  border-radius:4px 0 0 4px !important;
  height:44px !important;
  box-shadow:none !important;
}
#btnBuscar{
  position:static !important;
  height:44px !important;
  border-radius:0 4px 4px 0 !important;
  background: var(--amz-yellow) !important;
  color:#111 !important;
  font-weight:700 !important;
  box-shadow:none !important;
  border:1px solid #f0a947 !important;
}

/* Cart button: text/icon on dark header */
#btnOpenCart{
  background: transparent !important;
  border: 1px solid rgba(255,255,255,.2) !important;
  color:#fff !important;
  height:40px !important;
  border-radius:4px !important;
}
#btnOpenCart:hover{ background: rgba(255,255,255,.08) !important; }
#btnOpenCart img{ filter: brightness(2) !important; }

/* Layout & cards */
body{ background: #eaeded !important; }
.card{
  background:#fff !important;
  border:1px solid var(--amz-border) !important;
  border-radius:0 !important;
  box-shadow:none !important;
}
section .card{ background: transparent !important; border:none !important; }

/* Product grid cards */
.product-item{
  border:1px solid var(--amz-border) !important;
  border-radius:0 !important;
  box-shadow:none !important;
  background:#fff !important;
}
.product-item:hover{ box-shadow: 0 2px 8px rgba(0,0,0,.08) !important; transform: translateY(-2px) !important; }
.product-item .thumb{ background:#fff; }
.product-item .meta{ padding:12px 14px !important; }
.product-item h4{ margin:6px 0 8px !important; font-weight:700; }
.product-item h4, .product-item h4 *{ color: var(--amz-link) !important; }

/* Product badges & price */
.badge{
  background:#fafafa !important;
  border:1px solid var(--amz-border) !important;
  color:#111 !important;
  border-radius:2px !important;
  font-weight:700 !important;
}
.price{ color:#B12704 !important; font-size:1.1rem !important; font-weight: 800 !important; }

/* Product buttons: primary = yellow, secondary = light gray */
.product-item .btn{
  height:36px !important;
  border-radius:20px !important;
  padding:0 16px !important;
  flex:1;
}
.product-item .btn:not(.ghost){
  background: var(--amz-yellow) !important;
  border:1px solid #f0a947 !important;
  color:#111 !important;
}
.product-item .btn.ghost{
  background:#fff !important;
  border:1px solid var(--amz-border) !important;
  color:#111 !important;
}

/* Featured carousel & Ads: squared like Amazon */
.wa-carousel-wrap{
  border-radius:0 !important;
  border:1px solid var(--amz-border) !important;
  background:#fff !important;
  box-shadow:none !important;
}
.wa-btn{
  background: var(--amz-light) !important;
  color:#fff !important;
  border:none !important;
  width:34px !important; height:34px !important;
  border-radius:4px !important;
}
.wa-dot{ background:#c7c7c7 !important; }
.wa-dot.active{ background:#111 !important; }

/* Filter chips => minimal links */
.chips{ gap:6px !important; }
.chip{
  background:transparent !important;
  border:none !important;
  color:#111 !important;
  border-radius:0 !important;
  padding:4px 6px !important;
  font-weight:700 !important;
}
.chip.active{ color: var(--amz-link) !important; text-decoration: underline; }

/* Suggestions dropdown */
.sugg{
  border:1px solid var(--amz-border) !important;
  border-radius:0 !important;
  box-shadow:none !important;
}

/* Sidebar business list */
#bizList.scrolling{ border-top:1px solid var(--amz-border) !important; }
#bizList > div{
  border-radius:0 !important;
  border:1px solid var(--amz-border) !important;
  box-shadow:none !important;
}

/* Footer */
.footer{
  background:#fff !important;
  border-top:1px solid var(--amz-border) !important;
  color:#565959 !important;
}

/* Modal (Cart) => Amazon checkout vibe */
.modal{ background: rgba(0,0,0,.5) !important; }
.dialog{
  border-left: none !important;
  border-radius:0 !important;
  width:min(520px,100%) !important;
  background:#fff !important;
}
#cartModal .dialog h3{ font-weight:800 !important; }
#cartItems img{ border-radius:4px !important; }
#totals{ color:#111 !important; font-size:1.05rem !important; }
#checkoutForm input, #checkoutForm textarea{
  border:1px solid var(--amz-border) !important; border-radius:4px !important;
}
#checkoutForm .btn[type="submit"]{
  background: var(--amz-yellow) !important; color:#111 !important; border:1px solid #f0a947 !important;
}
#checkoutForm .btn.ghost{ background:#fff !important; color:#111 !important; border:1px solid var(--amz-border) !important; }

/* Keep verified badge visible */
.verified-badge img{ filter: none !important; }

  
/* ===== EXTRA ADJUSTMENTS (mobile grid, background, filters, cart modal) ===== */

/* 1. Background unified to Amazon light gray */
body{ background:#eaeded !important; }

/* 2. Mobile grid 3x3 (instead of 2x2 or 1) */
@media (max-width:900px){
  #results.grid{grid-template-columns: repeat(3, minmax(0,1fr)) !important;}
}
@media (max-width:520px){
  #results.grid{grid-template-columns: repeat(3, minmax(0,1fr)) !important;}
  .search{ width:100% !important; }
  .search input{ width:100% !important; }
}

/* 3. Filters: remove graphical background, just plain text */
.chip{ background:transparent !important; border:none !important; padding:0 !important; text-decoration:none !important; }

/* 4. Align header elements */
.header .row{ flex-wrap:nowrap !important; justify-content:space-between !important; }
.search{ flex:1 !important; margin:0 8px !important; }
#btnOpenCart{ margin-left:8px !important; }

/* 5. Modal cart above topbar */
.modal{ z-index:100 !important; }

  
/* ===== FINAL ADJUSTMENTS ===== */

/* 1. Mobile grid 2x2 instead of 3x3 */
@media (max-width:900px){
  #results.grid{grid-template-columns: repeat(2, minmax(0,1fr)) !important;}
}
@media (max-width:520px){
  #results.grid{grid-template-columns: repeat(2, minmax(0,1fr)) !important;}
}

/* 2. Filters only text (remove emojis manually with CSS hiding technique) */
.chip::after, .chip::before{ display:none !important; }

  </style>

<style>
  body{font-family:"SF Pro Display","Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#111;line-height:1.4;}
  header.topbar, header{width:100%!important;left:0;right:0;position:sticky;top:0;z-index:100;}
  .row.wrapper{max-width:100%!important;margin:0!important;padding:0 8px;box-sizing:border-box;}
  .btn.ghost{display:inline-block;padding:8px 14px;border-radius:20px;background:#f3f3f3;border:1px solid #ddd;
             font-weight:600;font-size:0.9rem;cursor:pointer;text-align:center;white-space:nowrap;}
  .btn.ghost:hover{background:#e0e0e0;}
  /* Modal styles */
  .modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;z-index:1000;}
  .modal{background:#fff;max-width:600px;width:90%;border-radius:12px;overflow:hidden;box-shadow:0 6px 20px rgba(0,0,0,.25);animation:fadeIn .3s;}
  .modal-header{padding:12px 16px;border-bottom:1px solid #eee;font-weight:700;font-size:1.1rem;}
  .modal-body{padding:16px;}
  .modal-body img{width:100%;max-height:300px;object-fit:contain;border-radius:8px;margin-bottom:12px;}
  .modal-footer{padding:12px 16px;border-top:1px solid #eee;text-align:right;}
  .modal-close{cursor:pointer;background:none;border:none;font-size:1.2rem;float:right;}
  @keyframes fadeIn{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:none;}}
</style>

</head>
<body>

<header class="header">
  <div class="row wrapper" style="padding-block:10px">
    <div class="logo">WapMarket</div>
    <form id="searchForm" class="search" onsubmit="return false;">
      <input id="q" placeholder="Buscar productos o servicios..." autocomplete="off" />
      <button class="btn" id="btnBuscar" aria-label="Buscar">Buscar</button>
      <ul id="suggBox" class="sugg" role="listbox"></ul>
    </form>
    <a href="#" class="btn ghost" id="btnOpenCart" aria-label="Abrir carrito" title="Carrito" data-has-items="false">
      <img src="/aset/icons8-buy-64.png" alt="Carrito">
    </a>
  </div>
</header>

<main class="wrapper">
  <div class="layout">
    <aside>
      <div class="card">
        <div class="body">
          <h3 style="margin:4px 0 10px">Negocios disponibles</h3>
          <div id="bizList"></div>
        </div>
      </div>

      <!-- Filtros: chips -->
      <div class="card" style="margin-top:16px">
        <div class="body">
          <h3 style="margin:4px 0 10px">Filtros</h3>
          <div class="chips" id="chips"></div>
          <!-- Select oculto para mantener compatibilidad JS si se necesita -->
          <select id="category" style="display:none">
            <option value="">Todas</option>
            <option>Servicios</option><option>Comida</option><option>Tiendas</option>
            <option>Salud</option><option>Transporte</option><option>Tecnología</option>
          </select>
        </div>
      </div>

      <!-- CONTENEDOR PUBLICITARIO (oculto pero conservado) -->
      <div class="ads-container">
        <button class="ads-info-btn" onclick="openAdsInfo()">i</button>
        <img src="/aset/Fachada.jpg" alt="Publicidad">
      </div>
    </aside>

    <section>
      <div class="card" style="background:transparent;box-shadow:none;border:none">
        <div class="body" style="padding:0">
          <h3 id="bizTitle" style="margin:6px 0 14px">Selecciona un negocio</h3>

          <!-- Carrusel de destacados (simple): se rellena con primeros productos -->
          <div id="featuredWrap" style="display:none;margin-bottom:14px">
            <div class="wa-carousel-wrap">
              <div class="wa-carousel" id="featCarousel"></div>
            </div>
            <div class="wa-nav">
              <button class="wa-btn" type="button" data-dir="-1" data-target="feat">‹</button>
              <div class="wa-dots" id="featDots"></div>
              <button class="wa-btn" type="button" data-dir="1" data-target="feat">›</button>
            </div>
          </div>

          <div id="results" class="grid"></div>
          <div style="display:flex;justify-content:center;margin-top:12px">
            <button id="nextBtn" class="btn" style="display:none">Ver más</button>
          </div>
        </div>
      </div>

      <!-- Publicidad WhatsApp (MANTENIDA) -->
      <section class="wa-ads" aria-label="Publicidad">
        <h3>Publicidad</h3>
        <div class="wa-carousel-wrap">
          <div class="wa-carousel" id="waCarousel">
            <div class="wa-slide">
              <a href="https://wa.me/240555218661" target="_blank" rel="noopener">
                <img src="/aset/Captura de pantalla 2025-07-07 a la(s) 19.02.16.png" alt="Wap Tech & Services">
                <p>Wap Tech &amp; Services</p>
              </a>
            </div>
            <div class="wa-slide">
              <a href="https://wa.me/240555218661" target="_blank" rel="noopener">
                <img src="/aset/app-check-hero_2x.png" alt="CiberSeguridad Prisma">
                <p>CiberSeguridad Prisma</p>
              </a>
            </div>
            <!-- Puedes añadir más slides conservando el formato -->
          </div>
        </div>
        <div class="wa-nav">
          <button class="wa-btn" type="button" data-dir="-1" aria-label="Anterior">‹</button>
          <div class="wa-dots" id="waDots"></div>
          <button class="wa-btn" type="button" data-dir="1" aria-label="Siguiente">›</button>
        </div>
      </section>
    </section>
  </div>
</main>

<!-- Drawer Carrito (manteniendo IDs y lógica original) -->
<div class="modal" id="cartModal">
  <div class="dialog">
    <div style="display:flex;align-items:center;justify-content:space-between">
      <h3 style="margin:6px 0">Tu carrito</h3>
      <button class="btn ghost" type="button" onclick="closeCart()">✕</button>
    </div>
    <div id="cartInfo" class="small" style="margin-bottom:8px"></div>
    <div id="cartItems"></div>
    <div style="margin:12px 0">
      <label style="display:flex;gap:8px;align-items:center">
        <input type="checkbox" id="deliveryChk"> <span>Envío a domicilio (+2000 XAF)</span>
      </label>
    </div>
    <div id="addressBox" style="display:none">
      <label style="display:block;margin-bottom:10px">Dirección exacta
        <input id="address" placeholder="Ej: Malabo, Semu, casa azul" style="width:100%;padding:10px;border-radius:10px;border:1px solid rgba(0,0,0,.12)">
      </label>
    </div>
    <div id="totals" style="margin:12px 0;font-weight:900"></div>
    <form id="checkoutForm" style="display:grid;gap:10px">
      <label>Tu nombre (opcional)
        <input id="cname" style="width:100%;padding:10px;border-radius:10px;border:1px solid rgba(0,0,0,.12)">
      </label>
      <label>Teléfono (WhatsApp) <input id="cphone" required style="width:100%;padding:10px;border-radius:10px;border:1px solid rgba(0,0,0,.12)"></label>
      <label>Nota <textarea id="cnote" placeholder="Ej: Entrega 18:00" style="width:100%;padding:10px;border-radius:10px;border:1px solid rgba(0,0,0,.12)"></textarea></label>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">
        <button class="btn" type="submit">Confirmar pedido</button>
        <button class="btn ghost" type="button" onclick="closeCart()">Cerrar</button>
      </div>
    </form>
  </div>
</div>

<!-- Modal info publicidad (conservada) -->
<div class="modal" id="adsModal">
  <div class="dialog">
    <h3>Promociona tu negocio</h3>
    <p>Puedes promocionar tus productos o servicios en WapMarket con banners publicitarios.</p>
    <ul>
      <li><a href="#">Más información</a></li>
      <li><a href="#">Contactar soporte</a></li>
      <li><a href="#">Enviar tu publicidad</a></li>
    </ul>
    <div style="text-align:right;margin-top:10px">
      <button class="btn" onclick="closeAdsInfo()">Cerrar</button>
    </div>
  </div>
</div>

<footer class="footer">
  <span>© WapMarket — Pulsa <span class="kbd">/</span> para buscar</span>
  <a href="#">comprar</a>
  <a href="#">reserva hotel</a>
  <a href="#">restaurantes</a>
  <a href="#">negocios</a>
  <a href="#">comprar billetes</a>
  <a href="#">empleos</a>
</footer>

  <!-- Google tag (gtag.js) -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-9EEQZSC4X3"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-9EEQZSC4X3');
</script>

<script src="/api.js"></script>
<script>
/* ====== JS PRINCIPAL (mejorado, manteniendo endpoints y lógica) ====== */
const DELIVERY_FEE = 2000;
let selectedBusiness = null;
let cart = JSON.parse(localStorage.getItem('cart') || '[]');
let currentProducts = [];

let pageSize = 20;
let currentPage = 1;

const qInput = document.getElementById('q');
const suggBox = document.getElementById('suggBox');

function saveCart(){ localStorage.setItem('cart', JSON.stringify(cart)); updateCartCount(); }
function updateCartCount(){
  const count = cart.reduce((a,c)=>a+Number(c.qty||1),0);
  document.getElementById('btnOpenCart').setAttribute('data-has-items', count>0 ? 'true' : 'false');
}
function closeCart(){ document.getElementById('cartModal').style.display='none'; }
function openCart(){ document.getElementById('cartModal').style.display='flex'; renderCart(); }

/* Publicidad modal (conservada) */
function openAdsInfo(){ var m=document.getElementById('adsModal'); if(m) m.style.display='flex'; }
function closeAdsInfo(){ var m=document.getElementById('adsModal'); if(m) m.style.display='none'; }

document.getElementById('btnOpenCart').addEventListener('click', (e)=>{ e.preventDefault(); openCart(); });

function categoryChipsInit(){
  const categories = ["Todas","Servicios","Comida","Tiendas","Salud","Transporte","Tecnología"];
  const wrap = document.getElementById('chips');
  wrap.innerHTML = '';
  categories.forEach(cat=>{
    const b = document.createElement('button');
    b.type='button'; b.className='chip'+(cat==="Todas"?' active':''); b.textContent=cat+(cat==="Comida"?' 🍔':cat==="Servicios"?' ⚡':cat==="Transporte"?' 🚗':cat==="Tecnología"?' 💻':'');
    b.dataset.value = cat==="Todas" ? "" : cat;
    b.addEventListener('click', ()=>{
      [...wrap.children].forEach(x=>x.classList.remove('active'));
      b.classList.add('active');
      document.getElementById('category').value = b.dataset.value;
      if (selectedBusiness) loadProducts();
    });
    wrap.appendChild(b);
  });
}

function setBusiness(b){
  selectedBusiness = b;
  document.getElementById('bizTitle').innerHTML =
    'Productos de ' + b.name + (b.business_type==='verified'
      ? '<span class="verified-badge"><img src="/aset/icons8-verified-50.png" alt="Verificado"></span>'
      : '');
  if (cart.length && cart[0].business_id !== b.id){
    if (confirm('Tu carrito pertenece a otro negocio. ¿Vaciar carrito para continuar con ' + b.name + '?')){
      cart = []; saveCart();
    }
  }
  currentPage = 1;
  loadProducts();
}

async function loadBusinesses(){
  const data = await API.get('/public/businesses');
  const box = document.getElementById('bizList');
  box.innerHTML = '';
  (data.items||[]).forEach(b=>{
    const el = document.createElement('div');
    el.style.cssText = 'padding:12px;border:1px solid rgba(0,0,0,.08);border-radius:12px;background:var(--card);box-shadow:var(--shadow);cursor:pointer;transition:transform .15s ease';
    el.onmouseenter=()=>el.style.transform='translateY(-2px)';
    el.onmouseleave=()=>el.style.transform='translateY(0)';
    el.innerHTML = `
      <strong style="font-size:1.02rem">${b.name}</strong>
      ${b.business_type==='verified' ? '<span class="verified-badge"><img src="/aset/icons8-verified-50.png" alt="Verificado"></span>' : ''}
      <div class="small">${b.location||''}</div>`;
    el.addEventListener('click', ()=> setBusiness(b));
    box.appendChild(el);
  });
  if ((data.items||[]).length > 10){ box.classList.add('scrolling'); }
  if (!selectedBusiness && (data.items||[]).length) setBusiness(data.items[0]);
}

function renderProductsPage(){
  const list = document.getElementById('results');
  list.innerHTML = '';
  const start = (currentPage-1)*pageSize;
  const pageItems = currentProducts.slice(start, start+pageSize);

  pageItems.forEach(p=>{
    const el = document.createElement('div');
    el.className = 'product-item';
    el.innerHTML = `
      <img class="thumb" src="${p.image_url || 'https://placehold.co/600x400?text=WapMarket'}" alt="">
      <div class="meta">
        <div style="display:flex;align-items:center;gap:8px;justify-content:space-between">
          <span class="badge">${p.category || ''}</span>
          ${p.price_xaf ? `<span class="price">${Number(p.price_xaf).toLocaleString()} XAF</span>` : '<span></span>'}
        </div>
        <h4 style="margin:8px 0 8px; font-size:1.02rem"><a href="product_detail.html?id=${p.id}" style="color:inherit;text-decoration:none">${p.title}</a></h4>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:space-between">
          <button class="btn" data-id="${p.id}" title="Añadir al carrito">Añadir</button>
          <a class="btn ghost" href="product_detail.html?id=${p.id}" title="Ver más">Ver más</a>
        </div>
      </div>`;
    list.appendChild(el);
  });

  const nextBtn = document.getElementById('nextBtn');
  if (currentProducts.length > pageSize){
    const startPlus = start + pageSize;
    nextBtn.style.display = startPlus < currentProducts.length ? 'inline-block' : 'none';
  } else {
    nextBtn.style.display = 'none';
  }

  // acción de añadir
  list.onclick = (e)=>{
    const addBtn = e.target.closest('button[data-id]');
    if(addBtn){
      const id = addBtn.dataset.id;
      const p = currentProducts.find(x=>x.id == id);
      if (!p) return;

      if (cart.length && cart[0].business_id !== p.business_id){
        if (!confirm('Tu carrito es de otro negocio. ¿Vaciar y cambiar a ' + (selectedBusiness?.name||'este negocio') + '?')) return;
        cart = [];
      }
      const exists = cart.find(x=>x.id===p.id);
      if (exists) exists.qty = Number(exists.qty||1)+1;
      else cart.push({ id:p.id, title:p.title, price_xaf:p.price_xaf, image_url:p.image_url, category:p.category, qty:1, business_id: p.business_id });
      saveCart();

      // microinteracción
      addBtn.style.transform='scale(0.96)';
      setTimeout(()=>addBtn.style.transform='',120);
    }
  };
}

function renderFeatured(){
  const wrap = document.getElementById('featuredWrap');
  const car = document.getElementById('featCarousel');
  const dots = document.getElementById('featDots');
  if (!currentProducts.length){ wrap.style.display='none'; return; }

  const items = currentProducts.slice(0, Math.min(6, currentProducts.length));
  car.innerHTML = items.map(p=>`
    <div class="wa-slide">
      <a href="javascript:void(0)">
        <img src="${p.image_url || 'https://placehold.co/1200x480?text=WapMarket'}" alt="${p.title}">
        <p style="font-weight:800">${p.title} ${p.price_xaf ? '• '+Number(p.price_xaf).toLocaleString()+' XAF':''}</p>
      </a>
    </div>`).join('');

  dots.innerHTML = '';
  items.forEach((_,i)=>{
    const d = document.createElement('button'); d.className='wa-dot'+(i===0?' active':''); d.type='button';
    d.addEventListener('click',()=>featGo(i));
    dots.appendChild(d);
  });

  wrap.style.display='block';

  let idx=0;
  function featGo(i){
    const slides = items.length;
    idx = (i+slides)%slides;
    car.style.transform = `translateX(-${idx*100}%)`;
    [...dots.children].forEach((d,j)=>d.classList.toggle('active', j===idx));
  }
  document.querySelectorAll('.wa-btn[data-target="feat"]').forEach(b=>{
    b.onclick=()=>featGo(idx + Number(b.dataset.dir||1));
  });
}

async function loadProducts(){
  if (!selectedBusiness) return;
  const q = document.getElementById('q').value.trim();
  const cat = document.getElementById('category').value;
  const params = new URLSearchParams();
  params.set('business_id', selectedBusiness.id);
  if (q) params.set('q', q);
  if (cat) params.set('category', cat);
  const data = await API.get('/public/products?' + params.toString());
  currentProducts = data.items || [];
  currentPage = 1;
  renderFeatured();
  renderProductsPage();
  renderSuggestions(); // refresca lista de sugerencias si está abierta
}

function renderCart(){
  const box = document.getElementById('cartItems');
  const info = document.getElementById('cartInfo');
  if (!cart.length){
    box.innerHTML = '<p class="small">Tu carrito está vacío.</p>';
    info.textContent=''; document.getElementById('totals').textContent=''; return;
  }
  info.textContent = 'Negocio: ' + (selectedBusiness && cart[0].business_id===selectedBusiness.id ? selectedBusiness.name : ('#' + cart[0].business_id));
  box.innerHTML = '';
  let subtotal = 0;
  cart.forEach((item, idx)=>{
    const div = document.createElement('div');
    div.style.margin='8px 0';
    div.innerHTML = `
      <div style="display:flex;gap:10px;align-items:center">
        <img src="${item.image_url || 'https://placehold.co/80'}" style="width:60px;height:60px;object-fit:cover;border-radius:12px;border:1px solid rgba(0,0,0,.08)">
        <div style="flex:1">
          <div><strong>${item.title}</strong></div>
          <div class="small">${(item.price_xaf||0).toLocaleString()} XAF • <span>${item.category||''}</span></div>
          <div style="display:flex;gap:6px;align-items:center;margin-top:6px">
            <button class="btn ghost" data-idx="${idx}" data-act="dec">-</button>
            <span style="min-width:24px;text-align:center">${item.qty}</span>
            <button class="btn ghost" data-idx="${idx}" data-act="inc">+</button>
            <button class="btn" data-idx="${idx}" data-act="del">Quitar</button>
          </div>
        </div>
      </div>
    `;
    subtotal += (Number(item.price_xaf||0) * Number(item.qty||1));
    box.appendChild(div);
  });
  const delivery = document.getElementById('deliveryChk').checked;
  const total = subtotal + (delivery ? DELIVERY_FEE : 0);
  document.getElementById('totals').textContent =
    'Subtotal: ' + subtotal.toLocaleString() + ' XAF' + (delivery? ' + Envío: 2.000 XAF = Total: ' + total.toLocaleString() + ' XAF' : ' = Total: ' + total.toLocaleString() + ' XAF');
  box.onclick = (e)=>{
    const btn = e.target.closest('button.btn,button.btn.ghost'); if(!btn) return;
    const i = Number(btn.dataset.idx); const act = btn.dataset.act;
    if (act==='inc') cart[i].qty = Number(cart[i].qty||1) + 1;
    if (act==='dec') cart[i].qty = Math.max(1, Number(cart[i].qty||1) - 1);
    if (act==='del') cart.splice(i,1);
    saveCart(); renderCart();
  }
}

document.getElementById('deliveryChk').addEventListener('change', (e)=>{
  document.getElementById('addressBox').style.display = e.target.checked ? 'block' : 'none';
  renderCart();
});

document.getElementById('btnBuscar').addEventListener('click', ()=>{ if (selectedBusiness) loadProducts(); });
document.addEventListener('keydown', (e)=>{ if(e.key==='/'){ e.preventDefault(); qInput.focus(); } });

// Paginación
document.getElementById('nextBtn').addEventListener('click', ()=>{
  const maxPages = Math.ceil(currentProducts.length / pageSize);
  if (currentPage < maxPages){ currentPage++; renderProductsPage(); window.scrollTo({top:0,behavior:'smooth'}); }
});

/* ====== BUSCADOR: Búsqueda en vivo + sugerencias locales ====== */
let typingTimer;
qInput.addEventListener('input', ()=>{
  clearTimeout(typingTimer);
  typingTimer = setTimeout(()=>{ if(selectedBusiness) loadProducts(); }, 250); // debounce
  renderSuggestions();
});
qInput.addEventListener('focus', ()=>renderSuggestions());
document.addEventListener('click', e=>{
  if(!e.target.closest('.search')) suggBox.style.display='none';
});

function renderSuggestions(){
  const term = qInput.value.trim().toLowerCase();
  if(!term || !currentProducts.length){ suggBox.style.display='none'; return; }
  const matches = currentProducts
    .filter(p => (p.title||'').toLowerCase().includes(term))
    .slice(0,8);
  if(!matches.length){ suggBox.style.display='none'; return; }
  suggBox.innerHTML = matches.map(m=>`
    <li role="option" data-id="${m.id}">
      <img src="${m.image_url || 'https://placehold.co/80'}" alt="">
      <div style="display:flex;flex-direction:column">
        <strong style="line-height:1.1">${m.title}</strong>
        <span class="small">${m.category||''} ${m.price_xaf? '• '+Number(m.price_xaf).toLocaleString()+' XAF':''}</span>
      </div>
    </li>`).join('');
  suggBox.style.display='block';

  suggBox.querySelectorAll('li').forEach(li=>{
    li.onclick=()=>{
      const id = li.dataset.id;
      const p = currentProducts.find(x=>''+x.id === ''+id);
      if (p){
        qInput.value = p.title;
        suggBox.style.display='none';
        // scroll to item
        const idx = currentProducts.findIndex(x=>x.id===p.id);
        currentPage = Math.floor(idx / pageSize) + 1;
        renderProductsPage();
        const itemEl = [...document.querySelectorAll('.product-item')][idx % pageSize];
        if (itemEl) itemEl.scrollIntoView({behavior:'smooth', block:'center'});
      }
    };
  });
}

/* ====== CARRUSEL WHATSAPP (MANTENIDO) ====== */
(function initWaCarousel(){
  const carousel = document.getElementById('waCarousel');
  const dotsBox = document.getElementById('waDots');
  const btns = document.querySelectorAll('.wa-btn:not([data-target])');
  if (!carousel || !dotsBox) return;

  const slides = Array.from(carousel.children);
  let idx = 0;

  // Crear dots
  slides.forEach((_,i)=>{
    const dot=document.createElement('button');
    dot.className='wa-dot'+(i===0?' active':'');
    dot.type='button';
    dot.addEventListener('click',()=>go(i));
    dotsBox.appendChild(dot);
  });

  function go(i){
    idx = (i+slides.length)%slides.length;
    carousel.style.transform = `translateX(-${idx*100}%)`;
    [...dotsBox.children].forEach((d,j)=>d.classList.toggle('active', j===idx));
  }

  btns.forEach(b=>{
    b.addEventListener('click',()=>{
      const dir = Number(b.dataset.dir||1);
      go(idx+dir);
    });
  });

  // Swipe táctil
  let startX=0;
  carousel.addEventListener('touchstart',e=>{ startX=e.touches[0].clientX; }, {passive:true});
  carousel.addEventListener('touchend',e=>{
    const dx = e.changedTouches[0].clientX - startX;
    if (Math.abs(dx)>40) go(idx + (dx<0?1:-1));
  });

  // Auto-advance opcional (desactivado).
  // setInterval(()=>go(idx+1), 6000);
})();

/* ====== INIT ====== */
function init(){
  categoryChipsInit();
  updateCartCount();
  loadBusinesses();
}
init();

/* ====== CHECKOUT ====== */
document.getElementById('checkoutForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  if (!cart.length) return alert('Tu carrito está vacío');
  const items = cart.map(c => ({ product_id: c.id, qty: c.qty }));
  const delivery = document.getElementById('deliveryChk').checked;
  const payload = {
    items,
    customer_name: document.getElementById('cname').value,
    customer_phone: document.getElementById('cphone').value,
    address: delivery ? document.getElementById('address').value : undefined,
    note: document.getElementById('cnote').value,
    delivery
  };
  const res = await API.post('/public/cart/checkout', payload);
  if (res.error){ alert(res.error); return; }
  alert('Pedido confirmado. Código de grupo: ' + res.group_id + '\nTotal: ' + (res.total_xaf||0).toLocaleString() + ' XAF');
  cart = []; saveCart(); closeCart();
});
</script>

<div class="modal-backdrop" id="productModal">
  <div class="modal">
    <div class="modal-header">
      <span id="modalTitle">Detalle del producto</span>
      <button class="modal-close" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-body">
      <img id="modalImg" src="" alt="Producto">
      <div class="price" id="modalPrice"></div>
      <div id="modalDesc"></div>
    </div>
    <div class="modal-footer">
      <button class="btn ghost" id="modalAddBtn">Añadir al carrito</button>
    </div>
  </div>
</div>
<script>
function openModal(id){
  API.get('/public/products/'+id).then(data=>{
    if(!data) return;
    document.getElementById('modalTitle').textContent=data.title||'Producto';
    document.getElementById('modalImg').src=data.image_url||'https://placehold.co/600x400';
    document.getElementById('modalPrice').textContent=(data.price_xaf?Number(data.price_xaf).toLocaleString()+' XAF':'');
    document.getElementById('modalDesc').textContent=data.description||'Sin descripción';
    document.getElementById('modalAddBtn').onclick=()=>{
      let cart=JSON.parse(localStorage.getItem('cart')||'[]');
      if(cart.length && cart[0].business_id!==data.business_id){
        if(!confirm('Tu carrito es de otro negocio. ¿Vaciar carrito?')) return;
        cart=[];
      }
      const exists=cart.find(x=>x.id==data.id);
      if(exists) exists.qty=Number(exists.qty||1)+1;
      else cart.push({id:data.id,title:data.title,price_xaf:data.price_xaf,image_url:data.image_url,category:data.category,qty:1,business_id:data.business_id});
      localStorage.setItem('cart',JSON.stringify(cart));
      alert('Producto añadido al carrito');
    };
    document.getElementById('productModal').style.display='flex';
  });
}
function closeModal(){document.getElementById('productModal').style.display='none';}
</script>

</body>
</html>

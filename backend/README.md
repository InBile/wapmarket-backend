# wapmarket — Backend (Railway)

Un único archivo `server.js` con API lista para producción.

## Variables (Railway → Variables)
- `DATABASE_URL` (de PostgreSQL en Railway)
- `ADMIN_SECRET` (elige uno fuerte)
- `CORS_ORIGINS` (coma separada, ej: `https://wapmarket.vercel.app,https://tu-dominio.com`)

## Deploy
1. Subir `backend/` a un repo e importar en Railway como servicio **Node.js**.
2. Añadir PostgreSQL en Railway.
3. Configurar variables anteriores.
4. Railway ejecuta `npm start`. La migración se corre automáticamente al arrancar.
5. Probar `GET /health`.

## Endpoints
- `POST /api/admin/businesses` (Bearer ADMIN_SECRET)
- `GET /api/admin/businesses` (Bearer ADMIN_SECRET)
- `POST /api/admin/businesses/:id/issue-key` (Bearer ADMIN_SECRET)
- `POST /api/products` (Bearer API_KEY + X-Business-Id)
- `PUT /api/products/:id` (Bearer API_KEY + X-Business-Id)
- `DELETE /api/products/:id` (Bearer API_KEY + X-Business-Id)
- `GET /api/public/products?q=&category=&location=&limit=&offset=`

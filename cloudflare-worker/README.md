# Transpol Files Worker (Cloudflare R2)

Este Worker expone un API de archivos para Transpol:

- `GET /files`
- `POST /files?name=...`
- `GET /files/:key`
- `DELETE /files/:key`

Todos los endpoints validan el token de Firebase Auth (`Bearer`) y separan archivos por usuario (`uid`).

## 1) Crear bucket en Cloudflare R2

1. Entra a Cloudflare Dashboard.
2. Ve a `R2 Object Storage`.
3. Crea un bucket con nombre `transpol-files` (o el que prefieras).

Si cambias el nombre, actualiza `bucket_name` en `wrangler.toml`.

## 2) Crear Worker

### Opcion A: Dashboard (sin terminal)

1. Ve a `Workers & Pages`.
2. Crea un Worker nuevo.
3. Copia el contenido de `src/index.js` en el editor del Worker.
4. En Settings del Worker:
   - Variables:
     - `FIREBASE_PROJECT_ID = transpol-ead50`
     - `ALLOWED_ORIGIN = https://TU_DOMINIO` (o `*` para pruebas)
   - Bindings > R2 Bucket:
     - Binding name: `MY_BUCKET`
     - Bucket: `transpol-files`
5. Deploy.

### Opcion B: CLI (recomendado)

Requisitos: Node.js y Wrangler.

```bash
cd cloudflare-worker
npm i -g wrangler
wrangler login
wrangler deploy
```

## 3) Configurar URL del Worker en Transpol

En `index.html`, antes del script principal, define:

```html
<script>
  window.TRANS_POL_FILES_API_BASE = "https://transpol-files.TU_SUBDOMINIO.workers.dev";
</script>
```

Tambien puedes usar un dominio propio.

## 4) Configurar CORS bien

En produccion, evita `*` y usa tu dominio exacto en `ALLOWED_ORIGIN`, por ejemplo:

- `https://transpol.app`
- `https://www.transpol.app`

Si usas Firebase Hosting preview o local, agrega esos orígenes según tu flujo.

## 5) Prueba funcional

1. Inicia sesion en Transpol.
2. Ve a `Almacenamiento de archivos`.
3. Sube archivo por boton.
4. Arrastra otro archivo a la zona de drop.
5. Verifica listado, descarga y borrar.

## Estructura de almacenamiento en R2

Cada usuario queda aislado en un prefijo propio:

- `UID_1/foto.png`
- `UID_1/reporte.pdf`
- `UID_2/notas.txt`

## Seguridad

- El frontend nunca ve claves secretas de R2.
- El Worker valida el ID token de Firebase contra JWKS de Google.
- Opcionalmente cruza `X-Transpol-Uid` para evitar mezclas de sesión.

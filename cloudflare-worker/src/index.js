const JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const TOKEN_STATE_PREFIX = "__external_tokens__/";
const EXTERNAL_UPLOAD_SECRET_FALLBACK = "FNBRJ3INF439F89FB39N8F9B38F8B893FDDGF67Fcnbjeicu6520vxznmx7328vs5";

let jwksCache = {
  expiresAt: 0,
  keysByKid: new Map()
};
const DEFAULT_MAX_TOTAL_BYTES = 10 * 1024 * 1024 * 1024;
const DEFAULT_EXTERNAL_EXPIRES_MINUTES = 30;
const DEFAULT_EXTERNAL_MAX_BYTES = 25 * 1024 * 1024;
const MAX_EXTERNAL_TOTAL_BYTES = 5 * 1024 * 1024 * 1024;
const FILE_RETENTION_MS = 3 * 24 * 60 * 60 * 1000;

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(env) });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === "GET" && path === "/external-upload") {
        return await externalUploadPage(request, env, url);
      }

      if (request.method === "POST" && path === "/external-upload") {
        return await externalUpload(request, env, url);
      }

      const { uid } = await requireAuth(request, env);
      const prefix = `${uid}/`;

      if (request.method === "POST" && path === "/external-upload-token") {
        return await createExternalUploadToken(request, env, uid);
      }

      if (request.method === "GET" && path === "/files") {
        return await listFiles(env, prefix);
      }

      if (request.method === "POST" && path === "/files") {
        return await uploadFile(request, env, prefix, url);
      }

      if (path.startsWith("/files/")) {
        const keyPart = path.slice("/files/".length);
        const decodedKey = decodeURIComponent(keyPart || "").trim();
        const fullKey = toObjectKey(prefix, decodedKey);

        if (request.method === "GET") {
          return await downloadFile(env, fullKey, decodedKey);
        }

        if (request.method === "DELETE") {
          return await deleteFile(env, fullKey);
        }
      }

      return json({ error: "Ruta no encontrada" }, 404, env);
    } catch (error) {
      const status = error.statusCode || 500;
      return json({ error: error.message || "Error interno" }, status, env);
    }
  }
};

async function listFiles(env, prefix) {
  const listing = await env.MY_BUCKET.list({
    prefix,
    include: ["httpMetadata", "customMetadata"]
  });
  const now = Date.now();
  const keptObjects = [];
  for (const obj of listing.objects) {
    const uploadedMs = obj.uploaded ? new Date(obj.uploaded).getTime() : 0;
    if (uploadedMs && uploadedMs + FILE_RETENTION_MS <= now) {
      await env.MY_BUCKET.delete(obj.key);
      continue;
    }
    keptObjects.push(obj);
  }
  const maxBytes = getMaxTotalBytes(env);
  const usedBytes = keptObjects.reduce((acc, obj) => acc + (obj.size || 0), 0);

  const files = keptObjects.map((obj) => ({
    key: obj.key.slice(prefix.length),
    name: obj.customMetadata?.name || obj.key.slice(prefix.length),
    size: obj.size,
    updatedAt: obj.uploaded?.toISOString?.() || null,
    createdAt: obj.uploaded?.toISOString?.() || null,
    expiresAt: obj.uploaded ? new Date(new Date(obj.uploaded).getTime() + FILE_RETENTION_MS).toISOString() : null
  }));

  return json({ files, usedBytes, maxBytes, remainingBytes: Math.max(0, maxBytes - usedBytes) }, 200, env);
}

async function uploadFile(request, env, prefix, url) {
  const rawName = (url.searchParams.get("name") || "").trim();
  if (!rawName) {
    throw httpError(400, "Falta el parametro name");
  }

  const safeName = sanitizeName(rawName);
  if (!safeName) {
    throw httpError(400, "Nombre de archivo invalido");
  }
  const incomingBytes = getIncomingSize(request);
  if (incomingBytes <= 0) {
    throw httpError(400, "No se pudo determinar el tamano del archivo");
  }
  const maxBytes = getMaxTotalBytes(env);
  const usage = await getUsageBytes(env, prefix);
  if (usage + incomingBytes > maxBytes) {
    const remaining = Math.max(0, maxBytes - usage);
    throw httpError(413, `Limite de almacenamiento excedido. Disponible: ${remaining} bytes`);
  }

  const objectKey = toObjectKey(prefix, safeName);
  const contentType = request.headers.get("content-type") || "application/octet-stream";

  await env.MY_BUCKET.put(objectKey, request.body, {
    httpMetadata: { contentType },
    customMetadata: { name: safeName }
  });

  return json({ ok: true, key: safeName }, 200, env);
}

async function createExternalUploadToken(request, env, uid) {
  const secret = getExternalUploadSecret(env);
  if (!secret) {
    throw httpError(500, "Falta EXTERNAL_UPLOAD_SECRET en el Worker");
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const expiresMinutesRaw = Number(body.expiresMinutes || DEFAULT_EXTERNAL_EXPIRES_MINUTES);
  const expiresMinutes = clamp(Math.floor(expiresMinutesRaw), 5, 1440);
  const maxBytesRaw = Number(body.maxBytes || DEFAULT_EXTERNAL_MAX_BYTES);
  const maxBytes = clamp(Math.floor(maxBytesRaw), 1, MAX_EXTERNAL_TOTAL_BYTES);
  const subpath = sanitizeSubpath(body.subpath || "");

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    v: 1,
    uid,
    exp: now + expiresMinutes * 60,
    maxBytes,
    subpath,
    nonce: randomId(18)
  };

  const token = await signExternalToken(payload, secret);
  const uploadUrl = `${new URL(request.url).origin}/external-upload?token=${encodeURIComponent(token)}`;
  return json({ token, uploadUrl, expiresMinutes, maxBytes }, 200, env);
}

async function externalUpload(request, env, url) {
  const token = (url.searchParams.get("token") || "").trim();
  if (!token) {
    throw httpError(401, "Falta token temporal");
  }

  const secret = getExternalUploadSecret(env);
  if (!secret) {
    throw httpError(500, "Falta EXTERNAL_UPLOAD_SECRET en el Worker");
  }

  const payload = await verifyExternalToken(token, secret);
  const tokenState = await getTokenState(env, payload);

  const contentType = request.headers.get("content-type") || "";
  const isMultipart = contentType.toLowerCase().includes("multipart/form-data");
  if (isMultipart) {
    return await externalUploadFromForm(request, env, payload, tokenState);
  }
  return await externalUploadFromRaw(request, env, url, payload, tokenState);
}

async function externalUploadFromRaw(request, env, url, payload, tokenState) {
  const rawName = (url.searchParams.get("name") || "").trim();
  if (!rawName) {
    throw httpError(400, "Falta el parametro name");
  }
  const safeName = sanitizeName(rawName);
  if (!safeName) {
    throw httpError(400, "Nombre de archivo invalido");
  }
  const incomingBytes = getIncomingSize(request);
  if (incomingBytes <= 0) {
    throw httpError(400, "No se pudo determinar el tamano del archivo");
  }
  const objectKey = await ensureExternalCapacity(payload, safeName, incomingBytes, tokenState);
  const prefix = `${payload.uid}/`;
  const maxTotal = getMaxTotalBytes(env);
  const usage = await getUsageBytes(env, prefix);
  if (usage + incomingBytes > maxTotal) {
    throw httpError(413, "No hay espacio suficiente en la cuenta");
  }
  const reqType = request.headers.get("content-type") || "application/octet-stream";
  await env.MY_BUCKET.put(objectKey, request.body, {
    httpMetadata: { contentType: reqType },
    customMetadata: { name: safeName, external: "1" }
  });
  await updateTokenState(env, payload, tokenState.usedBytes + incomingBytes);
  return json({ ok: true, key: objectKey.split("/").slice(1).join("/") }, 200, env);
}

async function externalUploadFromForm(request, env, payload, tokenState) {
  const form = await request.formData();
  const rawFiles = form.getAll("file");
  const files = rawFiles.filter((item) => item && typeof item !== "string");
  if (!files.length) {
    throw httpError(400, "Debes adjuntar al menos un archivo");
  }

  let totalIncomingBytes = 0;
  const parsed = [];
  for (const item of files) {
    const safeName = sanitizeName(item.name || "archivo.bin");
    if (!safeName) {
      throw httpError(400, "Nombre de archivo invalido");
    }
    const incomingBytes = Number(item.size || 0);
    if (incomingBytes <= 0) {
      throw httpError(400, "Archivo vacio o invalido");
    }
    totalIncomingBytes += incomingBytes;
    parsed.push({ safeName, incomingBytes, file: item });
  }

  if (tokenState.usedBytes + totalIncomingBytes > payload.maxBytes) {
    throw httpError(413, "El total de archivos excede el tamano maximo permitido por el token");
  }

  const prefix = `${payload.uid}/`;
  const maxTotal = getMaxTotalBytes(env);
  const usage = await getUsageBytes(env, prefix);
  if (usage + totalIncomingBytes > maxTotal) {
    throw httpError(413, "No hay espacio suficiente en la cuenta");
  }

  const uploadedNames = [];
  for (const item of parsed) {
    const objectKey = buildExternalObjectKey(payload, item.safeName);
    await env.MY_BUCKET.put(objectKey, item.file.stream(), {
      httpMetadata: { contentType: item.file.type || "application/octet-stream" },
      customMetadata: { name: item.safeName, external: "1" }
    });
    uploadedNames.push(item.safeName);
  }

  await updateTokenState(env, payload, tokenState.usedBytes + totalIncomingBytes);
  return new Response(externalUploadSuccessHtml(uploadedNames), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...corsHeaders(env)
    }
  });
}

async function ensureExternalCapacity(payload, safeName, incomingBytes, tokenState) {
  if (incomingBytes > payload.maxBytes || tokenState.usedBytes + incomingBytes > payload.maxBytes) {
    throw httpError(413, "Archivo excede el tamano maximo total permitido por el token");
  }
  return buildExternalObjectKey(payload, safeName);
}

function buildExternalObjectKey(payload, safeName) {
  const folder = payload.subpath ? `${payload.subpath}/` : "";
  return `${payload.uid}/${folder}${safeName}`;
}

async function externalUploadPage(request, env, url) {
  const token = (url.searchParams.get("token") || "").trim();
  if (!token) {
    return new Response(externalUploadErrorHtml("Falta token temporal"), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8", ...corsHeaders(env) }
    });
  }
  try {
    const payload = await verifyExternalToken(token, getExternalUploadSecret(env));
    return new Response(externalUploadFormHtml(token, payload.maxBytes, payload.exp), {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8", ...corsHeaders(env) }
    });
  } catch (error) {
    return new Response(externalUploadErrorHtml(error.message || "Token invalido"), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8", ...corsHeaders(env) }
    });
  }
}

async function downloadFile(env, fullKey, fallbackName) {
  const object = await env.MY_BUCKET.get(fullKey);
  if (!object) {
    throw httpError(404, "Archivo no encontrado");
  }

  const filename = object.customMetadata?.name || fallbackName || "archivo";
  const headers = new Headers(corsHeaders(env));
  headers.set("content-type", object.httpMetadata?.contentType || "application/octet-stream");
  headers.set("content-disposition", contentDisposition(filename));

  return new Response(object.body, {
    status: 200,
    headers
  });
}

async function deleteFile(env, fullKey) {
  await env.MY_BUCKET.delete(fullKey);
  return json({ ok: true }, 200, env);
}

function sanitizeName(name) {
  return name
    .replace(/\\/g, "/")
    .split("/")
    .filter(Boolean)
    .join("_")
    .replace(/[\r\n\t]/g, "")
    .trim();
}

function sanitizeSubpath(value) {
  const clean = String(value)
    .replace(/\\/g, "/")
    .split("/")
    .filter(Boolean)
    .join("/")
    .replace(/[\r\n\t]/g, "")
    .trim();
  if (!clean) return "";
  if (clean.includes("..")) return "";
  return clean;
}

function getExternalUploadSecret(env) {
  return env.EXTERNAL_UPLOAD_SECRET || EXTERNAL_UPLOAD_SECRET_FALLBACK;
}

function getIncomingSize(request) {
  const header = request.headers.get("content-length") || "";
  const size = Number(header);
  return Number.isFinite(size) ? size : 0;
}

function getMaxTotalBytes(env) {
  const raw = Number(env.MAX_TOTAL_BYTES || DEFAULT_MAX_TOTAL_BYTES);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_MAX_TOTAL_BYTES;
  return Math.floor(raw);
}

async function getUsageBytes(env, prefix) {
  let cursor = undefined;
  let total = 0;
  do {
    const listing = await env.MY_BUCKET.list({ prefix, cursor });
    for (const obj of listing.objects) {
      total += obj.size || 0;
    }
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
  return total;
}

async function signExternalToken(payload, secret) {
  const jsonPayload = JSON.stringify(payload);
  const encodedPayload = uint8ToBase64url(textToUint8(jsonPayload));
  const sigBytes = await hmacSign(textToUint8(secret), textToUint8(encodedPayload));
  return `${encodedPayload}.${uint8ToBase64url(sigBytes)}`;
}

async function verifyExternalToken(token, secret) {
  const [encodedPayload, encodedSig] = token.split(".");
  if (!encodedPayload || !encodedSig) {
    throw httpError(401, "Token temporal invalido");
  }

  const expected = await hmacSign(textToUint8(secret), textToUint8(encodedPayload));
  const received = base64urlToUint8(encodedSig);
  if (!timingSafeEqual(expected, received)) {
    throw httpError(401, "Firma de token invalida");
  }

  const payload = jsonParse(base64urlToText(encodedPayload));
  const now = Math.floor(Date.now() / 1000);
  if (!payload?.uid || typeof payload.uid !== "string") {
    throw httpError(401, "Token temporal invalido");
  }
  if (!payload?.nonce || typeof payload.nonce !== "string") {
    throw httpError(401, "Token temporal invalido");
  }
  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw httpError(401, "Token temporal expirado");
  }
  if (typeof payload.maxBytes !== "number" || payload.maxBytes <= 0) {
    throw httpError(401, "Token temporal invalido");
  }
  payload.subpath = sanitizeSubpath(payload.subpath || "");
  return payload;
}

async function getTokenState(env, payload) {
  const stateKey = `${TOKEN_STATE_PREFIX}${payload.uid}/${payload.nonce}.json`;
  const existing = await env.MY_BUCKET.get(stateKey);
  if (!existing) {
    return { usedBytes: 0 };
  }
  try {
    const state = await existing.json();
    return { usedBytes: Number(state?.usedBytes || 0) };
  } catch {
    return { usedBytes: 0 };
  }
}

async function updateTokenState(env, payload, usedBytes) {
  const stateKey = `${TOKEN_STATE_PREFIX}${payload.uid}/${payload.nonce}.json`;
  const body = JSON.stringify({ usedAt: new Date().toISOString(), exp: payload.exp, usedBytes });
  await env.MY_BUCKET.put(stateKey, body, { httpMetadata: { contentType: "application/json" } });
}

async function hmacSign(secretBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(signature);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a[i] ^ b[i];
  }
  return out === 0;
}

function randomId(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return uint8ToBase64url(bytes);
}

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function toObjectKey(prefix, clientKey) {
  const safe = sanitizeName(clientKey);
  if (!safe) {
    throw httpError(400, "Clave de archivo invalida");
  }
  return `${prefix}${safe}`;
}

async function requireAuth(request, env) {
  const authHeader = request.headers.get("authorization") || "";
  const [, token] = authHeader.match(/^Bearer\s+(.+)$/i) || [];
  if (!token) {
    throw httpError(401, "Falta token de autorizacion");
  }

  const projectId = env.FIREBASE_PROJECT_ID;
  if (!projectId) {
    throw httpError(500, "Falta FIREBASE_PROJECT_ID en el Worker");
  }

  const payload = await verifyFirebaseToken(token, projectId);
  const clientUid = (request.headers.get("x-transpol-uid") || "").trim();
  if (clientUid && clientUid !== payload.user_id) {
    throw httpError(403, "UID no coincide");
  }

  return { uid: payload.user_id };
}

async function verifyFirebaseToken(token, projectId) {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw httpError(401, "Token invalido");
  }

  const header = jsonParse(base64urlToText(encodedHeader));
  const payload = jsonParse(base64urlToText(encodedPayload));

  if (header.alg !== "RS256" || !header.kid) {
    throw httpError(401, "Cabecera JWT invalida");
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw httpError(401, "Token expirado");
  }

  if (payload.aud !== projectId) {
    throw httpError(401, "Audience invalida");
  }

  if (payload.iss !== `https://securetoken.google.com/${projectId}`) {
    throw httpError(401, "Issuer invalido");
  }

  if (!payload.sub || typeof payload.sub !== "string") {
    throw httpError(401, "UID invalido en token");
  }

  const publicKey = await getPublicKeyByKid(header.kid);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    base64urlToUint8(encodedSignature),
    textToUint8(`${encodedHeader}.${encodedPayload}`)
  );

  if (!valid) {
    throw httpError(401, "Firma JWT invalida");
  }

  payload.user_id = payload.user_id || payload.sub;
  return payload;
}

async function getPublicKeyByKid(kid) {
  const now = Date.now();
  if (now > jwksCache.expiresAt || !jwksCache.keysByKid.size) {
    await refreshJwks();
  }

  const jwk = jwksCache.keysByKid.get(kid);
  if (!jwk) {
    await refreshJwks();
  }

  const nextJwk = jwksCache.keysByKid.get(kid);
  if (!nextJwk) {
    throw httpError(401, "No se encontro clave publica para token");
  }

  return crypto.subtle.importKey(
    "jwk",
    nextJwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );
}

async function refreshJwks() {
  const res = await fetch(JWKS_URL);
  if (!res.ok) {
    throw httpError(503, "No se pudo obtener JWKS de Google");
  }

  const body = await res.json();
  const keys = Array.isArray(body.keys) ? body.keys : [];
  const map = new Map();
  for (const key of keys) {
    if (key.kid) {
      map.set(key.kid, key);
    }
  }

  const cacheControl = res.headers.get("cache-control") || "";
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/);
  const maxAgeSeconds = maxAgeMatch ? Number(maxAgeMatch[1]) : 300;

  jwksCache = {
    expiresAt: Date.now() + maxAgeSeconds * 1000,
    keysByKid: map
  };
}

function corsHeaders(env) {
  const origin = env.ALLOWED_ORIGIN || "*";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
    "access-control-allow-headers": "Authorization,Content-Type,X-Transpol-Uid",
    "access-control-max-age": "86400"
  };
}

function contentDisposition(filename) {
  const encoded = encodeRFC5987(filename);
  return `attachment; filename*=UTF-8''${encoded}`;
}

function externalUploadFormHtml(token, maxBytes, exp) {
  const maxMb = Math.max(1, Math.floor(maxBytes / (1024 * 1024)));
  const expText = formatCanaryDate(exp * 1000);
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Subida segura</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Arial;background:linear-gradient(145deg,#ecf5ff,#dcefff);color:#10203a}
.wrap{max-width:640px;margin:0 auto;padding:22px}
.card{background:rgba(255,255,255,.7);border:1px solid rgba(255,255,255,.8);border-radius:16px;padding:18px;box-shadow:0 18px 40px rgba(10,28,60,.14)}
h1{margin:0 0 8px;font-size:22px}
p{margin:8px 0;color:#3b4f73}
.meta{font-size:14px;background:#f4f9ff;border:1px solid #d7e9ff;padding:10px;border-radius:10px}
.filepick{display:block;width:100%;max-width:100%;text-align:center;margin-top:12px;padding:12px;border:none;border-radius:10px;background:#bfe8ff;color:#0b3f7a;font-weight:700;cursor:pointer}
.filename{margin-top:8px;font-size:14px;color:#335}
input[type=file]{display:none}
button{margin-top:12px;width:100%;padding:12px;border:none;border-radius:10px;background:#0b6bff;color:#fff;font-weight:700;cursor:pointer}
button[disabled]{opacity:.6;cursor:not-allowed}
.progress-list{display:grid;gap:8px;margin-top:12px}
.progress-item{display:grid;gap:6px;padding:10px 12px;border-radius:12px;background:#f7fbff;border:1px solid #d7e9ff}
.progress-head{display:flex;justify-content:space-between;gap:10px;font-size:13px}
.progress-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.progress-track{width:100%;height:10px;border-radius:999px;background:#dceeff;overflow:hidden}
.progress-fill{width:0%;height:100%;border-radius:999px;background:linear-gradient(90deg,#0bc5ff,#0b6bff)}
.error{margin-top:10px;color:#8d2020;font-size:14px}
.success{margin-top:10px;color:#14532d;font-size:14px;background:#eefcf2;border:1px solid #cdeed7;padding:10px;border-radius:10px}
.done-state{display:grid;gap:10px}
</style></head><body><div class="wrap"><div class="card">
<h1>Subida segura de archivo</h1>
<p>Este enlace permite una unica sesion de subida.</p>
<div class="meta">Tamano maximo total: ${maxMb} MB<br>Caduca el: ${expText} (hora Canarias)</div>
<form id="upload-form" novalidate>
  <label class="filepick" for="external-file">Seleccionar archivo</label>
  <input id="external-file" type="file" name="file" multiple>
  <div id="file-name" class="filename">Ningun archivo seleccionado</div>
  <div id="progress-list" class="progress-list" hidden></div>
  <div id="error-box" class="error" hidden></div>
  <div id="success-box" class="success" hidden></div>
  <button type="submit">Subir archivos</button>
</form>
</div></div>
<script>
const input=document.getElementById('external-file');
const label=document.getElementById('file-name');
const form=document.getElementById('upload-form');
const progressList=document.getElementById('progress-list');
const errorBox=document.getElementById('error-box');
const successBox=document.getElementById('success-box');
const submitBtn=form.querySelector('button');
let selectedFiles = [];
input.addEventListener('change',()=>{
  const list=Array.from(input.files||[]);
  if(!list.length){return;}
  for(const file of list){
    const key = file.name + '::' + file.size + '::' + file.lastModified;
    if (!selectedFiles.some((item)=> (item.name + '::' + item.size + '::' + item.lastModified) === key)) {
      selectedFiles.push(file);
    }
  }
  input.value = '';
  renderSelection();
});

function renderSelection(){
  if(!selectedFiles.length){
    label.textContent='Ningun archivo seleccionado';
    return;
  }
  const total=selectedFiles.reduce((a,f)=>a+(f.size||0),0);
  label.textContent=selectedFiles.length+' archivo(s) · '+(total/1024/1024).toFixed(2)+' MB';
}

form.addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  errorBox.hidden = true;
  errorBox.textContent = '';
  successBox.hidden = true;
  successBox.textContent = '';
  const files = selectedFiles.slice();
  if(!files.length){
    errorBox.hidden = false;
    errorBox.textContent = 'Selecciona al menos un archivo.';
    return;
  }
  const total = files.reduce((acc, file)=>acc + (file.size || 0), 0);
  if (total > ${Math.floor(maxBytes)}) {
    errorBox.hidden = false;
    errorBox.textContent = 'El total supera el limite permitido por el enlace.';
    return;
  }
  progressList.innerHTML = '';
  progressList.hidden = false;
  submitBtn.disabled = true;
  try{
    const uploadedNames = [];
    for (const file of files) {
      const row = createProgressRow(file.name);
      progressList.appendChild(row);
      await uploadOne(file, row);
      uploadedNames.push(file.name);
    }
    successBox.hidden = false;
    successBox.textContent = uploadedNames.length === 1
      ? 'Archivo subido correctamente.'
      : uploadedNames.length + ' archivos subidos correctamente.';
    form.innerHTML = '<div class="done-state"><div class="success">' + successBox.textContent + '</div></div>';
  }catch(err){
    errorBox.hidden = false;
    errorBox.textContent = err.message || 'No se pudo completar la subida.';
  } finally {
    if (submitBtn && document.body.contains(submitBtn)) {
      submitBtn.disabled = false;
    }
  }
});

function createProgressRow(name){
  const row = document.createElement('div');
  row.className = 'progress-item';
  row.innerHTML = '<div class="progress-head"><span class="progress-name"></span><span class="progress-value">0%</span></div><div class="progress-track"><div class="progress-fill"></div></div>';
  row.querySelector('.progress-name').textContent = name;
  return row;
}

function setProgress(row, percent){
  const safe = Math.max(0, Math.min(100, Math.round(percent)));
  row.querySelector('.progress-value').textContent = safe + '%';
  row.querySelector('.progress-fill').style.width = safe + '%';
}

function uploadOne(file, row){
  return new Promise((resolve, reject)=>{
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/external-upload?token=${encodeURIComponent(token)}&name=' + encodeURIComponent(file.name));
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
    xhr.upload.onprogress = (event)=>{
      if(!event.lengthComputable) return;
      setProgress(row, (event.loaded / event.total) * 100);
    };
    xhr.onload = ()=>{
      if (xhr.status >= 200 && xhr.status < 300) {
        setProgress(row, 100);
        resolve();
        return;
      }
      try{
        const data = JSON.parse(xhr.responseText || '{}');
        reject(new Error(data.error || ('Error ' + xhr.status)));
      }catch{
        reject(new Error('Error ' + xhr.status));
      }
    };
    xhr.onerror = ()=>reject(new Error('Fallo de red durante la subida.'));
    xhr.send(file);
  });
}
</script>
</body></html>`;
}

function externalUploadSuccessHtml(names) {
  const list = Array.isArray(names) ? names : [String(names || "")];
  const items = list.slice(0, 6).map((n)=>`<li>${escapeHtml(n)}</li>`).join("");
  const extra = list.length > 6 ? `<p>y ${list.length - 6} mas...</p>` : "";
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Subida completada</title>
<style>body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Arial;background:#eaf4ff;color:#0f2848}.wrap{max-width:560px;margin:40px auto;padding:20px}.ok{background:#fff;border:1px solid #d3e7ff;border-radius:14px;padding:18px}</style>
</head><body><div class="wrap"><div class="ok"><h2>Archivos recibidos</h2><ul>${items}</ul>${extra}</div></div></body></html>`;
}

function externalUploadErrorHtml(message) {
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Error</title>
<style>body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Arial;background:#fff2f2;color:#5f1111}.wrap{max-width:560px;margin:40px auto;padding:20px}.err{background:#fff;border:1px solid #ffc9c9;border-radius:14px;padding:18px}</style>
</head><body><div class="wrap"><div class="err"><h2>No se pudo subir</h2><p>${escapeHtml(message || "Error")}</p></div></div></body></html>`;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatCanaryDate(ms) {
  return new Intl.DateTimeFormat("es-ES", {
    timeZone: "Atlantic/Canary",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(ms));
}

function encodeRFC5987(value) {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function json(payload, status, env) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...corsHeaders(env)
    }
  });
}

function httpError(statusCode, message) {
  return { statusCode, message };
}

function jsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw httpError(401, "JWT malformado");
  }
}

function base64urlToText(input) {
  return new TextDecoder().decode(base64urlToUint8(input));
}

function textToUint8(input) {
  return new TextEncoder().encode(input);
}

function base64urlToUint8(input) {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((input.length + 3) % 4);
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

function uint8ToBase64url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

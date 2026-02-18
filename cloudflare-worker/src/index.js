const JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

let jwksCache = {
  expiresAt: 0,
  keysByKid: new Map()
};
const DEFAULT_MAX_TOTAL_BYTES = 10 * 1024 * 1024 * 1024;

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(env) });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      const { uid } = await requireAuth(request, env);
      const prefix = `${uid}/`;

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
  const maxBytes = getMaxTotalBytes(env);
  const usedBytes = listing.objects.reduce((acc, obj) => acc + (obj.size || 0), 0);

  const files = listing.objects.map((obj) => ({
    key: obj.key.slice(prefix.length),
    name: obj.customMetadata?.name || obj.key.slice(prefix.length),
    size: obj.size,
    updatedAt: obj.uploaded?.toISOString?.() || null
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

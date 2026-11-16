import { generateRandomId } from '../utils/crypto.js';
import { validateImageUpload } from '../validators/schemas.js';
import {
  ALLOWED_ASSET_FOLDERS,
  ALLOWED_IMAGE_MIME_TYPES,
  MAX_IMAGE_SIZE_BYTES,
  MAX_JSON_UPLOAD_BYTES,
  MAX_MULTIPART_BODY_BYTES,
} from '../config/constants.js';

const EXTENSION_BY_MIME = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
};

const ALLOWED_FOLDERS = new Set(ALLOWED_ASSET_FOLDERS);
const STRICT_ASSET_KEY_PATTERN = /^(portfolio|services|team|general)\/[a-zA-Z0-9._-]+$/;

function sanitizeFolder(folder = 'portfolio') {
  const cleaned = String(folder || 'portfolio')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_-]/g, '');
  return ALLOWED_FOLDERS.has(cleaned) ? cleaned : 'portfolio';
}

export function normalizeAssetKey(keyOrUrl) {
  if (!keyOrUrl || typeof keyOrUrl !== 'string') return '';
  let key = keyOrUrl.trim();
  if (key.includes('%')) {
    try {
      key = decodeURIComponent(key);
    } catch {
      return '';
    }
  }
  const fullUrlMatch = /^https?:\/\/[^/]+(\/api\/v1\/(?:uploads|assets)\/.+)$/i.exec(key);
  if (fullUrlMatch) {
    key = fullUrlMatch[1];
  }
  for (const prefix of ['/api/v1/uploads/', '/api/v1/assets/']) {
    if (key.startsWith(prefix)) {
      key = key.slice(prefix.length);
      break;
    }
  }
  key = key.replace(/^\/+/, '');
  if (!key || key.includes('..') || key.includes('\\') || /[\u0000-\u001F\u007F]/.test(key)) {
    return '';
  }
  if (!STRICT_ASSET_KEY_PATTERN.test(key)) {
    return '';
  }
  return key;
}

function decodeBase64DataUrl(dataUrl) {
  const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(String(dataUrl).trim());
  if (!match) return null;
  const mimeType = match[1].toLowerCase();
  const base64Data = match[2];
  const maxEncodedChars = Math.ceil((MAX_IMAGE_SIZE_BYTES * 4) / 3) + 16;
  if (base64Data.length > maxEncodedChars) {
    const err = new Error(
      `Image file exceeds maximum allowed size of ${Math.round(MAX_IMAGE_SIZE_BYTES / (1024 * 1024))}MB.`
    );
    err.status = 413;
    err.code = 'PAYLOAD_TOO_LARGE';
    throw err;
  }
  try {
    const binary = atob(base64Data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return { mimeType, bytes };
  } catch {
    return null;
  }
}

/**
 * Uploads a validated image to Cloudflare R2 (`env.ASSETS_BUCKET`) and returns the public path.
 * Supports both `multipart/form-data` File uploads and JSON `{ dataUrl, fileName, folder, replaceKey }` uploads.
 */
export async function uploadImageToR2(request, env, defaultFolder = 'portfolio') {
  if (!env?.ASSETS_BUCKET || typeof env.ASSETS_BUCKET.put !== 'function') {
    const err = new Error('R2 Storage bucket binding (ASSETS_BUCKET) is not configured.');
    err.status = 503;
    err.code = 'STORAGE_UNAVAILABLE';
    throw err;
  }

  const contentType = request.headers.get('content-type') || '';
  const contentLengthHeader = request.headers.get('content-length');
  const declaredBytes = contentLengthHeader ? Number.parseInt(contentLengthHeader, 10) : 0;
  let mimeType = '';
  let bytes = null;
  let folder = sanitizeFolder(defaultFolder);
  let replaceKey = '';

  if (contentType.includes('multipart/form-data')) {
    if (Number.isFinite(declaredBytes) && declaredBytes > MAX_MULTIPART_BODY_BYTES) {
      const err = new Error('Uploaded image payload exceeds maximum allowed size.');
      err.status = 413;
      err.code = 'PAYLOAD_TOO_LARGE';
      throw err;
    }
    let formData;
    try {
      formData = await request.formData();
    } catch {
      const err = new Error('Malformed multipart/form-data upload payload.');
      err.status = 400;
      err.code = 'INVALID_MULTIPART_PAYLOAD';
      throw err;
    }
    const file = formData.get('file') || formData.get('image');
    if (!file || typeof file.arrayBuffer !== 'function') {
      const err = new Error('No image file found in multipart upload.');
      err.status = 400;
      err.code = 'MISSING_FILE';
      throw err;
    }
    if (Number.isFinite(file.size) && file.size > MAX_IMAGE_SIZE_BYTES) {
      const err = new Error(
        `Image file exceeds maximum allowed size of ${Math.round(MAX_IMAGE_SIZE_BYTES / (1024 * 1024))}MB.`
      );
      err.status = 413;
      err.code = 'PAYLOAD_TOO_LARGE';
      throw err;
    }
    const rawFolder = formData.get('folder') || formData.get('entityType');
    if (rawFolder) {
      folder = sanitizeFolder(rawFolder);
    }
    const rawReplaceKey = formData.get('replaceKey');
    if (rawReplaceKey !== null && rawReplaceKey !== undefined && String(rawReplaceKey).trim()) {
      replaceKey = normalizeAssetKey(String(rawReplaceKey));
      if (!replaceKey) {
        const err = new Error('Invalid replaceKey specified for image upload.');
        err.status = 400;
        err.code = 'INVALID_ASSET_KEY';
        throw err;
      }
    }
    mimeType = (file.type || '').toLowerCase();
    const buffer = await file.arrayBuffer();
    bytes = new Uint8Array(buffer);
  } else {
    if (Number.isFinite(declaredBytes) && declaredBytes > MAX_JSON_UPLOAD_BYTES) {
      const err = new Error('Uploaded image JSON payload exceeds maximum allowed size.');
      err.status = 413;
      err.code = 'PAYLOAD_TOO_LARGE';
      throw err;
    }
    const rawText = await request.text().catch(() => '');
    if (rawText.length > MAX_JSON_UPLOAD_BYTES) {
      const err = new Error('Uploaded image JSON payload exceeds maximum allowed size.');
      err.status = 413;
      err.code = 'PAYLOAD_TOO_LARGE';
      throw err;
    }
    let body = {};
    try {
      body = rawText ? JSON.parse(rawText) : {};
    } catch {
      const err = new Error('Malformed JSON upload payload.');
      err.status = 400;
      err.code = 'INVALID_JSON_PAYLOAD';
      throw err;
    }
    let rawDataUrl = body?.dataUrl || body?.data_url || '';
    const rawBase64 = body?.base64Data || body?.base64_data || body?.base64 || '';
    const explicitMime = String(body?.mimeType || body?.mime_type || 'image/png').toLowerCase();

    if (!rawDataUrl && rawBase64) {
      rawDataUrl = rawBase64.startsWith('data:')
        ? rawBase64
        : `data:${explicitMime};base64,${rawBase64}`;
    }

    if (!rawDataUrl) {
      const err = new Error('Please provide a valid image file or dataUrl.');
      err.status = 400;
      err.code = 'MISSING_FILE';
      throw err;
    }
    const rawFolder = body.folder || body.entityType;
    if (rawFolder) {
      folder = sanitizeFolder(rawFolder);
    }
    const rawReplaceKey = body.replaceKey || body.replace_key;
    if (rawReplaceKey !== undefined && rawReplaceKey !== null && String(rawReplaceKey).trim()) {
      replaceKey = normalizeAssetKey(String(rawReplaceKey));
      if (!replaceKey) {
        const err = new Error('Invalid replaceKey specified for image upload.');
        err.status = 400;
        err.code = 'INVALID_ASSET_KEY';
        throw err;
      }
    }
    const decoded = decodeBase64DataUrl(rawDataUrl);
    if (!decoded) {
      const err = new Error('Malformed base64 image dataUrl.');
      err.status = 400;
      err.code = 'INVALID_DATA_URL';
      throw err;
    }
    mimeType = decoded.mimeType;
    bytes = decoded.bytes;
  }

  const validation = validateImageUpload({
    mimeType,
    sizeBytes: bytes.byteLength,
    bytes,
  });

  if (!validation.isValid) {
    const err = new Error(validation.error);
    err.status = 400;
    err.code = 'INVALID_IMAGE_UPLOAD';
    throw err;
  }

  const ext = EXTENSION_BY_MIME[mimeType] || 'jpg';
  const key = `${folder}/${generateRandomId('img')}.${ext}`;

  try {
    await env.ASSETS_BUCKET.put(key, bytes, {
      httpMetadata: {
        contentType: mimeType,
      },
    });
  } catch (r2Err) {
    const err = new Error(`Failed to store uploaded image in R2 object storage: ${r2Err?.message || 'R2 put failed'}`);
    err.status = 502;
    err.code = 'R2_STORAGE_ERROR';
    throw err;
  }

  // Best-effort cleanup of replaced asset if replaceKey was provided
  let replacedKey = null;
  if (replaceKey && replaceKey !== key && typeof env.ASSETS_BUCKET.delete === 'function') {
    await env.ASSETS_BUCKET.delete(replaceKey).catch(() => {});
    replacedKey = replaceKey;
  }

  const publicPath = `/api/v1/uploads/${key}`;
  return {
    id: key,
    key,
    url: publicPath,
    publicUrl: publicPath,
    mimeType,
    sizeBytes: bytes.byteLength,
    replacedKey,
  };
}

/**
 * Deletes an uploaded image from Cloudflare R2 (`env.ASSETS_BUCKET`).
 */
export async function deleteImageFromR2(env, keyOrUrl) {
  if (!env?.ASSETS_BUCKET || typeof env.ASSETS_BUCKET.delete !== 'function') {
    const err = new Error('R2 Storage bucket binding (ASSETS_BUCKET) is not configured.');
    err.status = 503;
    err.code = 'STORAGE_UNAVAILABLE';
    throw err;
  }

  const key = normalizeAssetKey(keyOrUrl);
  if (!key) {
    const err = new Error('A valid R2 asset key or URL is required for deletion.');
    err.status = 400;
    err.code = 'INVALID_ASSET_KEY';
    throw err;
  }

  try {
    await env.ASSETS_BUCKET.delete(key);
    return key;
  } catch (r2Err) {
    const err = new Error(`Failed to delete asset from R2 object storage: ${r2Err?.message || 'R2 delete failed'}`);
    err.status = 502;
    err.code = 'R2_STORAGE_ERROR';
    throw err;
  }
}

/**
 * Serves an uploaded image from Cloudflare R2 (`env.ASSETS_BUCKET`).
 */
export async function serveImageFromR2(env, keyOrUrl) {
  if (!env?.ASSETS_BUCKET || typeof env.ASSETS_BUCKET.get !== 'function') {
    const err = new Error('R2 Storage bucket binding (ASSETS_BUCKET) is not configured.');
    err.status = 503;
    err.code = 'STORAGE_UNAVAILABLE';
    throw err;
  }

  const key = normalizeAssetKey(keyOrUrl);
  if (!key) {
    return null;
  }

  let object;
  try {
    object = await env.ASSETS_BUCKET.get(key);
  } catch (r2Err) {
    const err = new Error(`Failed to read asset from R2 object storage: ${r2Err?.message || 'R2 get failed'}`);
    err.status = 502;
    err.code = 'R2_STORAGE_ERROR';
    throw err;
  }

  if (!object) {
    return null;
  }

  const rawContentType = String(object.httpMetadata?.contentType || 'image/jpeg').toLowerCase();
  const contentType = ALLOWED_IMAGE_MIME_TYPES.includes(rawContentType)
    ? rawContentType
    : 'image/jpeg';
  const body = object.body || (await object.arrayBuffer());
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'public, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy':
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      'Cross-Origin-Resource-Policy': 'cross-origin',
    },
  });
}

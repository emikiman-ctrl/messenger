import { getStore } from "@netlify/blobs";
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCb);

const ROOM_RE = /^[\p{L}\p{N} _-]{1,30}$/u;
const NAME_RE = /^[\p{L}\p{N} _.-]{1,30}$/u;
const MAX_TEXT = 1000;
const INITIAL_LIMIT = 60;
const MAX_MEDIA = 4 * 1024 * 1024; // Netlify functions accept ~6 MB requests (less after encoding)
const MEDIA_TYPES = /^(image\/(jpeg|png|gif|webp)|video\/(mp4|webm|quicktime)|audio\/(webm|mp4|mpeg|ogg|aac|x-m4a))$/;

/* Key layout (all user-controlled parts are hex, so keys only contain [0-9a-f/]):
   m2/<hex conv>/<id>        message            (conv = room name, or "dm:" + a + "|" + b)
   r2/<hex room>             public room exists
   u3/<hex lowerName>        user { name, salt, hash }
   s3/<token>                session { name }
   d3/<hex lower>/<hex lower> DM index entry { with }
   f3/<id>                   media bytes (metadata: mime)                                  */

const hex = (str) => Buffer.from(str, "utf8").toString("hex");
const unhex = (h) => Buffer.from(h, "hex").toString("utf8");
const store = () => getStore({ name: "chat", consistency: "strong" });

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
const fail = (msg, status = 400) => json({ error: msg }, status);

const cleanRoom = (v) => {
  const r = String(v || "").trim();
  return ROOM_RE.test(r) ? r : null;
};
const cleanName = (v) => {
  const n = String(v || "").trim().replace(/\s+/g, " ");
  return NAME_RE.test(n) ? n : null;
};
const dmConv = (a, b) => "dm:" + [a.toLowerCase(), b.toLowerCase()].sort().join("|");
const convPrefix = (conv) => `m2/${hex(conv)}/`;
const newId = () => `${String(Date.now()).padStart(13, "0")}-${randomBytes(4).toString("hex")}`;

/* ---------- auth ---------- */
async function hashPassword(password, salt) {
  return (await scrypt(password, salt, 32)).toString("hex");
}

async function getUser(name) {
  return store().get(`u3/${hex(name.toLowerCase())}`, { type: "json" });
}

async function auth(body) {
  const name = cleanName(body.name);
  const password = String(body.password || "");
  if (!name) return fail("Имя: до 30 символов — буквы, цифры, пробел, точка, _ или -");
  if (password.length < 4) return fail("Пароль — минимум 4 символа");
  const s = store();
  const key = `u3/${hex(name.toLowerCase())}`;
  let user = await s.get(key, { type: "json" });
  if (user) {
    const hash = await hashPassword(password, user.salt);
    if (!timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.hash, "hex"))) {
      return fail("Неверный пароль. Если это не твой аккаунт — выбери другое имя.", 401);
    }
  } else {
    const salt = randomBytes(16).toString("hex");
    user = { name, salt, hash: await hashPassword(password, salt), created: Date.now() };
    await s.setJSON(key, user);
  }
  const token = randomBytes(24).toString("hex");
  await s.setJSON(`s3/${token}`, { name: user.name, created: Date.now() });
  return json({ token, name: user.name });
}

async function whoAmI(req) {
  const h = req.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  if (!/^[0-9a-f]{48}$/.test(token)) return null;
  const session = await store().get(`s3/${token}`, { type: "json" });
  return session ? session.name : null;
}

/* ---------- conversations ---------- */
async function resolveConv(me, params) {
  if (params.dm) {
    const other = cleanName(params.dm);
    if (!other) return { error: "Некорректное имя" };
    if (other.toLowerCase() === me.toLowerCase()) return { error: "Нельзя написать самому себе" };
    const user = await getUser(other);
    if (!user) return { error: "Такого пользователя нет" };
    return { conv: dmConv(me, user.name), dmWith: user.name };
  }
  const room = cleanRoom(params.room);
  if (!room) return { error: "Некорректное название чата" };
  return { conv: room, room };
}

async function conversations(me) {
  const s = store();
  const [{ blobs: roomBlobs }, { blobs: dmBlobs }] = await Promise.all([
    s.list({ prefix: "r2/" }),
    s.list({ prefix: `d3/${hex(me.toLowerCase())}/` }),
  ]);
  const rooms = roomBlobs.map((b) => unhex(b.key.slice(3))).sort((a, b) => a.localeCompare(b, "ru"));
  const dmEntries = await Promise.all(dmBlobs.map((b) => s.get(b.key, { type: "json" })));
  const dms = dmEntries.filter(Boolean).sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return { rooms, dms };
}

async function users(me, q) {
  const { blobs } = await store().list({ prefix: "u3/" });
  const query = String(q || "").toLowerCase().trim();
  const lowers = blobs.map((b) => unhex(b.key.slice(3))).filter((n) => n !== me.toLowerCase());
  const matches = lowers.filter((n) => !query || n.includes(query)).slice(0, 30);
  const recs = await Promise.all(matches.map((n) => getUser(n)));
  return recs.filter(Boolean).map((u) => u.name).sort((a, b) => a.localeCompare(b, "ru"));
}

async function getMessages(conv, since) {
  const s = store();
  const prefix = convPrefix(conv);
  const { blobs } = await s.list({ prefix });
  let keys = blobs.map((b) => b.key).sort();
  keys = since ? keys.filter((k) => k > prefix + since) : keys.slice(-INITIAL_LIMIT);
  const msgs = await Promise.all(keys.map((k) => s.get(k, { type: "json" })));
  return msgs.filter(Boolean).map((m) => ({ type: "text", ...m }));
}

async function postMessage(me, body) {
  const target = await resolveConv(me, body);
  if (target.error) return fail(target.error);

  const type = ["text", "image", "video", "audio"].includes(body.type) ? body.type : "text";
  const text = String(body.text || "").trim().slice(0, MAX_TEXT);
  let media = null;
  if (type === "text") {
    if (!text) return fail("Пустое сообщение");
  } else {
    const m = body.media || {};
    if (!/^[0-9a-f]{32}$/.test(String(m.id || ""))) return fail("Файл не найден");
    media = {
      id: m.id,
      mime: String(m.mime || "").slice(0, 40),
      w: Number(m.w) || undefined,
      h: Number(m.h) || undefined,
      dur: Number(m.dur) || undefined,
    };
  }

  const msg = { id: newId(), type, name: me, text, media, ts: Date.now() };
  if (target.room) msg.room = target.room;
  else msg.dm = true;

  const s = store();
  await s.setJSON(convPrefix(target.conv) + msg.id, msg);
  if (target.room) {
    await s.set(`r2/${hex(target.room)}`, "1");
  } else {
    const preview = type === "text" ? text.slice(0, 80) : { image: "📷 Фото", video: "🎬 Видео", audio: "🎤 Голосовое" }[type];
    await Promise.all([
      s.setJSON(`d3/${hex(me.toLowerCase())}/${hex(target.dmWith.toLowerCase())}`, { with: target.dmWith, last: preview, ts: msg.ts }),
      s.setJSON(`d3/${hex(target.dmWith.toLowerCase())}/${hex(me.toLowerCase())}`, { with: me, last: `${me}: ${preview}`, ts: msg.ts }),
    ]);
  }
  return json(msg, 201);
}

/* ---------- media ---------- */
async function uploadMedia(req) {
  const mime = (req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (!MEDIA_TYPES.test(mime)) return fail("Этот тип файла не поддерживается");
  const buf = await req.arrayBuffer();
  if (!buf.byteLength) return fail("Пустой файл");
  if (buf.byteLength > MAX_MEDIA) return fail("Файл больше 4 МБ", 413);
  const id = randomBytes(16).toString("hex");
  await store().set(`f3/${id}`, buf, { metadata: { mime } });
  return json({ id, mime, size: buf.byteLength }, 201);
}

async function serveMedia(id, req) {
  if (!/^[0-9a-f]{32}$/.test(id)) return fail("Не найдено", 404);
  const res = await store().getWithMetadata(`f3/${id}`, { type: "arrayBuffer" });
  if (!res) return fail("Не найдено", 404);
  const bytes = new Uint8Array(res.data);
  const headers = {
    "content-type": res.metadata?.mime || "application/octet-stream",
    "cache-control": "public, max-age=31536000, immutable",
    "accept-ranges": "bytes",
  };
  // Safari needs byte ranges to play audio/video.
  const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.get("range") || "");
  if (range) {
    let start = range[1] ? Number(range[1]) : bytes.length - Number(range[2]);
    let end = range[1] && range[2] ? Number(range[2]) : bytes.length - 1;
    start = Math.max(0, start);
    end = Math.min(end, bytes.length - 1);
    if (start > end) return new Response(null, { status: 416, headers: { "content-range": `bytes */${bytes.length}` } });
    return new Response(bytes.slice(start, end + 1), {
      status: 206,
      headers: { ...headers, "content-range": `bytes ${start}-${end}/${bytes.length}`, "content-length": String(end - start + 1) },
    });
  }
  return new Response(bytes, { headers: { ...headers, "content-length": String(bytes.length) } });
}

/* ---------- router ---------- */
export default async (req) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\/?/, "");
  try {
    if (route === "auth" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      return await auth(body);
    }
    if (route.startsWith("media/") && req.method === "GET") {
      return await serveMedia(route.slice(6), req);
    }

    const me = await whoAmI(req);
    if (!me) return fail("Нужно войти заново", 401);

    if (route === "me" && req.method === "GET") return json({ name: me });
    if (route === "conversations" && req.method === "GET") return json(await conversations(me));
    if (route === "users" && req.method === "GET") return json({ users: await users(me, url.searchParams.get("q")) });
    if (route === "media" && req.method === "POST") return await uploadMedia(req);

    if (route === "messages" && req.method === "GET") {
      const target = await resolveConv(me, {
        room: url.searchParams.get("room"),
        dm: url.searchParams.get("dm"),
      });
      if (target.error) return fail(target.error);
      const since = (url.searchParams.get("since") || "").replace(/[^0-9a-z-]/g, "");
      return json({ messages: await getMessages(target.conv, since) });
    }
    if (route === "messages" && req.method === "POST") {
      const body = await req.json().catch(() => null);
      if (!body) return fail("Плохой запрос");
      return await postMessage(me, body);
    }
    return fail("Не найдено", 404);
  } catch (err) {
    console.error(err);
    return fail("Ошибка сервера", 500);
  }
};

export const config = { path: "/api/*" };

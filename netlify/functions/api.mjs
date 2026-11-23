import { getStore } from "@netlify/blobs";

const ROOM_RE = /^[\p{L}\p{N} _-]{1,30}$/u;
const MAX_TEXT = 1000;
const MAX_NAME = 30;
const INITIAL_LIMIT = 50;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const store = () => getStore({ name: "chat", consistency: "strong" });
// Room names are stored as hex so keys contain only [0-9a-f] (Cyrillic and spaces broke prefix listing).
const hex = (str) => Buffer.from(str, "utf8").toString("hex");
const unhex = (h) => Buffer.from(h, "hex").toString("utf8");
const roomPrefix = (room) => `m2/${hex(room)}/`;

function cleanRoom(value) {
  const room = String(value || "").trim();
  return ROOM_RE.test(room) ? room : null;
}

async function listRooms() {
  const { blobs } = await store().list({ prefix: "r2/" });
  return blobs
    .map((b) => unhex(b.key.slice(3)))
    .sort((a, b) => a.localeCompare(b, "ru"));
}

async function getMessages(room, since) {
  const s = store();
  const { blobs } = await s.list({ prefix: roomPrefix(room) });
  let keys = blobs.map((b) => b.key).sort();
  if (since) {
    const sinceKey = roomPrefix(room) + since;
    keys = keys.filter((k) => k > sinceKey);
  } else {
    keys = keys.slice(-INITIAL_LIMIT);
  }
  const msgs = await Promise.all(keys.map((k) => s.get(k, { type: "json" })));
  return msgs.filter(Boolean);
}

async function postMessage(body) {
  const room = cleanRoom(body.room);
  const name = String(body.name || "").trim().slice(0, MAX_NAME);
  const text = String(body.text || "").trim().slice(0, MAX_TEXT);
  if (!room) return json({ error: "Некорректное название комнаты" }, 400);
  if (!name) return json({ error: "Укажи имя" }, 400);
  if (!text) return json({ error: "Пустое сообщение" }, 400);

  const ts = Date.now();
  const id = `${String(ts).padStart(13, "0")}-${Math.random().toString(36).slice(2, 8)}`;
  const msg = { id, room, name, text, ts };
  const s = store();
  await s.setJSON(roomPrefix(room) + id, msg);
  await s.set(`r2/${hex(room)}`, "1");
  return json(msg, 201);
}

export default async (req) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\/?/, "");
  try {
    if (route === "rooms" && req.method === "GET") {
      return json({ rooms: await listRooms() });
    }
    if (route === "messages" && req.method === "GET") {
      const room = cleanRoom(url.searchParams.get("room"));
      if (!room) return json({ error: "Некорректное название комнаты" }, 400);
      const since = (url.searchParams.get("since") || "").replace(/[^0-9a-z-]/g, "");
      return json({ messages: await getMessages(room, since) });
    }
    if (route === "messages" && req.method === "POST") {
      let body;
      try {
        body = await req.json();
      } catch {
        return json({ error: "Плохой запрос" }, 400);
      }
      return await postMessage(body);
    }
    return json({ error: "Не найдено" }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: "Ошибка сервера" }, 500);
  }
};

export const config = { path: "/api/*" };

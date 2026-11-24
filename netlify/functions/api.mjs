import { getStore } from "@netlify/blobs";
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCb);

const ROOM_RE = /^[\p{L}\p{N} _-]{1,30}$/u;
const NAME_RE = /^[\p{L}\p{N} _.-]{1,30}$/u;
const ID_RE = /^[0-9]{13}-[0-9a-z]{4,12}$/;
const MEDIA_ID_RE = /^[0-9a-f]{32}$/;
const MAX_TEXT = 1000;
const MAX_POST = 280;
const MAX_BIO = 160;
const INITIAL_LIMIT = 60;
const PAGE = 25;
const MAX_MEDIA = 4 * 1024 * 1024; // Netlify functions accept ~6 MB requests (less after encoding)
const MEDIA_TYPES = /^(image\/(jpeg|png|gif|webp)|video\/(mp4|webm|quicktime)|audio\/(webm|mp4|mpeg|ogg|aac|x-m4a))$/;

// The repository is public, so only a hash of the promo code lives here.
const PROMO_SALT = "itp-promo-v1";
const PROMO_HASH = "c40fcf79239b5616addcc03dd878da2cd74baf32083ffef977da1dd38d157b2f";

/* Key layout (all user-controlled parts are hex, so keys only contain [0-9a-f/-]):
   Messenger
     m2/<hex conv>/<id>          message            (conv = room name, or "dm:" + a + "|" + b)
     r2/<hex room>               public room exists
     d3/<hex lower>/<hex lower>  DM index entry { with, last, ts }
     x2/<hex conv>/<id>          tombstone of a deleted message
   Accounts
     u3/<hex lower>              user { name, salt, hash, bio, avatar, following[], followers[], bookmarks[], admin, notifSeen }
     s3/<token>                  session { name }
     f3/<id>                     media bytes (metadata: mime)
   Social
     p4/<id>                     post { id, name, text, media[], ts, likes[], reposts{lower: entryId}, replies, replyTo }
                                 or repost entry { id, repostOf, name, ts }
     t4/<id>                     timeline index (top-level posts and repost entries)
     a4/<hex lower>/<id>         author index (what shows on a profile)
     q4/<parent id>/<id>         replies index
     n4/<hex lower>/<id>         notification { id, type, from, postId, text, ts }                */

const hex = (str) => Buffer.from(str, "utf8").toString("hex");
const unhex = (h) => Buffer.from(h, "hex").toString("utf8");
const low = (n) => String(n).toLowerCase();
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
const dmConv = (a, b) => "dm:" + [low(a), low(b)].sort().join("|");
const convPrefix = (conv) => `m2/${hex(conv)}/`;
const newId = () => `${String(Date.now()).padStart(13, "0")}-${randomBytes(4).toString("hex")}`;
const userKey = (name) => `u3/${hex(low(name))}`;

/* ---------- auth & users ---------- */
async function hashPassword(password, salt) {
  return (await scrypt(password, salt, 32)).toString("hex");
}

async function getUser(name) {
  if (!name) return null;
  return store().get(userKey(name), { type: "json" });
}
async function saveUser(user) {
  await store().setJSON(userKey(user.name), user);
}

async function auth(body) {
  const name = cleanName(body.name);
  const password = String(body.password || "");
  if (!name) return fail("Имя: до 30 символов — буквы, цифры, пробел, точка, _ или -");
  if (password.length < 4) return fail("Пароль — минимум 4 символа");
  const s = store();
  let user = await getUser(name);
  if (user) {
    const hash = await hashPassword(password, user.salt);
    if (!timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.hash, "hex"))) {
      return fail("Неверный пароль. Если это не твой аккаунт — выбери другое имя.", 401);
    }
  } else {
    const salt = randomBytes(16).toString("hex");
    user = { name, salt, hash: await hashPassword(password, salt), created: Date.now(), bio: "", avatar: null, following: [], followers: [], bookmarks: [] };
    await saveUser(user);
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

function publicUser(u, viewer) {
  const v = viewer ? low(viewer.name) : null;
  return {
    name: u.name,
    bio: u.bio || "",
    avatar: u.avatar || null,
    created: u.created || null,
    followers: (u.followers || []).length,
    following: (u.following || []).length,
    admin: !!u.admin,
    isFollowing: v ? (viewer.following || []).includes(low(u.name)) : false,
    followsYou: v ? (u.following || []).includes(v) : false,
  };
}

async function getMe(name) {
  const u = await getUser(name);
  const { blobs } = await store().list({ prefix: `n4/${hex(low(name))}/` });
  const seen = u.notifSeen || "";
  const unread = blobs.filter((b) => b.key.split("/").pop() > seen).length;
  return json({ ...publicUser(u, u), unread });
}

async function getProfile(viewerName, name) {
  const [u, viewer] = await Promise.all([getUser(cleanName(name)), getUser(viewerName)]);
  if (!u) return fail("Такого пользователя нет", 404);
  return json(publicUser(u, viewer));
}

async function updateProfile(name, body) {
  const u = await getUser(name);
  if (typeof body.bio === "string") u.bio = body.bio.trim().slice(0, MAX_BIO);
  if (body.avatar === null || MEDIA_ID_RE.test(String(body.avatar || ""))) {
    const old = u.avatar;
    u.avatar = body.avatar || null;
    if (old && old !== u.avatar) await store().delete(`f3/${old}`);
  }
  await saveUser(u);
  return json(publicUser(u, u));
}

async function avatars(list) {
  const names = [...new Set(String(list || "").split(",").map((n) => cleanName(n)).filter(Boolean).map(low))].slice(0, 60);
  const users = await Promise.all(names.map((n) => getUser(n)));
  const out = {};
  names.forEach((n, i) => {
    out[n] = users[i] ? { name: users[i].name, avatar: users[i].avatar || null } : { name: n, avatar: null, missing: true };
  });
  return json({ users: out });
}

async function follow(name, body) {
  const target = await getUser(cleanName(body.name));
  if (!target) return fail("Такого пользователя нет", 404);
  if (low(target.name) === low(name)) return fail("Нельзя подписаться на себя");
  const u = await getUser(name);
  u.following = (u.following || []).filter((x) => x !== low(target.name));
  target.followers = (target.followers || []).filter((x) => x !== low(name));
  if (body.on) {
    u.following.push(low(target.name));
    target.followers.push(low(name));
  }
  await Promise.all([saveUser(u), saveUser(target)]);
  if (body.on) await notify(target.name, { type: "follow", from: name });
  return json(publicUser(target, u));
}

async function followList(name, kind) {
  const u = await getUser(cleanName(name));
  if (!u) return fail("Такого пользователя нет", 404);
  const lowers = (kind === "followers" ? u.followers : u.following) || [];
  const users = await Promise.all(lowers.slice(0, 200).map((n) => getUser(n)));
  return json({ users: users.filter(Boolean).map((x) => ({ name: x.name, bio: x.bio || "", avatar: x.avatar || null })) });
}

async function users(meName, q) {
  const { blobs } = await store().list({ prefix: "u3/" });
  const query = low(String(q || "").trim());
  const lowers = blobs.map((b) => unhex(b.key.slice(3))).filter((n) => n !== low(meName));
  const matches = lowers.filter((n) => !query || n.includes(query)).slice(0, 30);
  const recs = await Promise.all(matches.map((n) => getUser(n)));
  return recs
    .filter(Boolean)
    .map((u) => ({ name: u.name, bio: u.bio || "", avatar: u.avatar || null }))
    .sort((a, b) => a.name.localeCompare(b.name, "ru"));
}

async function redeemPromo(name, body) {
  const code = String(body.code || "").trim();
  const hash = await hashPassword(code, PROMO_SALT);
  if (!timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(PROMO_HASH, "hex"))) return fail("Неверный промокод");
  const u = await getUser(name);
  u.admin = true;
  await saveUser(u);
  return json({ admin: true });
}

/* ---------- notifications ---------- */
async function notify(to, n) {
  if (!to || low(to) === low(n.from)) return;
  const id = newId();
  await store().setJSON(`n4/${hex(low(to))}/${id}`, { id, ts: Date.now(), ...n });
}

async function notifications(name) {
  const s = store();
  const { blobs } = await s.list({ prefix: `n4/${hex(low(name))}/` });
  const keys = blobs.map((b) => b.key).sort().reverse().slice(0, 60);
  const items = (await Promise.all(keys.map((k) => s.get(k, { type: "json" })))).filter(Boolean);
  const u = await getUser(name);
  const seen = u.notifSeen || "";
  if (items[0] && items[0].id > seen) {
    u.notifSeen = items[0].id;
    await saveUser(u);
  }
  return json({ items: items.map((i) => ({ ...i, unread: i.id > seen })) });
}

/* ---------- messenger ---------- */
async function resolveConv(me, params) {
  if (params.dm) {
    const other = cleanName(params.dm);
    if (!other) return { error: "Некорректное имя" };
    if (low(other) === low(me)) return { error: "Нельзя написать самому себе" };
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
    s.list({ prefix: `d3/${hex(low(me))}/` }),
  ]);
  const rooms = roomBlobs.map((b) => unhex(b.key.slice(3))).sort((a, b) => a.localeCompare(b, "ru"));
  const dmEntries = await Promise.all(dmBlobs.map((b) => s.get(b.key, { type: "json" })));
  const dms = dmEntries.filter(Boolean).sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return { rooms, dms };
}

async function getMessages(conv, since) {
  const s = store();
  const prefix = convPrefix(conv);
  const tombPrefix = `x2/${hex(conv)}/`;
  const [{ blobs }, { blobs: tombs }] = await Promise.all([s.list({ prefix }), s.list({ prefix: tombPrefix })]);
  let keys = blobs.map((b) => b.key).sort();
  keys = since ? keys.filter((k) => k > prefix + since) : keys.slice(-INITIAL_LIMIT);
  const msgs = await Promise.all(keys.map((k) => s.get(k, { type: "json" })));
  return {
    messages: msgs.filter(Boolean).map((m) => ({ type: "text", ...m })),
    deleted: tombs.map((b) => b.key.slice(tombPrefix.length)),
  };
}

const PREVIEW = { image: "📷 Фото", video: "🎬 Видео", audio: "🎤 Голосовое" };
const previewOf = (m) => (m ? (m.type === "text" || !m.type ? m.text.slice(0, 80) : PREVIEW[m.type]) : "Нет сообщений");

async function setDmPreviews(me, other, last, ts) {
  const s = store();
  const p = previewOf(last);
  await Promise.all([
    s.setJSON(`d3/${hex(low(me))}/${hex(low(other))}`, { with: other, last: last && last.name !== me ? `${last.name}: ${p}` : p, ts }),
    s.setJSON(`d3/${hex(low(other))}/${hex(low(me))}`, { with: me, last: last && last.name !== other ? `${last.name}: ${p}` : p, ts }),
  ]);
}

async function deleteMessage(me, body) {
  const target = await resolveConv(me, body);
  if (target.error) return fail(target.error);
  const id = String(body.id || "");
  if (!ID_RE.test(id)) return fail("Некорректное сообщение");
  const s = store();
  const key = convPrefix(target.conv) + id;
  const msg = await s.get(key, { type: "json" });
  if (!msg) return json({ ok: true }); // already gone
  if (msg.name !== me && !(await getUser(me)).admin) return fail("Удалять можно только свои сообщения", 403);
  await s.set(`x2/${hex(target.conv)}/${id}`, "1");
  await s.delete(key);
  if (msg.media && msg.media.id) await s.delete(`f3/${msg.media.id}`);
  if (target.dmWith) {
    const { blobs } = await s.list({ prefix: convPrefix(target.conv) });
    const lastKey = blobs.map((b) => b.key).sort().pop();
    const last = lastKey ? await s.get(lastKey, { type: "json" }) : null;
    await setDmPreviews(me, target.dmWith, last, last ? last.ts : Date.now());
  }
  return json({ ok: true });
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
    if (!MEDIA_ID_RE.test(String(m.id || ""))) return fail("Файл не найден");
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
    await setDmPreviews(me, target.dmWith, msg, msg.ts);
  }
  return json(msg, 201);
}

/* ---------- posts ---------- */
const postKey = (id) => `p4/${id}`;
async function getPost(id) {
  return ID_RE.test(String(id || "")) ? store().get(postKey(id), { type: "json" }) : null;
}
async function savePost(p) {
  await store().setJSON(postKey(p.id), p);
}

function cleanPostMedia(list) {
  if (!Array.isArray(list)) return [];
  const out = list
    .filter((m) => m && MEDIA_ID_RE.test(String(m.id)) && /^(image|video)\//.test(String(m.mime)))
    .slice(0, 4)
    .map((m) => ({ id: m.id, mime: String(m.mime).slice(0, 40), w: Number(m.w) || undefined, h: Number(m.h) || undefined }));
  const video = out.find((m) => m.mime.startsWith("video/"));
  return video ? [video] : out;
}

function view(p, viewer, extra = {}) {
  const v = low(viewer.name);
  return {
    id: p.id,
    name: p.name,
    text: p.text || "",
    media: p.media || [],
    ts: p.ts,
    replyTo: p.replyTo || null,
    replyToName: p.replyToName || null,
    replies: p.replies || 0,
    likes: (p.likes || []).length,
    liked: (p.likes || []).includes(v),
    reposts: Object.keys(p.reposts || {}).length,
    reposted: !!(p.reposts || {})[v],
    bookmarked: (viewer.bookmarks || []).includes(p.id),
    ...extra,
  };
}

// Turns stored records (posts or repost entries) into what the client shows.
async function hydrate(records, viewer) {
  const originals = await Promise.all(records.map((r) => (r && r.repostOf ? getPost(r.repostOf) : r)));
  const out = [];
  records.forEach((r, i) => {
    const p = originals[i];
    if (!r || !p) return;
    out.push(r.repostOf ? view(p, viewer, { repostedBy: r.name, entryId: r.id, sortTs: r.ts }) : view(p, viewer, { entryId: r.id }));
  });
  return out;
}

async function createPost(me, body) {
  const text = String(body.text || "").trim();
  if (text.length > MAX_POST) return fail(`Пост длиннее ${MAX_POST} символов`);
  const media = cleanPostMedia(body.media);
  if (!text && !media.length) return fail("Пустой пост");
  const s = store();
  let parent = null;
  if (body.replyTo) {
    parent = await getPost(body.replyTo);
    if (!parent || parent.repostOf) return fail("Пост не найден", 404);
  }
  const post = { id: newId(), name: me, text, media, ts: Date.now(), likes: [], reposts: {}, replies: 0 };
  if (parent) {
    post.replyTo = parent.id;
    post.replyToName = parent.name;
  }
  await savePost(post);
  if (parent) {
    await s.set(`q4/${parent.id}/${post.id}`, "1");
    const fresh = await getPost(parent.id);
    if (fresh) {
      fresh.replies = (fresh.replies || 0) + 1;
      await savePost(fresh);
    }
    await notify(parent.name, { type: "reply", from: me, postId: post.id, text: text.slice(0, 100) });
  } else {
    await Promise.all([s.set(`t4/${post.id}`, "1"), s.set(`a4/${hex(low(me))}/${post.id}`, "1")]);
  }
  // @mentions
  const mentioned = [...new Set((text.match(/@[\p{L}\p{N}_.-]+/gu) || []).map((m) => low(m.slice(1))))].slice(0, 5);
  for (const m of mentioned) {
    if (m === low(me) || (parent && m === low(parent.name))) continue;
    const u = await getUser(m);
    if (u) await notify(u.name, { type: "mention", from: me, postId: post.id, text: text.slice(0, 100) });
  }
  const viewer = await getUser(me);
  return json(view(post, viewer), 201);
}

async function deletePost(me, body) {
  const post = await getPost(body.id);
  if (!post || post.repostOf) return json({ ok: true });
  const viewer = await getUser(me);
  if (post.name !== me && !viewer.admin) return fail("Удалять можно только свои посты", 403);
  const s = store();
  await removePost(s, post);
  if (post.replyTo) {
    await s.delete(`q4/${post.replyTo}/${post.id}`);
    const parent = await getPost(post.replyTo);
    if (parent) {
      parent.replies = Math.max(0, (parent.replies || 1) - 1);
      await savePost(parent);
    }
  }
  // Replies go with the post.
  const { blobs } = await s.list({ prefix: `q4/${post.id}/` });
  for (const b of blobs.slice(0, 200)) {
    const reply = await getPost(b.key.split("/").pop());
    if (reply) await removePost(s, reply);
    await s.delete(b.key);
  }
  return json({ ok: true });
}

async function removePost(s, post) {
  const jobs = [s.delete(postKey(post.id)), s.delete(`t4/${post.id}`), s.delete(`a4/${hex(low(post.name))}/${post.id}`)];
  for (const m of post.media || []) jobs.push(s.delete(`f3/${m.id}`));
  for (const [who, entryId] of Object.entries(post.reposts || {})) {
    jobs.push(s.delete(postKey(entryId)), s.delete(`t4/${entryId}`), s.delete(`a4/${hex(who)}/${entryId}`));
  }
  await Promise.all(jobs);
}

async function likePost(me, body) {
  const post = await getPost(body.id);
  if (!post || post.repostOf) return fail("Пост не найден", 404);
  const l = low(me);
  const had = (post.likes || []).includes(l);
  post.likes = (post.likes || []).filter((x) => x !== l);
  if (body.on) post.likes.push(l);
  await savePost(post);
  if (body.on && !had) await notify(post.name, { type: "like", from: me, postId: post.id, text: (post.text || "").slice(0, 100) });
  return json(view(post, await getUser(me)));
}

async function repostPost(me, body) {
  const post = await getPost(body.id);
  if (!post || post.repostOf) return fail("Пост не найден", 404);
  const s = store();
  const l = low(me);
  post.reposts = post.reposts || {};
  if (body.on && !post.reposts[l]) {
    const entry = { id: newId(), repostOf: post.id, name: me, ts: Date.now() };
    await savePost(entry);
    await Promise.all([s.set(`t4/${entry.id}`, "1"), s.set(`a4/${hex(l)}/${entry.id}`, "1")]);
    post.reposts[l] = entry.id;
    await notify(post.name, { type: "repost", from: me, postId: post.id, text: (post.text || "").slice(0, 100) });
  } else if (!body.on && post.reposts[l]) {
    const eid = post.reposts[l];
    await Promise.all([s.delete(postKey(eid)), s.delete(`t4/${eid}`), s.delete(`a4/${hex(l)}/${eid}`)]);
    delete post.reposts[l];
  }
  await savePost(post);
  return json(view(post, await getUser(me)));
}

async function bookmarkPost(me, body) {
  const post = await getPost(body.id);
  if (!post || post.repostOf) return fail("Пост не найден", 404);
  const u = await getUser(me);
  u.bookmarks = (u.bookmarks || []).filter((x) => x !== post.id);
  if (body.on) u.bookmarks.unshift(post.id);
  u.bookmarks = u.bookmarks.slice(0, 500);
  await saveUser(u);
  return json(view(post, u));
}

async function pageOf(prefix, before, viewer, keep) {
  const s = store();
  const { blobs } = await s.list({ prefix });
  let ids = blobs.map((b) => b.key.slice(prefix.length)).sort().reverse();
  if (before) ids = ids.filter((id) => id < before);
  const picked = [];
  let i = 0;
  // Read in chunks until the page is full (filters like "following" skip records).
  while (picked.length < PAGE && i < ids.length && i < 400) {
    const chunk = ids.slice(i, i + 40);
    const recs = await Promise.all(chunk.map((id) => getPost(id)));
    for (let j = 0; j < chunk.length; j++) {
      i++;
      const r = recs[j];
      if (r && (!keep || keep(r))) picked.push(r);
      if (picked.length >= PAGE) break;
    }
  }
  return { posts: await hydrate(picked, viewer), next: i < ids.length ? ids[i - 1] : null };
}

async function feed(me, mode, before) {
  const viewer = await getUser(me);
  if (mode === "following") {
    const set = new Set([...(viewer.following || []), low(me)]);
    return json(await pageOf("t4/", before, viewer, (r) => set.has(low(r.name))));
  }
  return json(await pageOf("t4/", before, viewer));
}

async function userPosts(me, name, before) {
  const u = await getUser(cleanName(name));
  if (!u) return fail("Такого пользователя нет", 404);
  return json(await pageOf(`a4/${hex(low(u.name))}/`, before, await getUser(me)));
}

async function thread(me, id) {
  const post = await getPost(id);
  if (!post || post.repostOf) return fail("Пост удалён или не найден", 404);
  const viewer = await getUser(me);
  const s = store();
  const { blobs } = await s.list({ prefix: `q4/${post.id}/` });
  const ids = blobs.map((b) => b.key.split("/").pop()).sort().slice(0, 200);
  const replies = (await Promise.all(ids.map((rid) => getPost(rid)))).filter(Boolean);
  const parent = post.replyTo ? await getPost(post.replyTo) : null;
  return json({
    parent: parent ? view(parent, viewer) : null,
    post: view(post, viewer),
    replies: replies.map((r) => view(r, viewer)),
  });
}

async function bookmarks(me) {
  const viewer = await getUser(me);
  const recs = await Promise.all((viewer.bookmarks || []).slice(0, 100).map((id) => getPost(id)));
  return json({ posts: await hydrate(recs.filter(Boolean), viewer), next: null });
}

async function search(me, q) {
  const query = low(String(q || "").trim()).slice(0, 60);
  const viewer = await getUser(me);
  const people = await users(me, query.replace(/^[@#]/, ""));
  if (!query) return json({ users: people, posts: [] });
  const s = store();
  const { blobs } = await s.list({ prefix: "t4/" });
  const ids = blobs.map((b) => b.key.slice(3)).sort().reverse().slice(0, 300);
  const recs = await Promise.all(ids.map((id) => getPost(id)));
  const hits = recs.filter((r) => r && !r.repostOf && low(r.text || "").includes(query)).slice(0, 40);
  return json({ users: query.startsWith("#") ? [] : people, posts: await hydrate(hits, viewer) });
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
  if (!MEDIA_ID_RE.test(id)) return fail("Не найдено", 404);
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
  const q = (k) => url.searchParams.get(k);
  const body = async () => (await req.json().catch(() => null)) || {};
  try {
    if (route === "auth" && req.method === "POST") return await auth(await body());
    if (route.startsWith("media/") && req.method === "GET") return await serveMedia(route.slice(6), req);

    const me = await whoAmI(req);
    if (!me) return fail("Нужно войти заново", 401);

    if (req.method === "GET") {
      switch (route) {
        case "me": return await getMe(me);
        case "user": return await getProfile(me, q("name"));
        case "avatars": return await avatars(q("n"));
        case "follows": return await followList(q("name"), q("kind"));
        case "users": return json({ users: (await users(me, q("q"))).map((u) => u.name) });
        case "conversations": return json(await conversations(me));
        case "notifications": return await notifications(me);
        case "feed": return await feed(me, q("mode"), q("before"));
        case "posts/user": return await userPosts(me, q("name"), q("before"));
        case "post": return await thread(me, q("id"));
        case "bookmarks": return await bookmarks(me);
        case "search": return await search(me, q("q"));
        case "messages": {
          const target = await resolveConv(me, { room: q("room"), dm: q("dm") });
          if (target.error) return fail(target.error);
          const since = (q("since") || "").replace(/[^0-9a-z-]/g, "");
          return json(await getMessages(target.conv, since));
        }
      }
    }
    if (req.method === "POST") {
      if (route === "media") return await uploadMedia(req);
      const b = await body();
      switch (route) {
        case "profile": return await updateProfile(me, b);
        case "follow": return await follow(me, b);
        case "promo": return await redeemPromo(me, b);
        case "posts": return await createPost(me, b);
        case "posts/delete": return await deletePost(me, b);
        case "like": return await likePost(me, b);
        case "repost": return await repostPost(me, b);
        case "bookmark": return await bookmarkPost(me, b);
        case "messages": return await postMessage(me, b);
        case "messages/delete": return await deleteMessage(me, b);
      }
    }
    return fail("Не найдено", 404);
  } catch (err) {
    console.error(err);
    return fail("Ошибка сервера", 500);
  }
};


export const config = { path: "/api/*" };

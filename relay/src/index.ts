import { DurableObject } from "cloudflare:workers";

const MAX_RECORD_BYTES = 65_536; // 單筆 ciphertext 字元數(嚴格 base64 → 字元 = byte)
const MAX_CHAIN_BYTES = 1_048_576; // 所有列(含 tombstone)的 ciphertext + nonce 長度總和
const MAX_CHAIN_RECORDS = 4096;
const MAX_BODY_BYTES = 1_048_576;
const MAX_ITEMS_PER_PUSH = 200;
const RATE_LIMIT_PER_MINUTE = 120;
const IDLE_TTL_MS = 180 * 24 * 60 * 60 * 1000;
const TOUCH_INTERVAL_MS = 6 * 60 * 60 * 1000;
const IP_WINDOW_MS = 60 * 60 * 1000;
const HEX64 = /^[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

export interface Envelope {
  idHash: string;
  kind: string;
  seq: number;
  nonce: string;
  ciphertext: string;
  deleted: boolean;
}

export interface PushItem {
  idHash: string;
  kind: string;
  nonce: string;
  ciphertext: string;
  deleted: boolean;
  baseSeq: number;
}

type PushResult = { status: "ok"; seq: number } | { status: "conflict"; current: Envelope };

type Row = {
  id_hash: string;
  kind: string;
  seq: number;
  nonce: string;
  ciphertext: string;
  deleted: number;
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS records (
    id_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    seq INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    deleted INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS records_seq ON records (seq);
`;

const ROW_COLUMNS = "id_hash, kind, seq, nonce, ciphertext, deleted";

function toEnvelope(r: Row): Envelope {
  return { idHash: r.id_hash, kind: r.kind, seq: r.seq, nonce: r.nonce, ciphertext: r.ciphertext, deleted: r.deleted === 1 };
}

/** 每個 chain 一個 DO:token hash、記錄與序號全在它的 SQLite 裡。 */
export class ChainStore extends DurableObject<Env> {
  private minuteStart = 0;
  private minuteCount = 0;
  private lastTouch = 0;

  /**
   * chain 是否已建立 = `meta` 表存在。只讀 `sqlite_master`,不寫任何東西:讀一個從未建立的 chain
   * 不能留下持久化的空資料庫(沒寫過儲存的 DO 在關閉後就不存在)。schema 只在 `create()` 建。
   */
  async exists(): Promise<boolean> {
    return this.hasSchema();
  }

  private hasSchema(): boolean {
    return this.ctx.storage.sql.exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'meta'").toArray().length > 0;
  }

  private meta(key: string): string | null {
    const row = this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM meta WHERE key = ?", key).toArray()[0];
    return row ? row.value : null;
  }

  private setMeta(key: string, value: string): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      key,
      value,
    );
  }

  /** 已建立且 token 相符。不存在與不符都回 false(呼叫端一律 404)。 */
  private authorized(tokenHash: string): boolean {
    if (!this.hasSchema()) return false;
    const stored = this.meta("token_hash");
    return stored !== null && stored === tokenHash;
  }

  private rateLimited(): boolean {
    const now = Date.now();
    if (now - this.minuteStart > 60_000) {
      this.minuteStart = now;
      this.minuteCount = 0;
    }
    this.minuteCount += 1;
    return this.minuteCount > RATE_LIMIT_PER_MINUTE;
  }

  private row(idHash: string): Row | undefined {
    return this.ctx.storage.sql.exec<Row>(`SELECT ${ROW_COLUMNS} FROM records WHERE id_hash = ?`, idHash).toArray()[0];
  }

  /** 目前用量:所有列(含 tombstone)的 ciphertext + nonce 長度總和與筆數。 */
  private usage(): { bytes: number; count: number } {
    const r = this.ctx.storage.sql
      .exec<{ bytes: number; count: number }>(
        "SELECT COALESCE(SUM(LENGTH(ciphertext) + LENGTH(nonce)), 0) AS bytes, COUNT(*) AS count FROM records",
      )
      .one();
    return { bytes: Number(r.bytes), count: Number(r.count) };
  }

  /** 刷新閒置期限。寫入一律刷新;讀取節流(同一 instance 每 6 小時一次),唯讀裝置的 chain 才不會被清掉。 */
  private async touch(force: boolean): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastTouch < TOUCH_INTERVAL_MS) return;
    this.lastTouch = now;
    await this.ctx.storage.setAlarm(now + IDLE_TTL_MS);
  }

  /** 201 新建、200 已存在、404 token 不符、429 超過每 chain 速率。建鏈的每 IP 限制在 Worker 層。 */
  async create(tokenHash: string): Promise<201 | 200 | 404 | 429> {
    if (!this.hasSchema()) {
      // 建鏈那一次也計數,而且要看結果:計數跟著 instance 走、DELETE 不歸零,同一分鐘內刪掉再建也可能超限。
      if (this.rateLimited()) return 429;
      this.ctx.storage.sql.exec(SCHEMA);
      this.setMeta("token_hash", tokenHash);
      this.setMeta("latest_seq", "0");
      this.setMeta("created_at", String(Date.now()));
      await this.touch(true);
      return 201;
    }
    if (this.meta("token_hash") !== tokenHash) return 404;
    if (this.rateLimited()) return 429;
    await this.touch(true);
    return 200;
  }

  async pull(tokenHash: string, since: number): Promise<{ status: 200 | 404 | 429; body?: { records: Envelope[]; latestSeq: number } }> {
    if (!this.authorized(tokenHash)) return { status: 404 };
    if (this.rateLimited()) return { status: 429 };
    const records = this.ctx.storage.sql
      .exec<Row>(`SELECT ${ROW_COLUMNS} FROM records WHERE seq > ? ORDER BY seq`, since)
      .toArray()
      .map(toEnvelope);
    await this.touch(false);
    return { status: 200, body: { records, latestSeq: Number(this.meta("latest_seq") ?? "0") } };
  }

  async push(tokenHash: string, items: PushItem[]): Promise<{ status: 200 | 404 | 413 | 429; body?: { results: PushResult[]; latestSeq: number } }> {
    if (!this.authorized(tokenHash)) return { status: 404 };
    if (this.rateLimited()) return { status: 429 };

    // 1. 先判定每筆是接受還是 conflict —— 不寫入。
    let latest = Number(this.meta("latest_seq") ?? "0");
    const existing = new Map<string, Row>();
    for (const item of items) {
      const current = this.row(item.idHash);
      if (current) existing.set(item.idHash, current);
    }
    const plan: { item: PushItem; result: PushResult }[] = [];
    for (const item of items) {
      const current = existing.get(item.idHash);
      if (current && current.seq > item.baseSeq) {
        plan.push({ item, result: { status: "conflict", current: toEnvelope(current) } });
      } else {
        latest += 1;
        plan.push({ item, result: { status: "ok", seq: latest } });
      }
    }

    // 2. 以「接受之後」的用量檢查配額:conflict 不算;被取代的舊列先扣再加;tombstone 一樣算。
    //    輸入已驗證為嚴格 base64(ASCII),所以 JS `.length` 與 SQLite `LENGTH()` 一致。
    const usage = this.usage();
    let bytes = usage.bytes;
    let count = usage.count;
    for (const { item, result } of plan) {
      if (result.status !== "ok") continue;
      const previous = existing.get(item.idHash);
      if (previous) bytes -= previous.ciphertext.length + previous.nonce.length;
      else count += 1;
      bytes += item.ciphertext.length + item.nonce.length;
    }
    if (bytes > MAX_CHAIN_BYTES || count > MAX_CHAIN_RECORDS) return { status: 413 };

    // 3. 寫入(單一 DO、無 await 穿插 → 整批原子)。
    for (const { item, result } of plan) {
      if (result.status !== "ok") continue;
      this.ctx.storage.sql.exec(
        `INSERT INTO records (${ROW_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(id_hash) DO UPDATE SET kind = excluded.kind, seq = excluded.seq, nonce = excluded.nonce,
         ciphertext = excluded.ciphertext, deleted = excluded.deleted`,
        item.idHash,
        item.kind,
        result.seq,
        item.nonce,
        item.ciphertext,
        item.deleted ? 1 : 0,
      );
    }
    this.setMeta("latest_seq", String(latest));
    await this.touch(true);
    return { status: 200, body: { results: plan.map((p) => p.result), latestSeq: latest } };
  }

  async destroy(tokenHash: string): Promise<204 | 404 | 429> {
    if (!this.authorized(tokenHash)) return 404;
    if (this.rateLimited()) return 429;
    // compatibility_date ≥ 2026-02-24:deleteAll() 連 alarm 一起刪;schema 也沒了,下次 PUT 重建。
    await this.ctx.storage.deleteAll();
    this.lastTouch = 0;
    return 204;
  }

  /** 閒置 180 天:整個 chain 清掉(使用者本機資料不受影響)。儲存清空後 DO 會在關閉時消失。 */
  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
    this.lastTouch = 0;
  }
}

type Bucket = "create" | "request";
const IP_LIMITS: Record<Bucket, number> = { create: 20, request: 1200 };
type Windows = Record<Bucket, { start: number; count: number }>;

/** 每個來源 IP 一個小 DO:一小時視窗內分桶計數(建鏈、所有請求);閒置一小時由 alarm 清空自己。 */
export class IpLimiter extends DurableObject<Env> {
  async allow(bucket: Bucket): Promise<boolean> {
    const now = Date.now();
    const windows: Windows = (await this.ctx.storage.get<Windows>("windows")) ?? {
      create: { start: now, count: 0 },
      request: { start: now, count: 0 },
    };
    const w = windows[bucket];
    if (now - w.start >= IP_WINDOW_MS) {
      w.start = now;
      w.count = 0;
    }
    w.count += 1;
    await this.ctx.storage.put("windows", windows);
    await this.ctx.storage.setAlarm(now + IP_WINDOW_MS);
    return w.count <= IP_LIMITS[bucket];
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function bearer(request: Request): string | null {
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+([0-9a-f]{64})$/i.exec(header);
  return match ? match[1].toLowerCase() : null;
}

/** 嚴格的標準 base64:非空、ASCII 字母表、長度為 4 的倍數、padding ≤ 2。 */
function isStrictBase64(s: string): boolean {
  return s.length > 0 && s.length % 4 === 0 && BASE64.test(s);
}

function isPushItem(v: unknown): v is PushItem {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.idHash === "string" && HEX64.test(o.idHash) &&
    typeof o.kind === "string" && /^[a-z]{1,16}$/.test(o.kind) &&
    typeof o.nonce === "string" && o.nonce.length <= 64 && isStrictBase64(o.nonce) &&
    typeof o.ciphertext === "string" && isStrictBase64(o.ciphertext) &&
    typeof o.deleted === "boolean" &&
    typeof o.baseSeq === "number" && Number.isInteger(o.baseSeq) && o.baseSeq >= 0
  );
}

/** 以 byte 上限讀 body:超過就取消串流回 null,不把整個 body 讀進記憶體再檢查。 */
async function readBodyCapped(request: Request, maxBytes: number): Promise<string | null> {
  const reader = request.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

const bad = (message: string) => Response.json({ error: message }, { status: 400 });
const notFound = () => new Response(null, { status: 404 });
const status = (code: number) => new Response(null, { status: code });

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const match = /^\/v1\/chains\/([^/]+)(\/records)?$/.exec(url.pathname);
    if (!match) return notFound();
    const [, chainId, recordsPath] = match;
    if (!HEX64.test(chainId)) return bad("invalid chain id");
    const token = bearer(request);
    if (!token) return notFound();

    // 每 IP 限制(Cloudflare 在邊緣覆寫 CF-Connecting-IP,客戶端偽造不了;本機測試自己帶 header)。
    // 任何請求都會啟動一個 chain DO(即使不存在),所以總請求也要限;建鏈另外計一桶。
    const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
    const limiter = env.IP_LIMIT.getByName(`ip:${ip}`);
    if (!(await limiter.allow("request"))) return status(429);
    const isCreate = !recordsPath && request.method === "PUT";
    if (isCreate && !(await limiter.allow("create"))) return status(429);

    const tokenHash = await sha256Hex(token);
    const stub = env.CHAIN.getByName(chainId);

    if (isCreate) {
      const code = await stub.create(tokenHash);
      if (code === 404) return notFound();
      if (code === 429) return status(429);
      return Response.json({}, { status: code });
    }
    if (!recordsPath && request.method === "DELETE") {
      return status(await stub.destroy(tokenHash));
    }
    if (recordsPath && request.method === "GET") {
      const raw = url.searchParams.get("since") ?? "0";
      if (!/^\d{1,18}$/.test(raw)) return bad("invalid since");
      const result = await stub.pull(tokenHash, Number(raw));
      if (result.status !== 200) return status(result.status);
      return Response.json(result.body);
    }
    if (recordsPath && request.method === "POST") {
      // 宣告長度只用來提前拒絕;真正的上限由串流讀取保證(沒有 Content-Length 的請求也一樣)。
      const declared = Number(request.headers.get("content-length") ?? "0");
      if (declared > MAX_BODY_BYTES) return status(413);
      const text = await readBodyCapped(request, MAX_BODY_BYTES);
      if (text === null) return status(413);
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        return bad("body must be JSON");
      }
      if (!Array.isArray(body) || body.length === 0 || body.length > MAX_ITEMS_PER_PUSH || !body.every(isPushItem)) {
        return bad("body must be a non-empty array of records");
      }
      if (new Set(body.map((i) => i.idHash)).size !== body.length) return bad("duplicate idHash in one push");
      if (body.some((i) => i.ciphertext.length > MAX_RECORD_BYTES)) return status(413);
      const result = await stub.push(tokenHash, body);
      if (result.status !== 200) return status(result.status);
      return Response.json(result.body);
    }
    return notFound();
  },
} satisfies ExportedHandler<Env>;

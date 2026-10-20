import { DurableObject } from "cloudflare:workers";

const IP_WINDOW_MS = 60 * 60 * 1000;

export type Bucket = "create" | "request" | "pull";
const IP_LIMITS: Record<Bucket, number> = {
  create: 20,
  request: 1200,
  pull: 12000,
};
type Windows = Record<Bucket, { start: number; count: number }>;

/** 每個來源 IP 一個小 DO:一小時視窗內分桶計數(建鏈、所有請求、批次查詢的 chain 數);最後一個視窗結束後由 alarm 清空自己。 */
export class IpLimiter extends DurableObject<Env> {
  /** 單一桶的簡寫,見 `allowMany`。 */
  async allow(bucket: Bucket, cost = 1): Promise<boolean> {
    return this.allowMany([[bucket, cost]]);
  }

  /**
   * 一次呼叫計入多個桶(只寫一次儲存),全部都在上限內才回 true。`cost` 一次計入多筆(批次查詢每項計 1);
   * 首次超限計入並持久保存拒絕狀態;同視窗後續拒絕不再寫入。
   *
   * alarm 只在這次呼叫開了新視窗時才設(計到的桶已過期,包括補上的 { start: 0 } 桶),設在新視窗開始後一小時。
   * 所以 alarm 永遠是「最晚開始的視窗 + 一小時」,其他視窗都開始得更早:alarm 觸發、`deleteAll()` 時沒有還在進行的視窗。
   * 若改成「快到期就往後延」,就可能在某個視窗結束前把它清掉。
   */
  async allowMany(charges: Array<[Bucket, number]>): Promise<boolean> {
    const now = Date.now();
    const stored =
      (await this.ctx.storage.get<Partial<Windows>>("windows")) ?? {};
    // 三個桶一律寫回。缺的桶(0.1.0 的紀錄沒有 pull)補成 { start: 0, count: 0 }:對任何版本都是已過期的視窗,
    // 沒計到就不開視窗、不動 alarm,計到了就跟過期的桶一樣從頭開始。不能省略:回滾到 0.1.0 時,它的 allow 直接讀
    // windows[bucket].start、沒有預設值,紀錄裡少了 create 桶,那個 IP 的每個 PUT 都會回 500。
    const windows: Windows = {
      create: stored.create ?? { start: 0, count: 0 },
      request: stored.request ?? { start: 0, count: 0 },
      pull: stored.pull ?? { start: 0, count: 0 },
    };
    // A blocked bucket is durable until its fixed window expires. Repeated denied
    // requests must not keep consuming writes (or charge unrelated buckets).
    if (
      charges.some(
        ([bucket]) =>
          now - windows[bucket].start < IP_WINDOW_MS &&
          windows[bucket].count > IP_LIMITS[bucket],
      )
    ) {
      return false;
    }
    let started = false;
    let allowed = true;
    for (const [bucket, cost] of charges) {
      const w = windows[bucket];
      if (now - w.start >= IP_WINDOW_MS) {
        w.start = now;
        w.count = 0;
        started = true;
      }
      w.count = Math.min(w.count + cost, IP_LIMITS[bucket] + 1);
      if (w.count > IP_LIMITS[bucket]) allowed = false;
    }
    await this.ctx.storage.put("windows", windows);
    if (started) await this.ctx.storage.setAlarm(now + IP_WINDOW_MS);
    return allowed;
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

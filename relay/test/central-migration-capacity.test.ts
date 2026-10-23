import { expect, it } from "vitest";
import { evictDurableObject } from "cloudflare:test";
import { setup } from "./helpers/migration";
import { migrationCanonical } from "../src/v2/migration";
const json = async (response: Response) => {
  expect(response.status).toBe(200);
  return response.json() as Promise<any>;
};
it("migrates and reads all 16384 signed history rows across cold restarts", async () => {
  const s = await setup(0, 16384, undefined, 4096);
  const tooMany = structuredClone(s.manifest);
  tooMany.body.target_sequence = "16385";
  expect(() => migrationCanonical(tooMany.body)).toThrow();
  const invalid = await s.child.beginMigration(s.actor, tooMany);
  expect(invalid.status).toBe(403);
  await invalid.body?.cancel();
  await json(await s.child.beginMigration(s.actor, s.manifest));
  for (let after = 0; after < s.records.length; after += 32) {
    const batch = s.records.slice(after, after + 32);
    const staged = await json(
      await s.child.stageMigration(s.actor, s.operation, String(after), batch),
    );
    expect(staged.staged).toBe(String(after + batch.length));
    if (after === 8192) {
      await evictDurableObject(s.child);
      expect((await json(await s.child.migrationStatus(s.actor))).staged).toBe(
        "8224",
      );
    }
  }
  expect(
    (await json(await s.child.commitMigration(s.actor, s.operation))).phase,
  ).toBe("retired");
  await evictDurableObject(s.child);
  let after = 0;
  while (after < s.records.length) {
    const page = await json(await s.child.pull(s.actor, after));
    expect(page.records.length).toBeGreaterThan(0);
    expect(page.records.length).toBeLessThanOrEqual(32);
    expect(page.records.map((row: any) => row.envelope)).toEqual(
      s.records.slice(after, after + page.records.length),
    );
    after += page.records.length;
    expect(page.sequence).toBe("16384");
    expect(page.history_hash).toBe(s.manifest.body.target_history_hash);
  }
  expect(after).toBe(16384);
  expect(
    (
      await s.child.stageMigration(s.actor, s.operation, "16384", [
        s.records[0],
      ])
    ).status,
  ).toBe(409);
}, 180_000);
it("rejects the ciphertext byte ceiling without publishing partial history", async () => {
  // Opaque synthetic ciphertext; this case measures server storage admission, not decryption.
  const s = await setup(0, 1600, 16384);
  await json(await s.child.beginMigration(s.actor, s.manifest));
  let rejected = false;
  for (let after = 0; after < s.records.length; after += 32) {
    const response = await s.child.stageMigration(
      s.actor,
      s.operation,
      String(after),
      s.records.slice(after, after + 32),
    );
    if (response.status === 413) {
      rejected = true;
      await response.body?.cancel();
      break;
    }
    await json(response);
  }
  expect(rejected).toBe(true);
  const incomplete = await s.child.commitMigration(s.actor, s.operation);
  expect(incomplete.status).toBe(409);
  await incomplete.body?.cancel();
  const hidden = await s.child.pull(s.actor, 0);
  expect(hidden.status).toBe(423);
  await hidden.body?.cancel();
  await evictDurableObject(s.child);
  expect((await s.child.pull(s.actor, 0)).status).toBe(423);
}, 180_000);

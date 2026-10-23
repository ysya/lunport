import { setup, random, sign, zero } from "./helpers/migration";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import fixture from "../../fixtures/central-sync-v2.json";
import migrationFixture from "../../fixtures/central-migration-v2.json";
import {
  authorBytes,
  base64,
  canonical,
  hash,
  recordCanonical,
  type RecordEnvelope,
} from "../src/v2/protocol";
import { trustGenesis } from "../src/v2/membership";
import { wrapsDigest } from "../src/v2/rekey";
import {
  migrationCanonical,
  migrationDigest,
  verifyMigration,
} from "../src/v2/migration";

async function resign(envelope: RecordEnvelope): Promise<void> {
  envelope.signature = sign(
    await authorBytes(
      "lunport-record-author-v2",
      recordCanonical(envelope.header),
      envelope.nonce,
      Uint8Array.from(atob(envelope.ciphertext), (c) => c.charCodeAt(0)),
    ),
  );
}
async function retarget(s: Awaited<ReturnType<typeof setup>>): Promise<void> {
  let history = zero;
  for (const [index, envelope] of s.records.entries()) {
    await resign(envelope);
    const digest = await hash(
      canonical([
        "lunport-operation-v2",
        new TextDecoder().decode(recordCanonical(envelope.header)),
        envelope.nonce,
        envelope.ciphertext,
        envelope.signature,
      ]),
    );
    history = await hash(
      canonical(["lunport-history-v2", history, String(index + 1), digest]),
    );
  }
  s.manifest.body.target_sequence = String(s.records.length);
  s.manifest.body.target_history_hash = history;
  s.manifest.signature = sign(migrationCanonical(s.manifest.body));
}

const json = async (response: Response) => {
  expect(response.status).toBe(200);
  return (await response.json()) as any;
};
const begin = (s: Awaited<ReturnType<typeof setup>>) =>
  s.child.beginMigration(s.actor, s.manifest);
const stage = (
  s: Awaited<ReturnType<typeof setup>>,
  after = "0",
  rows = s.records,
) => s.child.stageMigration(s.actor, s.operation, after, rows);
const commit = (s: Awaited<ReturnType<typeof setup>>) =>
  s.child.commitMigration(s.actor, s.operation);
async function committed() {
  const s = await setup();
  await json(await begin(s));
  await json(await stage(s));
  await json(await commit(s));
  return s;
}

describe("signed central initial-library migration", () => {
  it("matches the native canonical signature, commit digest and frozen source fixture", async () => {
    const member = (await trustGenesis(fixture.genesis, fixture.anchor))!;
    const manifest = migrationFixture.manifest;
    expect(base64(migrationCanonical(manifest.body))).toBe(
      migrationFixture.manifest_canonical_base64,
    );
    expect(sign(migrationCanonical(manifest.body))).toBe(manifest.signature);
    expect(await migrationDigest(manifest)).toBe(
      migrationFixture.manifest_digest,
    );
    expect(
      await verifyMigration(
        member,
        manifest,
        1,
        1,
        manifest.body.vault_id,
        manifest.body.author,
      ),
    ).toBe(true);
    const snapshot = migrationFixture.legacy_snapshot;
    expect(
      await hash(
        new TextEncoder().encode(
          JSON.stringify([
            "lunport-legacy-snapshot-v1",
            snapshot.chain_id,
            snapshot.latest_seq,
            [...snapshot.records].sort((a, b) =>
              a.idHash.localeCompare(b.idHash),
            ),
          ]),
        ),
      ),
    ).toBe(snapshot.ciphertext_digest);
    await expect(
      migrationDigest({ ...manifest, signature: manifest.signature + "=" }),
    ).rejects.toThrow();
  });
  it("keeps partial staging hidden and installs an empty-source library atomically", async () => {
    const s = await setup();
    expect(
      await verifyMigration(
        s.member,
        s.manifest,
        1,
        1,
        s.install.vault,
        s.actor.device,
      ),
    ).toBe(true);
    await json(await begin(s));
    for (const response of [
      await s.child.pull(s.actor, 0),
      await s.child.metadata(s.actor),
      await s.child.wrap(s.actor),
      await s.child.push(s.actor, [s.records[0]]),
    ]) {
      expect(response.status).toBe(423);
      await response.body?.cancel();
    }
    const grant = {
      kind: "recovery_read" as const,
      locator: s.actor.locator,
      account: s.actor.account,
      device: s.actor.device,
      epoch: 1,
      head: s.member.head,
      expires: Date.now() + 300000,
    };
    for (const response of [
      await s.child.recoveryForGrant(grant),
      await s.child.recoveryHistoryForGrant(grant, 0),
    ]) {
      expect(response.status).toBe(423);
      await response.body?.cancel();
    }
    expect(
      (await json(await stage(s, "0", s.records.slice(0, 1)))).staged,
    ).toBe("1");
    expect((await commit(s)).status).toBe(409);
    expect((await json(await stage(s, "1", s.records.slice(1)))).staged).toBe(
      "3",
    );
    const receipt = await json(await commit(s));
    expect(receipt.phase).toBe("retired");
    expect(receipt.history_hash).toBe(s.manifest.body.target_history_hash);
    const page = await json(await s.child.pull(s.actor, 0));
    expect(page.records.map((r: any) => r.envelope)).toEqual(s.records);
    expect(page.history_hash).toBe(s.manifest.body.target_history_hash);
    expect(
      (
        await json(
          await s.child.operationReceipt(
            s.actor,
            s.records[0].header.operation_id,
          ),
        )
      ).revision,
    ).toBe("1");
    await evictDurableObject(s.child);
    expect(await json(await commit(s))).toEqual(receipt);
    expect(
      (await json(await s.child.retireMigration(s.actor, s.operation))).phase,
    ).toBe("retired");

  });

  it("atomically retains private history and a later inactive-slot tombstone", async () => {
    const s = await setup(0);
    s.records[0].header.kind = "keyslot";
    s.records[1].header.kind = "key";
    s.records[2].header = {
      ...s.records[2].header,
      record_id: s.records[0].header.record_id,
      kind: "keyslot",
      expected_revision: "1",
      deleted: true,
    };
    await retarget(s);
    await json(await begin(s));
    await json(await stage(s, "0", s.records.slice(0, 2)));
    await json(await stage(s, "2", s.records.slice(2)));
    expect((await json(await stage(s))).staged).toBe("3"); // full existing prefix retry
    expect((await s.child.pull(s.actor, 0)).status).toBe(423);
    await json(await commit(s));
    const page = await json(await s.child.pull(s.actor, 0));
    expect(
      page.records.map((r: any) => [r.revision, r.sequence, r.envelope]),
    ).toEqual([
      ["1", "1", s.records[0]],
      ["1", "2", s.records[1]],
      ["2", "3", s.records[2]],
    ]);
    const current = await runInDurableObject(s.child, (_instance, ctx) =>
      ctx.storage.sql
        .exec<{ record_id: string; revision: number; envelope: string }>(
          "SELECT record_id,revision,envelope FROM current_records ORDER BY seq",
        )
        .toArray(),
    );
    expect(current).toHaveLength(2);
    expect(
      current.find((r) => r.record_id === s.records[0].header.record_id)
        ?.revision,
    ).toBe(2);
    expect(
      JSON.parse(
        current.find((r) => r.record_id === s.records[0].header.record_id)!
          .envelope,
      ).header.deleted,
    ).toBe(true);
    expect(
      current.some((r) => r.record_id === s.records[1].header.record_id),
    ).toBe(true);
    expect(
      (
        await json(
          await s.child.operationReceipt(
            s.actor,
            s.records[2].header.operation_id,
          ),
        )
      ).revision,
    ).toBe("2");
    expect(
      (
        await json(
          await s.child.operationReceipt(
            s.actor,
            s.records[0].header.operation_id,
          ),
        )
      ).revision,
    ).toBe("1");
  });

  it("validates repeated revisions within a batch and rejects gaps or reused operations", async () => {
    const s = await setup(0);
    const id = s.records[0].header.record_id;
    s.records[1].header = {
      ...s.records[1].header,
      record_id: id,
      expected_revision: "1",
    };
    s.records[2].header = {
      ...s.records[2].header,
      record_id: id,
      expected_revision: "2",
      deleted: true,
    };
    await retarget(s);
    await json(await begin(s));
    const gap = structuredClone(s.records[1]);
    gap.header.expected_revision = "2";
    await resign(gap);
    expect((await stage(s, "0", [s.records[0], gap])).status).toBe(409);
    expect((await json(await s.child.migrationStatus(s.actor))).staged).toBe(
      "0",
    );
    await json(await stage(s));
    expect((await json(await stage(s, "1", s.records.slice(1)))).staged).toBe(
      "3",
    );
    await json(await commit(s));
    expect(
      (
        await json(
          await s.child.operationReceipt(
            s.actor,
            s.records[2].header.operation_id,
          ),
        )
      ).revision,
    ).toBe("3");
    const other = await setup(0);
    await json(await begin(other));
    await json(await stage(other, "0", [other.records[0]]));
    const reused = structuredClone(other.records[1]);
    reused.header.operation_id = other.records[0].header.operation_id;
    await resign(reused);
    expect((await stage(other, "1", [reused])).status).toBe(409);
    expect(
      (await json(await other.child.migrationStatus(other.actor))).staged,
    ).toBe("1");
  });

  it("bounds distinct current rows even when retained history permits more revisions", async () => {
    const s = await setup(0);
    s.manifest.body.target_sequence = "4097";
    s.manifest.signature = sign(migrationCanonical(s.manifest.body));
    await json(await begin(s));
    // Synthetic capacity fixture only: no production ciphertext or authorization is used.
    await runInDurableObject(s.child, (_instance, ctx) => {
      for (let index = 1; index <= 4096; index++)
        ctx.storage.sql.exec(
          "INSERT INTO migration_versions VALUES(?,?,?,?,?,?,?)",
          index,
          index.toString(16).padStart(64, "0"),
          1,
          index.toString(16).padStart(32, "0"),
          "{}",
          zero,
          zero,
        );
      const j = JSON.parse(
        ctx.storage.sql
          .exec<{ value: string }>("SELECT value FROM migration_journal")
          .one().value,
      );
      j.staged = 4096;
      j.historyHash = zero;
      ctx.storage.sql.exec(
        "UPDATE migration_journal SET value=?",
        JSON.stringify(j),
      );
    });
    expect((await stage(s, "4096", [s.records[0]])).status).toBe(413);
    expect((await json(await s.child.migrationStatus(s.actor))).staged).toBe(
      "4096",
    );
  });

  it("accepts exact retries but rejects changed manifests, overlap and row reordering", async () => {
    const s = await setup();
    const first = await json(await begin(s));
    expect(await json(await begin(s))).toEqual(first);
    const altered = structuredClone(s.manifest);
    altered.body.inventory_digest = random();
    altered.signature = sign(migrationCanonical(altered.body));
    expect((await s.child.beginMigration(s.actor, altered)).status).toBe(409);
    await json(await stage(s, "0", s.records.slice(0, 2)));
    expect(
      (await json(await stage(s, "0", s.records.slice(0, 2)))).staged,
    ).toBe("2");
    expect(
      (await stage(s, "0", [...s.records].reverse().slice(1))).status,
    ).toBe(409);
    expect((await stage(s, "1", s.records.slice(1))).status).toBe(409);
    expect((await stage(s, "2", s.records.slice(0, 1))).status).toBe(409);
    await json(await stage(s, "2", s.records.slice(2)));
    expect((await commit(s)).status).toBe(200);
  });

  it("rejects unsigned changes, wrong roots/authors and malformed or oversized source lists", async () => {
    const s = await setup();
    for (const change of [
      { origin: "https://other.test" },
      { account_id: random() },
      { genesis_hash: random() },
      { vault_id: random() },
      { author: random(16) },
      { authorization_epoch: "2" },
      { key_epoch: "2" },
      { inventory_digest: random() },
    ]) {
      expect(
        (
          await s.child.beginMigration(s.actor, {
            ...s.manifest,
            body: { ...s.manifest.body, ...change },
          })
        ).status,
      ).toBe(403);
    }
    const retiredSource = { chain_id: random(), sequence: "0", count: "0", ciphertext_digest: random() };
    for (const body of [
      { ...s.manifest.body, extra: "unknown" },
      { ...s.manifest.body, target_sequence: "0" },
      { ...s.manifest.body, target_sequence: "16385" },
      {
        ...s.manifest.body,
        sources: Array(66).fill(retiredSource),
      },
      {
        ...s.manifest.body,
        sources: [retiredSource, retiredSource],
      },
      {
        ...s.manifest.body,
        sources: [{ ...retiredSource, sequence: "01" }],
      },
    ])
      expect(() => migrationCanonical(body as any)).toThrow();
    expect(
      (
        await s.child.beginMigration(s.actor, {
          ...s.manifest,
          extra: true,
        } as any)
      ).status,
    ).toBe(403);
    expect(
      (await s.child.beginMigration({ ...s.actor, expires: 0 }, s.manifest))
        .status,
    ).toBe(403);
  });

  it("never overwrites a nonempty normal target", async () => {
    const s = await setup();
    expect((await s.child.push(s.actor, [s.records[0]])).status).toBe(200);
    expect((await begin(s)).status).toBe(409);
    expect((await json(await s.child.pull(s.actor, 0))).records).toHaveLength(
      1,
    );
  });

  it("rejects invalid batches and stale authorization without changing staged progress", async () => {
    const s = await setup();
    await json(await begin(s));
    expect((await stage(s, "0", [])).status).toBe(400);
    expect((await stage(s, "0", Array(33).fill(s.records[0]))).status).toBe(
      400,
    );
    expect((await stage(s, "01", s.records)).status).toBe(400);
    expect((await stage(s, "0", [s.records[0], s.records[0]])).status).toBe(
      400,
    );
    const altered = structuredClone(s.records[0]);
    altered.ciphertext = "YQ==";
    expect((await stage(s, "0", [altered])).status).toBe(403);
    expect((await json(await s.child.migrationStatus(s.actor))).staged).toBe(
      "0",
    );
    expect(
      await s.child.install({
        ...s.install,
        epoch: 2,
        denied: [s.actor.device],
      }),
    ).toBe(200);
    expect((await stage(s)).status).toBe(403);
    expect((await commit(s)).status).toBe(403);
    expect(
      (await s.child.migrationStatus({ ...s.actor, epoch: 2 })).status,
    ).toBe(403);
  });

  it("does not accept another sequence/history hash as a complete target", async () => {
    const s = await setup();
    s.manifest.body.target_history_hash = random();
    s.manifest.signature = sign(migrationCanonical(s.manifest.body));
    await json(await begin(s));
    await json(await stage(s));
    expect((await commit(s)).status).toBe(409);
    expect((await s.child.pull(s.actor, 0)).status).toBe(423);
    expect((await s.child.retireMigration(s.actor, s.operation)).status).toBe(
      409,
    );
  });

  it("resumes retirement with fresh authorization after a committed receipt", async () => {
    const s = await committed();
    const receipt = await json(await commit(s));
    expect(await s.child.install({ ...s.install, epoch: 2 })).toBe(200);
    expect((await commit(s)).status).toBe(403);
    const fresh = { ...s.actor, epoch: 2 };
    expect(
      await json(await s.child.commitMigration(fresh, s.operation)),
    ).toEqual(receipt);
    expect(
      (await json(await s.child.retireMigration(fresh, s.operation))).phase,
    ).toBe("retired");
    // Joining devices need the original signed receipt after authorization advances.
    const retired = await json(await s.child.migrationStatus(fresh));
    expect(retired).toMatchObject({
      manifest: s.manifest,
      manifest_digest: await migrationDigest(s.manifest),
      phase: "retired",
      staged: s.manifest.body.target_sequence,
      history_hash: s.manifest.body.target_history_hash,
      retired: String(s.manifest.body.sources.length),
    });
    expect((await s.child.migrationStatus(s.actor)).status).toBe(403);
    await evictDurableObject(s.child);
    expect(await json(await s.child.migrationStatus(fresh))).toEqual(retired);
  });

  it("keeps a durable commit receipt without replaying over later edits", async () => {
    const s = await committed();
    const receipt = await json(await commit(s));
    expect(receipt.phase).toBe("retired");
    const edit = structuredClone(s.records[0]);
    edit.header.operation_id = random(16);
    edit.header.expected_revision = "1";
    edit.header.deleted = true;
    edit.signature = sign(
      await authorBytes(
        "lunport-record-author-v2",
        recordCanonical(edit.header),
        edit.nonce,
        Uint8Array.from(atob(edit.ciphertext), (c) => c.charCodeAt(0)),
      ),
    );
    expect((await s.child.push(s.actor, [edit])).status).toBe(200);
    expect(await json(await commit(s))).toEqual(receipt);
    const page = await json(await s.child.pull(s.actor, 0));
    expect(page.records).toHaveLength(4);
    expect(page.records[3].envelope).toEqual(edit);
    expect(
      (
        await json(
          await s.child.operationReceipt(s.actor, edit.header.operation_id),
        )
      ).revision,
    ).toBe("2");
    expect(receipt.manifest_digest).toBe(await migrationDigest(s.manifest));
  });
});

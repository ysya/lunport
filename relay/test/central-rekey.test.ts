import { env } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import fixture from "../../fixtures/central-rekey-v2.json";
import original from "../../fixtures/central-sync-v2.json";
import {
  base64,
  canonical,
  decode,
  hash,
  recordCanonical,
  wrapCanonical,
} from "../src/v2/protocol";
import { rekeyCanonical, verifyRekey, wrapsDigest } from "../src/v2/rekey";
import { verifyControl, type ControlProof } from "../src/v2/store";
import type { Principal } from "../src/v2/auth";
const random = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(32)), (v) =>
    v.toString(16).padStart(2, "0"),
  ).join("");
async function setup() {
  const locator = random(),
    vault = fixture.manifest.body.vault_id;
  const child = env.VAULT.getByName(locator);
  expect(
    await child.install({
      locator,
      account: fixture.anchor.account_id,
      vault,
      epoch: 4,
      proof: fixture.proof as ControlProof,
      wraps: fixture.source_wraps,
      freeze: true,
      denied: [],
    }),
  ).toBe(200);
  const actor: Principal = {
    locator,
    account: fixture.anchor.account_id,
    device: fixture.manifest.body.author,
    epoch: 4,
    session: "0".repeat(32),
    expires: Date.now() + 300000,
  };
  // Load a retained, signed pre-revocation history, including an author now revoked.
  await runInDurableObject(child, async (_instance, state) => {
    for (const row of fixture.source_rows) {
      const args = [
        Number(row.sequence),
        row.envelope.header.record_id,
        Number(row.revision),
        JSON.stringify(row.envelope),
        row.digest,
        row.history_hash,
      ];
      state.storage.sql.exec(
        "INSERT INTO versions VALUES(?,?,?,?,?,?)",
        ...args,
      );
      state.storage.sql.exec(
        "INSERT OR REPLACE INTO current_records VALUES(?,?,?,?,?,?)",
        args[1],
        args[2],
        args[0],
        args[3],
        args[4],
        args[5],
      );
      const receipt = {
        operation_id: row.envelope.header.operation_id,
        record_id: row.envelope.header.record_id,
        revision: row.revision,
        sequence: row.sequence,
        digest: row.digest,
        history_hash: row.history_hash,
      };
      state.storage.sql.exec(
        "INSERT INTO operations VALUES(?,?,?)",
        receipt.operation_id,
        row.digest,
        JSON.stringify(receipt),
      );
    }
    const current = JSON.parse(
      state.storage.sql
        .exec<{ value: string }>("SELECT value FROM vault_state")
        .one().value,
    );
    current.sequence = fixture.source.sequence;
    current.historyHash = fixture.source.history_hash;
    state.storage.sql.exec(
      "UPDATE vault_state SET value=?",
      JSON.stringify(current),
    );
  });
  return { child, actor };
}
async function begin(s: Awaited<ReturnType<typeof setup>>) {
  const reply = await s.child.beginRekey(
    s.actor,
    fixture.manifest,
    fixture.target_wraps,
  );
  expect(reply.status).toBe(200);
  return reply.json();
}
describe("signed full-history rekey", () => {
  it("verifies the Rust manifest and independently decrypts every retained revision", async () => {
    const trusted = (await verifyControl(fixture.proof as ControlProof))!;
    expect(base64(rekeyCanonical(fixture.manifest.body))).toBe(
      fixture.manifest_canonical_base64,
    );
    expect(await wrapsDigest(fixture.target_wraps)).toBe(
      fixture.manifest.body.wraps_digest,
    );
    expect(await wrapsDigest([...fixture.target_wraps].reverse())).toBe(
      fixture.manifest.body.wraps_digest,
    );
    const checkpoint = {
      vault: fixture.manifest.body.vault_id,
      authEpoch: 4,
      keyEpoch: 1,
      sequence: fixture.source.sequence,
      historyHash: fixture.source.history_hash,
    };
    expect(
      await verifyRekey(
        trusted,
        fixture.manifest,
        checkpoint,
        fixture.manifest.body.author,
      ),
    ).toBe(true);
    for (const field of Object.keys(
      checkpoint,
    ) as (keyof typeof checkpoint)[]) {
      const altered = {
        ...checkpoint,
        [field]:
          typeof checkpoint[field] === "number"
            ? Number(checkpoint[field]) + 1
            : "0".repeat(64),
      };
      expect(
        await verifyRekey(
          trusted,
          fixture.manifest,
          altered,
          fixture.manifest.body.author,
        ),
      ).toBe(false);
    }
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Chacha20Poly1305(),
    });
    const wrapped = fixture.target_wraps.find(
      (w) => w.header.recipient === fixture.manifest.body.author,
    )!;
    const context = wrapCanonical(wrapped.header);
    const keys = new Uint8Array(
      await suite.open(
        {
          recipientKey: await suite.kem.deserializePrivateKey(
            new Uint8Array(32).fill(1),
          ),
          enc: decode(wrapped.encapsulated_key, 32, 32),
          info: context,
        },
        decode(wrapped.ciphertext, 80, 80),
        context,
      ),
    );
    expect([...keys.slice(0, 32)]).toEqual([...new Uint8Array(32).fill(3)]);
    expect([...keys.slice(32)]).not.toEqual([...new Uint8Array(32).fill(3)]);
    for (const [index, row] of fixture.target_rows.entries()) {
      const opened = xchacha20poly1305(
        keys.slice(32),
        decode(row.envelope.nonce, 24, 24),
        recordCanonical(row.envelope.header),
      ).decrypt(decode(row.envelope.ciphertext, 16, 65552));
      expect(new TextDecoder().decode(opened)).toBe(
        index === 0 ? original.plaintext : "second retained revision",
      );
      expect(() =>
        xchacha20poly1305(
          new Uint8Array(32).fill(3),
          decode(row.envelope.nonce, 24, 24),
          recordCanonical(row.envelope.header),
        ).decrypt(decode(row.envelope.ciphertext, 16, 65552)),
      ).toThrow();
    }
    expect(
      fixture.target_wraps.some(
        (w) =>
          w.header.recipient ===
          fixture.proof.nodes[0].body.enrollment!.device.id,
      ),
    ).toBe(false);
  });
  it("keeps old history and immutable receipts until a complete, restart-safe atomic switch", async () => {
    const s = await setup();
    const op = fixture.source_rows[0].envelope.header.operation_id;
    const receipt = await (await s.child.operationReceipt(s.actor, op)).json();
    await begin(s);
    const grant = {
      kind: "recovery_read" as const,
      locator: s.actor.locator,
      account: s.actor.account,
      device: "f".repeat(32),
      epoch: s.actor.epoch,
      head: fixture.manifest.body.membership_head,
      expires: s.actor.expires,
    };
    const stagedRecovery = await s.child.recoveryForGrant(grant);
    expect(stagedRecovery.status).toBe(200);
    expect(await stagedRecovery.json()).toMatchObject({
      epoch: 1,
      committed: null,
      commits: [],
    });

    const incomplete = await s.child.commitRekey(
      s.actor,
      fixture.manifest.body.rotation_id,
    );
    expect(incomplete.status).toBe(409);
    await incomplete.arrayBuffer();
    const firstPage = await s.child.stageRekey(
      s.actor,
      fixture.manifest.body.rotation_id,
      "0",
      [fixture.target_rows[0]],
    );
    expect(firstPage.status).toBe(200);
    await firstPage.arrayBuffer();
    await evictDurableObject(s.child);
    expect(await begin(s)).toMatchObject({ staged: "1" });
    expect(
      (
        await s.child.stageRekey(
          s.actor,
          fixture.manifest.body.rotation_id,
          "0",
          [fixture.target_rows[0]],
        )
      ).status,
    ).toBe(200);
    expect(
      ((await (await s.child.pull(s.actor, 0)).json()) as any).records,
    ).toEqual(fixture.source_rows);
    expect(
      (await s.child.push(s.actor, [fixture.source_rows[0].envelope])).status,
    ).toBe(423);
    expect(
      (
        await s.child.stageRekey(
          s.actor,
          fixture.manifest.body.rotation_id,
          "1",
          [fixture.target_rows[1]],
        )
      ).status,
    ).toBe(200);
    expect(
      (await s.child.commitRekey(s.actor, fixture.manifest.body.rotation_id))
        .status,
    ).toBe(200);
    const recovery = await s.child.recoveryForGrant(grant);
    expect(recovery.status).toBe(200);
    expect(await recovery.json()).toMatchObject({
      epoch: 2,
      sequence: fixture.manifest.body.source_sequence,
      history_hash: fixture.manifest.body.target_history_hash,
      committed: { manifest: fixture.manifest, wraps: fixture.target_wraps },
      commits: [fixture.manifest],
    });

    expect(
      (await (await s.child.metadata(s.actor)).json()) as any,
    ).toMatchObject({
      epoch: 2,
      phase: "ready",
      history_hash: fixture.manifest.body.target_history_hash,
    });
    expect(
      ((await (await s.child.pull(s.actor, 0)).json()) as any).records,
    ).toEqual(fixture.target_rows);
    expect(await (await s.child.operationReceipt(s.actor, op)).json()).toEqual(
      receipt,
    );
    expect(
      (await s.child.commitRekey(s.actor, fixture.manifest.body.rotation_id))
        .status,
    ).toBe(200);
    expect(await (await s.child.committedWraps(s.actor, 2)).json()).toEqual({
      manifest: fixture.manifest,
      wraps: fixture.target_wraps,
    });
    expect(
      (await s.child.committedWraps({ ...s.actor, device: "d".repeat(32) }, 2))
        .status,
    ).toBe(403);
    const proof = (await (
      await s.child.sourceProof(s.actor, 2, 1)
    ).json()) as any;
    expect(proof.digests).toEqual([
      { sequence: "2", digest: fixture.source_rows[1].digest },
    ]);
    expect(
      await hash(
        canonical([
          "lunport-history-v2",
          fixture.known_prefix.history_hash,
          "2",
          proof.digests[0].digest,
        ]),
      ),
    ).toBe(fixture.manifest.body.source_history_hash);
    expect((await s.child.sourceProof(s.actor, 2, 3)).status).toBe(400);
  });
  it("rejects substituted history, recipients, cancelled plans and revoked or expired actors", async () => {
    const s = await setup();
    expect(
      (
        await s.child.beginRekey(
          s.actor,
          fixture.manifest,
          fixture.target_wraps.slice(0, 1),
        )
      ).status,
    ).toBe(403);
    await begin(s);
    const altered = structuredClone(fixture.target_rows);
    altered[1].envelope.header.operation_id = "9".repeat(32);
    expect(
      (
        await s.child.stageRekey(
          s.actor,
          fixture.manifest.body.rotation_id,
          "0",
          altered,
        )
      ).status,
    ).toBe(403);
    expect(
      ((await (await s.child.rekeyStatus(s.actor)).json()) as any).journal
        .staged,
    ).toBe("0");
    expect(
      (
        await s.child.stageRekey(
          { ...s.actor, expires: Date.now() - 1 },
          fixture.manifest.body.rotation_id,
          "0",
          fixture.target_rows,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await s.child.stageRekey(
          { ...s.actor, device: "d".repeat(32) },
          fixture.manifest.body.rotation_id,
          "0",
          fixture.target_rows,
        )
      ).status,
    ).toBe(403);
    expect(
      (await s.child.abortRekey(s.actor, fixture.manifest.body.rotation_id))
        .status,
    ).toBe(204);
    expect(
      (
        await s.child.beginRekey(
          s.actor,
          fixture.manifest,
          fixture.target_wraps,
        )
      ).status,
    ).toBe(409);
    expect(
      ((await (await s.child.pull(s.actor, 0)).json()) as any).records,
    ).toEqual(fixture.source_rows);
  });
  it("discards staged keys when a newer access barrier arrives", async () => {
    const s = await setup();
    await begin(s);
    const page = await s.child.stageRekey(
      s.actor,
      fixture.manifest.body.rotation_id,
      "0",
      fixture.target_rows,
    );
    expect(page.status).toBe(200);
    await page.arrayBuffer();
    expect(
      await s.child.install({
        locator: s.actor.locator,
        account: s.actor.account,
        vault: fixture.manifest.body.vault_id,
        epoch: 5,
        proof: fixture.proof as ControlProof,
        wraps: [],
        freeze: true,
        denied: [],
      }),
    ).toBe(200);
    expect(
      (await s.child.commitRekey(s.actor, fixture.manifest.body.rotation_id))
        .status,
    ).toBe(403);
    const fresh = { ...s.actor, epoch: 5 };
    expect(
      (await s.child.beginRekey(fresh, fixture.manifest, fixture.target_wraps))
        .status,
    ).toBe(403);
    expect(await (await s.child.rekeyStatus(fresh)).json()).toMatchObject({
      phase: "rekey_pending",
      epoch: 1,
      journal: null,
    });
    expect(
      ((await (await s.child.pull(fresh, 0)).json()) as any).records,
    ).toEqual(fixture.source_rows);
  });
  it("rolls back replacement if the final durable write fails and permits an exact retry", async () => {
    const s = await setup();
    await begin(s);
    expect(
      (
        await s.child.stageRekey(
          s.actor,
          fixture.manifest.body.rotation_id,
          "0",
          fixture.target_rows,
        )
      ).status,
    ).toBe(200);
    await runInDurableObject(s.child, async (_instance, state) => {
      state.storage.sql.exec(
        "CREATE TRIGGER fail_rekey BEFORE INSERT ON rekey_commits BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END",
      );
    });
    const failed = await runInDurableObject(s.child, async (instance) => {
      try {
        instance.commitRekey(s.actor, fixture.manifest.body.rotation_id);
        return false;
      } catch (error) {
        return String(error).includes("synthetic disk failure");
      }
    });
    expect(failed).toBe(true);
    expect(
      ((await (await s.child.pull(s.actor, 0)).json()) as any).records,
    ).toEqual(fixture.source_rows);
    expect(
      ((await (await s.child.metadata(s.actor)).json()) as any).epoch,
    ).toBe(1);
    await runInDurableObject(s.child, async (_instance, state) => {
      state.storage.sql.exec("DROP TRIGGER fail_rekey");
    });
    expect(
      (await s.child.commitRekey(s.actor, fixture.manifest.body.rotation_id))
        .status,
    ).toBe(200);
  });
});

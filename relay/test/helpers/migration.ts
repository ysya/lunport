import { env } from "cloudflare:workers";
import { expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import fixture from "../../../fixtures/central-sync-v2.json";
import {
  authorBytes,
  base64,
  canonical,
  hash,
  recordCanonical,
  wrapCanonical,
  type RecordEnvelope,
  type WrappedKeys,
} from "../../src/v2/protocol";
import { trustGenesis } from "../../src/v2/membership";
import { wrapsDigest } from "../../src/v2/rekey";
import {
  migrationCanonical,
  migrationScope,
  type SignedMigration,
  type MigrationSource,
} from "../../src/v2/migration";
import type { Principal } from "../../src/v2/auth";
export const random = (n = 32) =>
  Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
export const sign = (bytes: Uint8Array) =>
  base64(ed25519.sign(bytes, new Uint8Array(32).fill(1)));
export const zero = "0".repeat(64),
  tokenHash = "b".repeat(64);
export async function setup(
  sourceCount = 1,
  recordCount = 3,
  ciphertextBytes?: number,
  distinctRecords = recordCount,
) {
  const member = (await trustGenesis(fixture.genesis, fixture.anchor))!;
  const locator = random(),
    vault = random(),
    operation = random(16);
  const child = env.VAULT.getByName(member.anchor.account_id + ":" + vault);
  const actor: Principal = {
    locator,
    account: member.anchor.account_id,
    device: fixture.genesis.first.id,
    epoch: 1,
    session: random(16),
    expires: Date.now() + 300000,
  };
  const wraps: WrappedKeys[] = [];
  for (const [recipient, keys] of Object.entries({
    ...member.devices,
    recovery: member.recovery,
  })) {
    const wrapped: WrappedKeys = {
      ...fixture.wrap,
      header: {
        ...fixture.wrap.header,
        origin: member.anchor.origin,
        account_id: member.anchor.account_id,
        genesis_hash: member.anchor.genesis_hash,
        vault_id: vault,
        key_epoch: "1",
        membership_head: member.head,
        author: actor.device,
        recipient,
        recipient_key: keys.encryption,
      },
    };
    wrapped.signature = sign(
      await authorBytes(
        "lunport-wrap-author-v2",
        wrapCanonical(wrapped.header),
        wrapped.encapsulated_key,
        Uint8Array.from(atob(wrapped.ciphertext), (c) => c.charCodeAt(0)),
      ),
    );
    wraps.push(wrapped);
  }
  const install = {
    locator,
    account: actor.account,
    vault,
    epoch: 1,
    proof: { genesis: fixture.genesis, nodes: [] },
    wraps,
    freeze: false,
    denied: [] as string[],
  };
  expect(await child.install(install)).toBe(200);
  const records: RecordEnvelope[] = [];
  let historyHash = zero;
  const recordIds = Array.from({ length: distinctRecords }, () => random());
  for (let index = 0; index < recordCount; index++) {
    const envelope: RecordEnvelope = {
      ...fixture.record,
      ...(ciphertextBytes === undefined
        ? {}
        : { ciphertext: base64(new Uint8Array(ciphertextBytes)) }),
      header: {
        ...fixture.record.header,
        origin: member.anchor.origin,
        account_id: actor.account,
        genesis_hash: member.anchor.genesis_hash,
        vault_id: vault,
        key_epoch: "1",
        membership_head: member.head,
        author: actor.device,
        record_id: recordIds[index % distinctRecords],
        operation_id: random(16),
        expected_revision: String(Math.floor(index / distinctRecords)),
      },
    };
    envelope.signature = sign(
      await authorBytes(
        "lunport-record-author-v2",
        recordCanonical(envelope.header),
        envelope.nonce,
        Uint8Array.from(atob(envelope.ciphertext), (c) => c.charCodeAt(0)),
      ),
    );
    records.push(envelope);
    const digest = await hash(
      canonical([
        "lunport-operation-v2",
        new TextDecoder().decode(recordCanonical(envelope.header)),
        envelope.nonce,
        envelope.ciphertext,
        envelope.signature,
      ]),
    );
    historyHash = await hash(
      canonical(["lunport-history-v2", historyHash, String(index + 1), digest]),
    );
  }
  const body = {
    origin: member.anchor.origin,
    account_id: actor.account,
    genesis_hash: member.anchor.genesis_hash,
    vault_id: vault,
    migration_id: operation,
    authorization_epoch: "1",
    key_epoch: "1",
    membership_head: member.head,
    author: actor.device,
    inventory_digest: random(),
    target_sequence: String(recordCount),
    target_history_hash: historyHash,
    wraps_digest: await wrapsDigest(wraps),
    sources: [] as MigrationSource[],
  };
  for (let index = 0; index < sourceCount; index++) {
    const id = random(),
      legacy = env.CHAIN.getByName(id);
    expect(await legacy.create(tokenHash, id)).toBe(201);
    expect(
      (
        await legacy.push(
          tokenHash,
          [
            {
              idHash: random(),
              kind: "host",
              nonce: "bm9uY2U=",
              ciphertext: "Y2lwaGVy",
              deleted: false,
              baseSeq: 0,
            },
          ],
          id,
        )
      ).status,
    ).toBe(200);
    const frozen = await legacy.freezeForMigration(
      id,
      tokenHash,
      migrationScope(body),
    );
    expect(frozen.status).toBe(200);
    body.sources.push({
      chain_id: id,
      sequence: String(frozen.snapshot!.latestSeq),
      count: String(frozen.snapshot!.count),
      ciphertext_digest: frozen.snapshot!.digest,
    });
  }
  body.sources.sort((a, b) => a.chain_id.localeCompare(b.chain_id));
  const manifest: SignedMigration = {
    body,
    signature: sign(migrationCanonical(body)),
  };
  return { member, child, actor, manifest, records, operation, install };
}

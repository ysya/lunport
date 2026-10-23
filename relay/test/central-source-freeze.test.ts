import { describe, expect, it } from "vitest";
import { setup, random, sign } from "./helpers/migration";
import { freezeCanonical, type SignedFreeze } from "../src/v2/migration-freeze";
import { migrationCanonical } from "../src/v2/migration";

function intent(s: Awaited<ReturnType<typeof setup>>, chains: string[] = []): SignedFreeze {
  const body = {
    origin: s.manifest.body.origin,
    account_id: s.manifest.body.account_id,
    genesis_hash: s.manifest.body.genesis_hash,
    vault_id: s.manifest.body.vault_id,
    migration_id: s.manifest.body.migration_id,
    authorization_epoch: s.manifest.body.authorization_epoch,
    key_epoch: s.manifest.body.key_epoch,
    membership_head: s.manifest.body.membership_head,
    author: s.manifest.body.author,
    preview_digest: random(),
    parent_chain: "",
    revision: "1",
    previous_digest: "",
    chains,
  };
  return { body, signature: sign(freezeCanonical(body)) };
}

describe("central library source admission", () => {
  it("accepts signed empty-source setup and survives an exact retry", async () => {
    const s = await setup();
    const signed = intent(s);
    const first = await s.child.freezeSources(s.actor, signed, []);
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ phase: "frozen", sources: [] });
    const retry = await s.child.freezeSources(s.actor, signed, []);
    expect(retry.status).toBe(200);
  });

  it("rejects both legacy source claims and supplied chain credentials", async () => {
    const s = await setup();
    const chain = random();
    expect((await s.child.freezeSources(s.actor, intent(s, [chain]), [])).status).toBe(410);
    expect((await s.child.freezeSources(s.actor, intent(s), [{ chain, token: random() }])).status).toBe(410);
    expect((await s.child.freezeStatus(s.actor)).status).toBe(404);

    const manifest = structuredClone(s.manifest);
    manifest.body.sources = [{ chain_id: chain, sequence: "0", count: "0", ciphertext_digest: random() }];
    manifest.signature = sign(migrationCanonical(manifest.body));
    expect((await s.child.beginMigration(s.actor, manifest)).status).toBe(410);
  });
});

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import fixture from "../../fixtures/central-migration-library-v2.json";
import {
  base64,
  decode,
  hash,
  recordCanonical,
  wrapCanonical,
  type WrappedKeys,
} from "../src/v2/protocol";
import { verifyControl, type ControlProof } from "../src/v2/store";
import { verifyMigration } from "../src/v2/migration";
import { wrapsDigest } from "../src/v2/rekey";
import type { Principal } from "../src/v2/auth";
const responseJson = async (response: Response) => {
  expect(response.status).toBe(200);
  return (await response.json()) as any;
};
async function unwrap(wrap: WrappedKeys, seed: number): Promise<Uint8Array> {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  const context = wrapCanonical(wrap.header);
  return new Uint8Array(
    await suite.open(
      {
        recipientKey: await suite.kem.deserializePrivateKey(
          new Uint8Array(32).fill(seed),
        ),
        enc: decode(wrap.encapsulated_key, 32, 32),
        info: context,
      },
      decode(wrap.ciphertext, 80, 80),
      context,
    ),
  );
}
function cipherName(privateKey: string): string {
  const encoded = privateKey
    .trim()
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("-----"))
    .join("");
  const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
  expect(new TextDecoder().decode(bytes.slice(0, 15))).toBe("openssh-key-v1\0");
  const size = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  ).getUint32(15, false);
  return new TextDecoder().decode(bytes.slice(19, 19 + size));
}
describe("native prepared initial library across the real service", () => {
  it("accepts exact fresh wraps and keeps encrypted inactive private history without interim activation", async () => {
    const body = fixture.manifest.body,
      member = (await verifyControl(fixture.proof as ControlProof))!;
    expect(
      await verifyMigration(
        member,
        fixture.manifest,
        1,
        1,
        body.vault_id,
        fixture.device,
      ),
    ).toBe(true);
    const child = env.VAULT.getByName(body.account_id + ":" + body.vault_id);
    const actor: Principal = {
      locator: fixture.locator,
      account: body.account_id,
      device: fixture.device,
      epoch: 1,
      session: "f".repeat(32),
      expires: Date.now() + 300000,
    };
    expect(
      await child.install({
        locator: fixture.locator,
        account: body.account_id,
        vault: body.vault_id,
        epoch: 1,
        proof: fixture.proof as ControlProof,
        wraps: fixture.original_wraps,
        freeze: false,
        denied: [],
      }),
    ).toBe(200);
    expect(await wrapsDigest(fixture.original_wraps)).not.toBe(
      body.wraps_digest,
    );
    expect((await child.beginMigration(actor, fixture.manifest)).status).toBe(
      409,
    );
    for (const bad of [
      fixture.wraps.slice(0, 1),
      [fixture.wraps[0], fixture.wraps[0]],
      fixture.wraps.map((w) => ({
        ...w,
        header: { ...w.header, key_epoch: "2" },
      })),
    ])
      expect(
        (await child.beginMigration(actor, fixture.manifest, bad)).status,
      ).toBe(403);
    expect((await responseJson(await child.metadata(actor))).sequence).toBe(
      "0",
    );
    const own = fixture.wraps.find(
      (w) => w.header.recipient === fixture.device,
    )!;
    const recovery = fixture.wraps.find(
      (w) => w.header.recipient === "recovery",
    )!;
    const keys = await unwrap(own, 1),
      prior = await unwrap(
        fixture.original_wraps.find(
          (w) => w.header.recipient === fixture.device,
        )!,
        1,
      ),
      recovered = await unwrap(recovery, 4);
    expect(
      base64(keys) === base64(prior) && base64(keys) === base64(recovered),
    ).toBe(true);
    const decoded = fixture.rows.map((row) => ({
      header: row.envelope.header,
      value: JSON.parse(
        new TextDecoder().decode(
          xchacha20poly1305(
            keys.slice(32),
            decode(row.envelope.nonce, 24, 24),
            recordCanonical(row.envelope.header),
          ).decrypt(decode(row.envelope.ciphertext, 16, 65552)),
        ),
      ),
    }));
    const privateRows = decoded.filter((row) => row.header.kind === "key");
    expect(privateRows).toHaveLength(2);
    for (const row of privateRows) {
      const metadata = decoded.find(
        (publicRow) =>
          publicRow.header.kind === "keyslot" &&
          !publicRow.header.deleted &&
          publicRow.value.id === row.value.id,
      )!.value.payload;
      expect(
        await hash(new TextEncoder().encode(row.value.payload.private_key)),
      ).toBe(metadata.storage.sha256);
      expect(cipherName(row.value.payload.private_key) !== "none").toBe(
        metadata.public.has_passphrase,
      );
    }
    expect(
      privateRows.some(
        (row) =>
          row.value.id === "2".repeat(32) &&
          cipherName(row.value.payload.private_key) !== "none",
      ),
    ).toBe(true);
    expect(
      decoded.some(
        (row) =>
          row.header.kind === "keyslot" &&
          row.header.deleted &&
          row.value.id === "2".repeat(32),
      ),
    ).toBe(true);
    await responseJson(
      await child.beginMigration(actor, fixture.manifest, fixture.wraps),
    );
    await responseJson(
      await child.beginMigration(actor, fixture.manifest, fixture.wraps),
    );
    const hidden = await child.wrap(actor);
    expect(hidden.status).toBe(423);
    await hidden.body?.cancel();
    await responseJson(
      await child.stageMigration(
        actor,
        body.migration_id,
        "0",
        fixture.rows.slice(0, 3).map((row) => row.envelope),
      ),
    );
    expect((await child.commitMigration(actor, body.migration_id)).status).toBe(
      409,
    );
    await responseJson(
      await child.stageMigration(
        actor,
        body.migration_id,
        "3",
        fixture.rows.slice(3).map((row) => row.envelope),
      ),
    );
    const receipt = await responseJson(
      await child.commitMigration(actor, body.migration_id),
    );
    expect(receipt.phase).toBe("retired");
    expect(receipt.history_hash).toBe(body.target_history_hash);
    expect((await responseJson(await child.pull(actor, 0))).records).toEqual(
      fixture.rows,
    );
    expect(await responseJson(await child.wrap(actor))).toEqual(own);
    expect(
      (
        await responseJson(
          await child.operationReceipt(
            actor,
            fixture.rows.at(-1)!.envelope.header.operation_id,
          ),
        )
      ).revision,
    ).toBe("2");
    keys.fill(0);
    prior.fill(0);
    recovered.fill(0);
  });
});

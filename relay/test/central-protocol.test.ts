import { describe, expect, it } from "vitest";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import fixture from "../../fixtures/central-sync-v2.json";
import {
  base64,
  decode,
  recordCanonical,
  safeNumber,
  verify,
  verifyRecord,
  verifyWrap,
  wrapCanonical,
} from "../src/v2/protocol";

describe("central protocol Rust / Worker interop", () => {
  it("emits byte-identical authenticated headers and verifies Rust author signatures", async () => {
    expect(base64(recordCanonical(fixture.record.header))).toBe(
      fixture.record_aad_base64,
    );
    expect(base64(wrapCanonical(fixture.wrap.header))).toBe(
      fixture.wrap_context_base64,
    );
    expect(
      await verifyRecord(fixture.record, fixture.author_public.signing),
    ).toBe(true);
    expect(await verifyWrap(fixture.wrap, fixture.author_public.signing)).toBe(
      true,
    );
    const reordered = Object.fromEntries(
      Object.entries(fixture.record.header).reverse(),
    );
    expect(
      base64(recordCanonical(reordered as typeof fixture.record.header)),
    ).toBe(fixture.record_aad_base64);
  });
  it("opens Rust HPKE and XChaCha ciphertext with independent implementations", async () => {
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Chacha20Poly1305(),
    });
    const recipient = await suite.kem.deserializePrivateKey(
      decode(fixture.recipient_secret, 64, 64).slice(32),
    );
    const context = wrapCanonical(fixture.wrap.header);
    const keys = new Uint8Array(
      await suite.open(
        {
          recipientKey: recipient,
          enc: decode(fixture.wrap.encapsulated_key, 32, 32),
          info: context,
        },
        decode(fixture.wrap.ciphertext, 80, 80),
        context,
      ),
    );
    expect(base64(keys)).toBe(fixture.vault_keys);
    const opened = xchacha20poly1305(
      keys.slice(32),
      decode(fixture.record.nonce, 24, 24),
      recordCanonical(fixture.record.header),
    ).decrypt(decode(fixture.record.ciphertext, 16, 65552));
    expect(new TextDecoder().decode(opened)).toBe(fixture.plaintext);
    const altered = context.slice();
    altered[0] ^= 1;
    await expect(
      suite.open(
        {
          recipientKey: recipient,
          enc: decode(fixture.wrap.encapsulated_key, 32, 32),
          info: altered,
        },
        decode(fixture.wrap.ciphertext, 80, 80),
        altered,
      ),
    ).rejects.toThrow();
  });
  it("rejects substitution of every record context field, ciphertext and nonce", async () => {
    for (const field of Object.keys(fixture.record.header) as Array<
      keyof typeof fixture.record.header
    >) {
      const envelope = structuredClone(fixture.record);
      if (field === "deleted") envelope.header.deleted = true;
      else if (field === "origin")
        envelope.header.origin = "https://other.example";
      else if (field === "kind") envelope.header.kind = "key";
      else if (field === "key_epoch" || field === "expected_revision")
        envelope.header[field] = "2";
      else envelope.header[field] = "9".repeat(envelope.header[field].length);
      expect(
        await verifyRecord(envelope, fixture.author_public.signing),
        field,
      ).toBe(false);
    }
    for (const field of ["nonce", "ciphertext"] as const) {
      const envelope = structuredClone(fixture.record);
      const data = decode(envelope[field], 0, 65552);
      data[0] ^= 1;
      envelope[field] = base64(data);
      expect(await verifyRecord(envelope, fixture.author_public.signing)).toBe(
        false,
      );
    }
  });
  it("rejects key-wrap recipient, epoch and author substitutions", async () => {
    for (const field of Object.keys(fixture.wrap.header) as Array<
      keyof typeof fixture.wrap.header
    >) {
      const wrapped = structuredClone(fixture.wrap);
      if (field === "origin") wrapped.header.origin = "https://other.example";
      else if (field === "key_epoch") wrapped.header.key_epoch = "2";
      else if (field === "recipient_key")
        wrapped.header.recipient_key = fixture.author_public.encryption;
      else wrapped.header[field] = "9".repeat(wrapped.header[field].length);
      expect(
        await verifyWrap(wrapped, fixture.author_public.signing),
        field,
      ).toBe(false);
    }
  });
  it("rejects weak identity-key forgeries, ambiguous integers and oversized encodings", async () => {
    const publicKey = new Uint8Array(32);
    publicKey[0] = 1;
    const signature = new Uint8Array(64);
    signature[0] = 1;
    expect(
      await verify(
        base64(publicKey),
        new TextEncoder().encode("synthetic weak-key probe"),
        base64(signature),
      ),
    ).toBe(false);
    for (const value of ["01", "-1", "1.0", "1e2", "9007199254740992"])
      expect(() => safeNumber(value, true)).toThrow();
    expect(() => decode("AQ", 1, 1)).toThrow();
    expect(() => decode("A".repeat(1000000), 0, 65552)).toThrow();
    expect(
      await verifyRecord(
        { ...fixture.record, extra: true } as typeof fixture.record,
        fixture.author_public.signing,
      ),
    ).toBe(false);
  });
});

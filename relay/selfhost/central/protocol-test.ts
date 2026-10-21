/** Synthetic real HTTP deployment check. Bundle for Node with the locked relay dependencies. */
import assert from "node:assert/strict";
import { randomBytes, createHmac } from "node:crypto";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import fixture from "../../../fixtures/central-migration-library-v2.json";
import {
  authorBytes,
  base64,
  canonical,
  decode,
  hash,
  recordCanonical,
  wrapCanonical,
} from "../../src/v2/protocol";
import {
  genesisCanonical,
  trustGenesis,
  enrollmentCanonical,
  membershipCanonical,
  applyMembership,
} from "../../src/v2/membership";
import { unlockCanonical, type SignedUnlock } from "../../src/v2/unlock";
import { freezeCanonical } from "../../src/v2/migration-freeze";
import { migrationCanonical } from "../../src/v2/migration";
import { rekeyCanonical, wrapsDigest } from "../../src/v2/rekey";
const random = (bytes = 32) => randomBytes(bytes).toString("hex");
const sign = (bytes: Uint8Array, seed = 1) =>
  base64(ed25519.sign(bytes, new Uint8Array(32).fill(seed)));
export async function checkCentralProtocol({
  address,
  origin,
  loginToken,
  beforeSecurityChange,
}: {
  address: string;
  origin: string;
  loginToken: string;
  beforeSecurityChange?: () => Promise<void>;
}) {
  const request = async (path: string, bearer: string, value?: unknown) =>
    fetch(`http://${address}${path}`, {
      method: value === undefined ? "GET" : "POST",
      headers: {
        authorization: `Bearer ${bearer}`,
        "content-type": "application/json",
      },
      ...(value === undefined ? {} : { body: JSON.stringify(value) }),
      signal: AbortSignal.timeout(15000),
    });
  const json = async (response: Response) => {
    assert.equal(response.status, 200, await response.clone().text());
    return response.json() as Promise<any>;
  };
  const firstDevice = fixture.proof.genesis.first;
  const peer = {
    id: random(16),
    keys: {
      signing: base64(ed25519.getPublicKey(new Uint8Array(32).fill(6))),
      encryption: base64(x25519.getPublicKey(new Uint8Array(32).fill(6))),
    },
  };
  const credentials = new Map([
    [firstDevice.id, random()],
    [peer.id, random()],
  ]);
  const register = async (device: typeof peer) => {
    const sessionId = random(16),
      secret = random();
    const info = await json(
      await request("/v2/register", loginToken, {
        device,
        name: "Synthetic deployment device",
        credential: credentials.get(device.id),
        session_id: sessionId,
        session_secret: secret,
      }),
    );
    return {
      info,
      bearer: `v2.${info.account_locator}.${sessionId}.${secret}`,
    };
  };
  let first = await register(firstDevice);
  const genesis = {
    ...fixture.proof.genesis,
    origin,
    account_id: first.info.account_id,
  };
  const genesisBytes = genesisCanonical(genesis);
  genesis.device_signature = sign(genesisBytes);
  genesis.recovery_signature = sign(genesisBytes, 4);
  const anchor = {
    origin,
    account_id: first.info.account_id,
    genesis_hash: await hash(genesisBytes),
  };
  let member = (await trustGenesis(genesis, anchor))!;
  assert.ok(member);
  const vault = random();
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  const oldWrap = fixture.wraps.find(
    (w) => w.header.recipient === firstDevice.id,
  )!;
  const oldContext = wrapCanonical(oldWrap.header);
  const keys = new Uint8Array(
    await suite.open(
      {
        recipientKey: await suite.kem.deserializePrivateKey(
          new Uint8Array(32).fill(1),
        ),
        enc: decode(oldWrap.encapsulated_key, 32, 32),
        info: oldContext,
      },
      decode(oldWrap.ciphertext, 80, 80),
      oldContext,
    ),
  );
  const wrap = async (trusted: typeof member, epoch = "1", author = firstDevice.id, seed = 1) => {
    const result = [];
    for (const [recipient, publicKeys] of Object.entries({
      ...trusted.devices,
      recovery: trusted.recovery,
    })) {
      const header = {
        origin,
        account_id: anchor.account_id,
        genesis_hash: anchor.genesis_hash,
        vault_id: vault,
        key_epoch: epoch,
        membership_head: trusted.head,
        author,
        recipient,
        recipient_key: publicKeys.encryption,
      };
      const context = wrapCanonical(header);
      const sealed = await suite.seal(
        {
          recipientPublicKey: await suite.kem.deserializePublicKey(
            decode(publicKeys.encryption, 32, 32),
          ),
          info: context,
        },
        keys,
        context,
      );
      const ciphertext = base64(new Uint8Array(sealed.ct)),
        encapsulated_key = base64(new Uint8Array(sealed.enc));
      result.push({
        header,
        ciphertext,
        encapsulated_key,
        signature: sign(
          await authorBytes(
            "lunport-wrap-author-v2",
            context,
            encapsulated_key,
            new Uint8Array(sealed.ct),
          ),
          seed,
        ),
      });
    }
    return result;
  };
  const wraps = await wrap(member);
  await json(
    await request("/v2/bootstrap", first.bearer, { genesis, vault, wraps }),
  );
  first = await register(firstDevice);
  const path = `/v2/vaults/${vault}/`;
  const chain = random(),
    legacyToken = random();
  const created = await fetch(`http://${address}/v1/chains/${chain}`, {
    method: "PUT",
    headers: { authorization: `Bearer ${legacyToken}` },
  });
  assert.equal(created.status, 201);
  await created.arrayBuffer();
  const operation = random(16),
    preview = random();
  const freeze = {
    body: {
      origin,
      account_id: anchor.account_id,
      genesis_hash: anchor.genesis_hash,
      vault_id: vault,
      migration_id: operation,
      authorization_epoch: String(first.info.auth_epoch),
      key_epoch: "1",
      membership_head: member.head,
      author: firstDevice.id,
      preview_digest: preview,
      parent_chain: chain,
      revision: "1",
      previous_digest: "",
      chains: [chain],
    },
    signature: "",
  };
  freeze.signature = sign(freezeCanonical(freeze.body));
  const frozen = await json(
    await request(path + "migration/freeze", first.bearer, {
      intent: freeze,
      credentials: [{ chain, token: legacyToken }],
    }),
  );
  assert.equal(frozen.phase, "frozen");
  let history = "0".repeat(64);
  const original: Uint8Array[] = [];
  const rows = [];
  for (const row of fixture.rows) {
    const old = row.envelope;
    const plain = xchacha20poly1305(
      keys.slice(32),
      decode(old.nonce, 24, 24),
      recordCanonical(old.header),
    ).decrypt(decode(old.ciphertext, 16, 65552));
    original.push(plain);
    const header = {
      ...old.header,
      origin,
      account_id: anchor.account_id,
      genesis_hash: anchor.genesis_hash,
      vault_id: vault,
      membership_head: member.head,
      author: firstDevice.id,
    };
    const ciphertextBytes = xchacha20poly1305(
      keys.slice(32),
      decode(old.nonce, 24, 24),
      recordCanonical(header),
    ).encrypt(plain);
    const envelope = {
      header,
      nonce: old.nonce,
      ciphertext: base64(ciphertextBytes),
      signature: sign(
        await authorBytes(
          "lunport-record-author-v2",
          recordCanonical(header),
          old.nonce,
          ciphertextBytes,
        ),
      ),
    };
    rows.push(envelope);
    const digest = await hash(
      canonical([
        "lunport-operation-v2",
        new TextDecoder().decode(recordCanonical(header)),
        envelope.nonce,
        envelope.ciphertext,
        envelope.signature,
      ]),
    );
    history = await hash(
      canonical(["lunport-history-v2", history, String(rows.length), digest]),
    );
  }
  assert.ok(
    original.some((bytes) =>
      new TextDecoder().decode(bytes).includes("OPENSSH PRIVATE KEY"),
    ),
  );
  const manifest = {
    body: {
      ...fixture.manifest.body,
      origin,
      account_id: anchor.account_id,
      genesis_hash: anchor.genesis_hash,
      vault_id: vault,
      migration_id: operation,
      authorization_epoch: String(first.info.auth_epoch),
      membership_head: member.head,
      author: firstDevice.id,
      inventory_digest: random(),
      target_sequence: String(rows.length),
      target_history_hash: history,
      wraps_digest: await wrapsDigest(wraps),
      sources: frozen.sources,
    },
    signature: "",
  };
  manifest.signature = sign(migrationCanonical(manifest.body));
  await json(
    await request(path + "migration/begin", first.bearer, { manifest, wraps }),
  );
  for (let after = 0; after < rows.length; after += 32)
    await json(
      await request(path + "migration/stage", first.bearer, {
        migration: operation,
        after: String(after),
        rows: rows.slice(after, after + 32),
      }),
    );
  await json(
    await request(path + "migration/commit", first.bearer, {
      migration: operation,
    }),
  );
  assert.equal(
    (
      await json(
        await request(path + "migration/retire", first.bearer, {
          migration: operation,
        }),
      )
    ).phase,
    "retired",
  );
  const info = await json(await fetch(`http://${address}/v2/info`));
  assert.ok(info.features.includes("account-unlock-v1"));
  // Ciphertext is opaque to the service; native integration tests exercise password decryption.
  const registry: SignedUnlock = { body: {
    version: 1, anchor, revision: "1", previous_digest: "", membership_head: member.head,
    authorization_epoch: String(first.info.auth_epoch), author: firstDevice.id, recovery: member.recovery,
    slots: [{header:{version:1,anchor,generation:"1",binding:{kind:"password"},salt:base64(randomBytes(32))},
      nonce:base64(randomBytes(24)),ciphertext:base64(randomBytes(64))}],
  }, signature: "" };
  registry.signature = sign(unlockCanonical(registry.body));
  await json(await request("/v2/unlock", first.bearer, {registry}));
  assert.deepEqual((await json(await request("/v2/unlock", first.bearer))).registry,registry);
  let other = await register(peer);
  assert.equal(other.info.device_state, "pending");
  const denied = await request(path + "records", other.bearer);
  assert.equal(denied.status, 403);
  await denied.arrayBuffer();
  const now = Date.now();
  const enrollment = {
    origin,
    account_id: anchor.account_id,
    genesis_hash: anchor.genesis_hash,
    request_id: random(16),
    device: peer,
    nonce: random(),
    created_at_ms: String(now - 100),
    expires_at_ms: String(now + 300000),
    signature: "",
  };
  enrollment.signature = sign(enrollmentCanonical(enrollment), 6);
  const en = await request("/v2/enrollment", other.bearer, {
    request: enrollment,
  });
  assert.equal(en.status, 204);
  await en.arrayBuffer();
  assert.deepEqual((await json(await request("/v2/unlock", other.bearer))).registry,registry);
  const readProof = { request_id: enrollment.request_id, membership_head: member.head,
    auth_epoch: String(other.info.auth_epoch), signature: sign(canonical([
      "lunport-recovery-read-v2", origin, anchor.account_id, anchor.genesis_hash, member.head,
      String(other.info.auth_epoch), base64(enrollmentCanonical(enrollment)), enrollment.signature,
    ]), 4) };
  const snapshot = await json(await request("/v2/recovery/wraps", other.bearer, {proof:readProof}));
  assert.ok(snapshot);
  const node = {
    body: {
      origin,
      account_id: anchor.account_id,
      genesis_hash: anchor.genesis_hash,
      revision: "1",
      previous_head: member.head,
      author: "recovery",
      action: "unlock" as const,
      issued_at_ms: String(now),
      enrollment,
      devices: { ...member.devices, [peer.id]: peer.keys },
      recovery: member.recovery,
    },
    signature: "",
  };
  node.signature = sign(membershipCanonical(node.body), 4);
  member = (await applyMembership(member, node))!;
  assert.ok(member);
  const minimum = {
    vault,
    creation_head: anchor.genesis_hash,
    creation_authorization_epoch: String(first.info.auth_epoch),
    key_epoch: "1",
    sequence: String(rows.length),
    history_hash: history,
  };
  const minimumBytes = new TextEncoder().encode(
    JSON.stringify([
      [
        minimum.vault,
        minimum.creation_head,
        minimum.creation_authorization_epoch,
        minimum.key_epoch,
        minimum.sequence,
        minimum.history_hash,
      ],
    ]),
  );
  const confirmationBytes = canonical([
    "lunport-pairing-confirmation-v2",
    base64(enrollmentCanonical(enrollment)),
    enrollment.signature,
    member.head,
    vault,
    base64(minimumBytes),
  ]);
  const secret = randomBytes(32),
    mac = createHmac("sha256", secret)
      .update(confirmationBytes)
      .digest("base64");
  const confirmation = {
    request_id: enrollment.request_id,
    approved_head: member.head,
    personal_vault: vault,
    minimums: [minimum],
    mac,
  };
  const peerWraps = await wrap(member, "1", peer.id, 6);
  await json(
    await request("/v2/unlock/join", other.bearer, {
      node,
      wraps: { [vault]: peerWraps },
      confirmation,
      read_proof: readProof,
    }),
  );
  first = await register(firstDevice);
  other = await register(peer);
  assert.equal(other.info.device_state, "active");
  const overview = await json(await request("/v2/account", other.bearer));
  assert.deepEqual(overview.pairing_confirmation, confirmation);
  assert.equal(
    createHmac("sha256", secret).update(confirmationBytes).digest("base64"),
    overview.pairing_confirmation.mac,
  );
  const own = await json(await request(path + "wrap", other.bearer));
  const context = wrapCanonical(own.header);
  const peerKeys = new Uint8Array(
    await suite.open(
      {
        recipientKey: await suite.kem.deserializePrivateKey(
          new Uint8Array(32).fill(6),
        ),
        enc: decode(own.encapsulated_key, 32, 32),
        info: context,
      },
      decode(own.ciphertext, 80, 80),
      context,
    ),
  );
  assert.deepEqual(peerKeys, keys);
  const page = await json(await request(path + "records", other.bearer));
  assert.equal(page.sequence, String(rows.length));
  assert.equal(page.history_hash, history);
  assert.equal(page.records.length, rows.length);
  for (const [index, row] of page.records.entries())
    assert.deepEqual(
      xchacha20poly1305(
        peerKeys.slice(32),
        decode(row.envelope.nonce, 24, 24),
        recordCanonical(row.envelope.header),
      ).decrypt(decode(row.envelope.ciphertext, 16, 65552)),
      original[index],
    );
  await beforeSecurityChange?.();
  await json(
    await request("/v2/device-access/revoke", loginToken, { device: peer.id }),
  );
  const revoked = await request(path + "records", other.bearer);
  assert.ok([401, 403].includes(revoked.status));
  await revoked.arrayBuffer();
  const retired = await request(`/v1/chains/${chain}/records`, legacyToken);
  assert.equal(retired.status, 410);
  await retired.arrayBuffer();
  first = await register(firstDevice);
  const removal = {
    body: {
      ...node.body,
      author: firstDevice.id,
      revision: "2",
      previous_head: member.head,
      action: "revoke" as const,
      issued_at_ms: String(Date.now()),
      enrollment: null,
      devices: { [firstDevice.id]: firstDevice.keys },
    },
    signature: "",
  };
  removal.signature = sign(membershipCanonical(removal.body));
  await json(
    await request("/v2/membership", first.bearer, { node: removal, wraps: {}, confirmation: null }),
  );
  member = (await applyMembership(member, removal))!;
  assert.ok(member);
  first = await register(firstDevice);
  const source = await json(await request(path + "records", first.bearer));
  keys.set(randomBytes(32), 32); // Preserve the index key and rotate only content encryption.
  const nextWraps = await wrap(member, "2");
  let nextHistory = "0".repeat(64);
  const staged = [];
  for (const [index, row] of source.records.entries()) {
    const header = {
      ...row.envelope.header,
      key_epoch: "2",
      membership_head: member.head,
      author: firstDevice.id,
    };
    const nonce = base64(randomBytes(24));
    const ciphertext = xchacha20poly1305(
      keys.slice(32),
      decode(nonce, 24, 24),
      recordCanonical(header),
    ).encrypt(original[index]);
    const envelope = {
      header,
      nonce,
      ciphertext: base64(ciphertext),
      signature: sign(
        await authorBytes(
          "lunport-record-author-v2",
          recordCanonical(header),
          nonce,
          ciphertext,
        ),
      ),
    };
    const digest = await hash(
      canonical([
        "lunport-operation-v2",
        new TextDecoder().decode(recordCanonical(header)),
        nonce,
        envelope.ciphertext,
        envelope.signature,
      ]),
    );
    nextHistory = await hash(
      canonical(["lunport-history-v2", nextHistory, String(index + 1), digest]),
    );
    staged.push({
      sequence: String(index + 1),
      revision: row.revision,
      envelope,
      digest,
      history_hash: nextHistory,
    });
  }
  const rekey = {
    body: {
      origin,
      account_id: anchor.account_id,
      genesis_hash: anchor.genesis_hash,
      vault_id: vault,
      rotation_id: random(16),
      authorization_epoch: String(first.info.auth_epoch),
      from_epoch: "1",
      to_epoch: "2",
      membership_head: member.head,
      author: firstDevice.id,
      source_sequence: source.sequence,
      source_history_hash: source.history_hash,
      target_history_hash: nextHistory,
      wraps_digest: await wrapsDigest(nextWraps),
    },
    signature: "",
  };
  rekey.signature = sign(rekeyCanonical(rekey.body));
  await json(
    await request(path + "rekey/begin", first.bearer, {
      manifest: rekey,
      wraps: nextWraps,
    }),
  );
  for (let after = 0; after < staged.length; after += 32)
    await json(
      await request(path + "rekey/stage", first.bearer, {
        rotation: rekey.body.rotation_id,
        after: String(after),
        rows: staged.slice(after, after + 32),
      }),
    );
  await json(
    await request(path + "rekey/commit", first.bearer, {
      rotation: rekey.body.rotation_id,
    }),
  );
  await json(await request(path + "rekey/reconcile", first.bearer, {}));
  const surviving = await json(await request(path + "records", first.bearer));
  assert.ok(
    surviving.records.every(
      (row: any) => row.envelope.header.key_epoch === "2",
    ),
  );
  assert.equal(surviving.history_hash, nextHistory);
  assert.deepEqual(
    surviving.records.map((row: any) => row.envelope),
    staged.map((row) => row.envelope),
  );
  for (const [index, row] of surviving.records.entries()) {
    assert.deepEqual(
      xchacha20poly1305(
        keys.slice(32),
        decode(row.envelope.nonce, 24, 24),
        recordCanonical(row.envelope.header),
      ).decrypt(decode(row.envelope.ciphertext, 16, 65552)),
      original[index],
    );
    assert.throws(() =>
      xchacha20poly1305(
        peerKeys.slice(32),
        decode(row.envelope.nonce, 24, 24),
        recordCanonical(row.envelope.header),
      ).decrypt(decode(row.envelope.ciphertext, 16, 65552)),
    );
  }
  const survivingWrap = await json(await request(path + "wrap", first.bearer));
  keys.fill(0);
  peerKeys.fill(0);
  secret.fill(0);
  original.forEach((bytes) => bytes.fill(0));
  console.log(
    "PASS: deployed central encrypted migration, permanent legacy retirement, signed password envelope readback, additive account unlock, pending-device denial, peer decryption, device revocation and epoch-2 content rotation",
  );
  return {
    positive: {
      path: path + "records",
      token: first.bearer,
      sequence: String(rows.length),
      history_hash: nextHistory,
      key_epoch: "2",
      envelopes: staged.map((row) => row.envelope),
    },
    wrapped: { path: path + "wrap", token: first.bearer, value: survivingWrap },
    denials: [
      { path: path + "records", token: other.bearer, status: revoked.status },
      { path: `/v1/chains/${chain}/records`, token: legacyToken, status: 410 },
    ],
  };
}

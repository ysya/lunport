import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";
import { hash } from "../src/v2/protocol";
import { REGISTRY_WITNESS } from "../src/security/floor";
import { authorityWitness } from "../src/security/authority";
import { verifyAuthorityImport } from "../selfhost/central/authority-check";
import control from "../selfhost/central/control";
const installation = "a".repeat(32),
  roles = ["accounts", "vaults", "passkeys"];
async function fixture(selected = installation) {
  const bytes = new Uint8Array([1, 2, 3]);
  const namespaces = await Promise.all(
    roles.map(async (role) => ({
      role,
      name: `lunport-${selected}-${role}`,
      files: [
        {
          name: "b".repeat(64) + ".sqlite",
          bytes: bytes.length,
          sha256: await hash(bytes),
        },
      ],
    })),
  );
  const value = { version: 1, installation: selected, namespaces },
    sha256 = await hash(new TextEncoder().encode(JSON.stringify(value)));
  const storage = {
    fetch: async (request: Request) => {
      const name = new URL(request.url).pathname;
      if (name === "/")
        return Response.json(
          namespaces.map((ns) => ({ name: ns.name, type: "directory" })),
        );
      for (const ns of namespaces) {
        if (name === `/${ns.name}/`)
          return Response.json(
            ns.files.map((file) => ({ name: file.name, type: "file" })),
          );
        if (name === `/${ns.name}/${ns.files[0].name}`)
          return new Response(bytes, {
            headers: { "content-length": String(bytes.length) },
          });
      }
      return new Response(null, { status: 404 });
    },
  } as Fetcher;
  return { value, sha256, storage, text: JSON.stringify({ value, sha256 }) };
}
it("verifies every fixed namespace and database byte before permitting a private handoff", async () => {
  const f = await fixture();
  await verifyAuthorityImport(installation, f.sha256, f.text, f.storage);
  for (const kind of ["hash", "missing", "extra", "link", "bytes", "scope"]) {
    const storage = {
      fetch: async (request: Request) => {
        const name = new URL(request.url).pathname;
        if (kind === "scope") return new Response(null, { status: 404 });
        if (name.includes(".sqlite")) {
          if (kind === "hash")
            return new Response(new Uint8Array([1, 2, 4]), {
              headers: { "content-length": "3" },
            });
          if (kind === "bytes")
            return new Response(new Uint8Array([1, 2]), {
              headers: { "content-length": "3" },
            });
        }
        if (name.endsWith("accounts/")) {
          if (kind === "missing") return Response.json([]);
          if (kind === "extra")
            return Response.json([
              { name: f.value.namespaces[0].files[0].name, type: "file" },
              { name: "unknown", type: "file" },
            ]);
          if (kind === "link")
            return Response.json([
              { name: f.value.namespaces[0].files[0].name, type: "symlink" },
            ]);
        }
        return f.storage.fetch(request);
      },
    } as Fetcher;
    await expect(
      verifyAuthorityImport(installation, f.sha256, f.text, storage),
    ).rejects.toThrow();
  }
  await expect(
    verifyAuthorityImport("c".repeat(32), f.sha256, f.text, f.storage),
  ).rejects.toThrow();
  await expect(
    verifyAuthorityImport(installation, "f".repeat(64), f.text, f.storage),
  ).rejects.toThrow();
});
it("cannot bind an older floor without exact independently read-back import evidence", async () => {
  const id = crypto.randomUUID().replaceAll("-", ""),
    f = await fixture(id);
  const value = f.value,
    receipt = f.sha256,
    storage = f.storage;
  const registry =
      env.LEGACY_RETIREMENT.idFromName(REGISTRY_WITNESS).toString(),
    floor = env.SECURITY_FLOOR.getByName("floor:" + id);
  await runInDurableObject(floor, (_instance, state) =>
    state.storage.put("floor", {
      version: 1,
      installation: id,
      minimum: 1,
      registry,
    }),
  );
  const settings = {
    ...env,
    SECURITY_INSTALLATION: id,
    SELFHOST_CONTROL_MODE: "bind-authority",
    SELFHOST_EXPECTED_REGISTRY: registry,
    SELFHOST_EXPECTED_AUTHORITY: authorityWitness(env),
    SELFHOST_AUTHORITY_RECEIPT: receipt,
    SELFHOST_AUTHORITY_IMPORT: JSON.stringify({ value, sha256: receipt }),
    AUTHORITY_READ: storage,
  };
  await expect(
    control.test({}, { ...settings, AUTHORITY_READ: undefined }),
  ).rejects.toThrow();
  expect((await floor.authorize(id)).status).toBe(503);
  await control.test({}, settings);
  expect((await floor.authorize(id)).status).toBe(200);
});

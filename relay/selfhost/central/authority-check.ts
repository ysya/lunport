/** Private, stopped-runtime readback only. Never fetch a path supplied in a receipt. */
import { exactObject, hash, hex } from "../../src/v2/protocol";
const roles = ["accounts", "vaults", "passkeys"],
  file = /^(?:[0-9a-f]{64}|metadata)\.sqlite(?:-wal|-shm)?$/;
const invalid = () =>
  new Error(
    "Authoritative storage handoff evidence does not match the retained installation.",
  );
export async function verifyAuthorityImport(
  installation: string,
  expected: string,
  text: string,
  storage: Fetcher,
): Promise<void> {
  if (
    !hex(installation, 32) ||
    !hex(expected, 64) ||
    new TextEncoder().encode(text).length > 4 * 1024 * 1024
  )
    throw invalid();
  const receipt = JSON.parse(text) as any,
    value = receipt?.value;
  if (
    !exactObject(receipt, ["value", "sha256"]) ||
    receipt.sha256 !== expected ||
    !exactObject(value, ["version", "installation", "namespaces"]) ||
    value.version !== 1 ||
    value.installation !== installation ||
    !Array.isArray(value.namespaces) ||
    value.namespaces.length !== 3 ||
    (await hash(new TextEncoder().encode(JSON.stringify(value)))) !== expected
  )
    throw invalid();
  const bounded = async (response: Response) => {
    const reader = response.body?.getReader();
    if (!reader) throw invalid();
    let total = 0;
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 4 * 1024 * 1024) {
        await reader.cancel();
        throw invalid();
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  };
  const listing = async (name: string) => {
    const reply = await storage.fetch(new Request("http://authority/" + name));
    if (reply.status !== 200) throw invalid();
    const text = await bounded(reply);
    if (text.length > 4 * 1024 * 1024) throw invalid();
    const rows: unknown = JSON.parse(text);
    if (!Array.isArray(rows) || rows.length > 8192) throw invalid();
    return rows as { name: string; type: string }[];
  };
  const root = await listing("");
  let bytes = 0,
    count = 0;
  for (let i = 0; i < roles.length; i++) {
    const ns = value.namespaces[i],
      name = `lunport-${installation}-${roles[i]}`;
    if (
      !exactObject(ns, ["role", "name", "files"]) ||
      ns.role !== roles[i] ||
      ns.name !== name ||
      !Array.isArray(ns.files) ||
      !root.some((entry) => entry.name === name && entry.type === "directory")
    )
      throw invalid();
    const actual = await listing(name + "/");
    if (actual.length !== ns.files.length) throw invalid();
    let previous = "";
    for (const entry of ns.files) {
      if (
        !exactObject(entry, ["name", "bytes", "sha256"]) ||
        typeof entry.name !== "string" ||
        !file.test(entry.name) ||
        entry.name <= previous ||
        typeof entry.bytes !== "number" ||
        !Number.isSafeInteger(entry.bytes) ||
        entry.bytes < 0 ||
        !hex(entry.sha256, 64) ||
        !actual.some((row) => row.name === entry.name && row.type === "file") ||
        ++count > 8192
      )
        throw invalid();
      previous = entry.name;
      bytes += entry.bytes;
      if (bytes > 64 * 1024 ** 3) throw invalid();
      const response = await storage.fetch(
        new Request(`http://authority/${name}/${entry.name}`),
      );
      if (
        response.status !== 200 ||
        Number(response.headers.get("content-length")) !== entry.bytes ||
        !response.body
      )
        throw invalid();
      const digest = new crypto.DigestStream("SHA-256"),
        reader = response.body.getReader(),
        writer = digest.getWriter();
      let length = 0;
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          length += value.byteLength;
          if (length > entry.bytes) throw invalid();
          await writer.write(value);
        }
        await writer.close();
      } catch (error) {
        await reader.cancel().catch(() => {});
        await writer.abort(error).catch(() => {});
        throw invalid();
      }
      const result = Array.from(new Uint8Array(await digest.digest), (b) =>
        b.toString(16).padStart(2, "0"),
      ).join("");
      if (length !== entry.bytes || result !== entry.sha256) throw invalid();
    }
  }
}

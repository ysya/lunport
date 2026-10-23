import { describe, expect, it } from "vitest";
import { configured, trustedRequest } from "../src/security/selfhost";
const config = {
  CENTRAL_ORIGIN: "https://sync.test",
  SELFHOST_PROXY_KEY: "a".repeat(64),
};
function request(url = "http://sync.test/legacy/v1/info", headers: HeadersInit = {}) {
  return new Request(url, {
    headers: {
      "x-lunport-proxy-key": config.SELFHOST_PROXY_KEY,
      "x-forwarded-proto": "https",
      "cf-connecting-ip": "198.51.100.1",
      ...headers,
    },
  });
}
describe("private selfhost proxy hop", () => {
  it("requires explicit valid origin and proxy capability configuration", () => {
    expect(configured(config)).toBe(true);
    for (const changed of [
      { CENTRAL_ORIGIN: "http://sync.test" },
      { CENTRAL_ORIGIN: "https://sync.test/path" },
      { SELFHOST_PROXY_KEY: "" },
      { SELFHOST_PROXY_KEY: "A".repeat(64) },
    ])
      expect(configured({ ...config, ...changed })).toBe(false);
  });
  it("preserves exact path/query/method/ciphertext and trusted client IP while stripping proxy secrets", async () => {
    const incoming = new Request(
      "http://sync.test/v1/vaults/opaque/records?since=12",
      {
        method: "POST",
        body: "opaque ciphertext",
        headers: {
          "x-lunport-proxy-key": config.SELFHOST_PROXY_KEY,
          "x-forwarded-proto": "https",
          "cf-connecting-ip": "198.51.100.1",
          forwarded: "host=evil.test",
          "x-forwarded-host": "evil.test",
        },
      },
    );
    const normalized = trustedRequest(incoming, config)!;
    expect(normalized.url).toBe(
      "https://sync.test/v1/vaults/opaque/records?since=12",
    );
    expect(normalized.method).toBe("POST");
    expect(await normalized.text()).toBe("opaque ciphertext");
    expect(normalized.headers.get("cf-connecting-ip")).toBe("198.51.100.1");
    for (const name of [
      "x-lunport-proxy-key",
      "forwarded",
      "x-forwarded-proto",
      "x-forwarded-host",
    ])
      expect(normalized.headers.has(name)).toBe(false);
  });
  it("rejects missing/wrong capabilities and mismatched host/proto rather than trusting forwarding headers", () => {
    for (const [url, headers] of [
      ["http://sync.test/legacy/v1/info", { "x-lunport-proxy-key": "" }],
      ["http://sync.test/legacy/v1/info", { "x-lunport-proxy-key": "b".repeat(64) }],
      ["http://sync.test/legacy/v1/info", { "x-forwarded-proto": "http" }],
      ["http://evil.test/legacy/v1/info", { "x-forwarded-host": "sync.test" }],
      ["https://sync.test/legacy/v1/info", {}],
    ] as [string, Record<string, string>][])
      expect(trustedRequest(request(url, headers), config)).toBeNull();
  });
});

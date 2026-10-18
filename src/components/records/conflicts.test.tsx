import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";
import { RecordConflictPanel } from "./ConflictPanel";
import type { RecordConflict } from "@/lib/records";
const version = (notes: string, seq: string) => ({ seq, deleted: false, record: { kind: "host", id: "1", updated_at_ms: 1, device_id: "a", payload: { notes } } });
const conflict: RecordConflict = { space_id: "space", key: "host:1", token: "token", label: "web", base: version("base", "1"), local: version("offline notes", "1"), remote: [version("remote notes", "2")], can_copy_remote: true };
function render(value: RecordConflict) { return renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}><RecordConflictPanel conflicts={[value]} /></QueryClientProvider>); }
describe("saved sync conflict review", () => {
  it("keeps both versions, the common base and resolution choices visible", () => {
    const html = render(conflict);
    for (const text of ["offline notes", "remote notes", "Common base", "Keep local", "Keep latest remote", "copy remote host"]) expect(html).toContain(text);
  });
  it("shows encrypted versions without exposing a private key or copy action", () => {
    const html = render({ ...conflict, label: "Encrypted SSH key", base: null, local: { seq: "1", deleted: false, record: null }, remote: [{ seq: "2", deleted: true, record: null }], can_copy_remote: false });
    expect(html).toContain("contents are hidden"); expect(html).toContain("Deleted"); expect(html).not.toContain("Copied host name"); expect(html).not.toContain("private_key");
  });
  it("escapes untrusted metadata and keeps earlier remote versions available", () => {
    const html = render({ ...conflict, label: "<script>bad</script>", remote: [version("earlier remote", "2"), version("latest remote", "3")] });
    expect(html).not.toContain("<script>"); expect(html).toContain("earlier remote"); expect(html).toContain("latest remote");
  });
});

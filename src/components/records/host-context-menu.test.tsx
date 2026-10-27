import { QueryClient } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { elementsOf, textIn } from "@/components/keychain/test-markup";
import { ContextMenuItem } from "@/components/ui/context-menu";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { renderHook } from "@/lib/test-ipc";
import { HostContextMenu } from "./HostContextMenu";
import { RecordHostList } from "./HostList";
import { hostPayload, hostTransport, hostView, recordOverview } from "./fixtures";

/**
 * What a host's context menu offers, in order. The menu draws into a portal only once it is open, so its items are read from the
 * element tree the component returns on its first render.
 */
function menuOf(host: RecordHostView, overview: RecordOverview): string[] {
  const tree = renderHook(new QueryClient(), () =>
    HostContextMenu({ host, overview, disabled: false, organizeDisabled: false, connectDisabled: false, returnFocus: () => {}, children: <article /> }),
  );
  return elementsOf(tree, ContextMenuItem).map((item) => textIn(item).trim());
}

describe("host context menu entry", () => {
  it("attaches a keyboard and pointer context menu to each saved host card", () => {
    const html = renderToStaticMarkup(
      <RecordHostList
        overview={recordOverview()}
        selectedId={null}
        select={vi.fn()}
        edit={vi.fn()}
        connect={vi.fn()}
        accept={vi.fn()}
      />,
    );
    expect(html).toContain('data-slot="context-menu-trigger"');
    expect(html).toContain('aria-haspopup="menu"');
  });
});

describe("Copy address in a host's context menu", () => {
  const address = hostView({ id: "0000000000000001", payload: hostPayload({ alias: "web-1", hostname: "10.0.0.8" }) });
  const iap = hostView({ id: "0000000000000002", payload: hostPayload({ alias: "jumpbox", hostname: "10.0.0.9" }) });
  const overview = recordOverview({ hosts: [address, iap], transports: [hostTransport({}, iap.id)] });

  it("copies the address of a host that is dialed at one", () => {
    expect(menuOf(address, overview)).toEqual(["Connect", "Edit host…", "Copy address", "Move to group…", "Add tag…", "Delete host…"]);
  });

  it("is left out for a host with a route, whose saved hostname is never dialed", () => {
    expect(menuOf(iap, overview)).toEqual(["Connect", "Edit host…", "Move to group…", "Add tag…", "Delete host…"]);
  });
});

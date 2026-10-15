import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { RecordHostList } from "./HostList";
import { recordOverview } from "./fixtures";

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

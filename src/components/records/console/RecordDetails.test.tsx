import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { text } from "@/components/keychain/test-markup";
import { formatJson, RecordDetails } from "./RecordDetails";

describe("RecordDetails", () => {
  it("distinguishes null from an empty string and offers to expand long values", () => {
    const long = "a".repeat(5_000);
    const html = renderToStaticMarkup(<RecordDetails
      id="record"
      rowNumber={3}
      columns={[
        { name: "note", type_name: "text" },
        { name: "label", type_name: "text" },
        { name: "description", type_name: "text" },
      ]}
      row={[null, "", long]}
      onClose={vi.fn()}
    />);
    expect(text(html)).toContain("Row 3");
    expect(text(html)).toContain("note text NULL");
    expect(text(html)).toContain("label text Empty string");
    expect(html).toContain('aria-label="Copy description"');
    expect(text(html)).toContain("Show full value");
    expect(html).not.toContain("a".repeat(2_001));
  });

  it("formats JSON without changing large integers, strings, or duplicate keys", () => {
    const value = '{"id":9007199254740993,"id":7,"text":"a, [b]", "items":[{},true]}';
    expect(formatJson(value)).toBe([
      "{",
      '  "id": 9007199254740993,',
      '  "id": 7,',
      '  "text": "a, [b]",',
      '  "items": [',
      "    {},",
      "    true",
      "  ]",
      "}",
    ].join("\n"));
  });

  it("displays formatted JSON in a record", () => {
    const html = renderToStaticMarkup(<RecordDetails
      id="record"
      rowNumber={1}
      columns={[{ name: "meta", type_name: "jsonb" }]}
      row={['{"id":9007199254740993}']}
      onClose={vi.fn()}
    />);
    expect(html).toContain("{\n  &quot;id&quot;: 9007199254740993\n}");
  });
});

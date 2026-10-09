import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { syncOverviewKey } from "@/lib/sync";
import { keySlot, overview, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { IdentityFileRow } from "./HostEditor";
import { HIDDEN_CHARS } from "./keychain/test-markup";

const SLOT_VALUE = "~/.ssh/sshelter/keys/id_mac-3fa2c1d9";
const NOTE = "is in SSHelter: ssh can use it only while SSHelter is running.";

type Values = { firstClass: Record<string, string>; advanced: { keyword: string; value: string }[] };

/** The IdentityFile row of a host whose IdentityFile is `value`, with these key slots in the sync overview. A server render shows the form's default values. */
function row(value: string, slots: SyncKeySlotView[]): string {
  const Row = () => {
    const { control, register, setValue } = useForm<Values>({ defaultValues: { firstClass: { identityfile: value }, advanced: [] } });
    return <IdentityFileRow id="field-identityfile" name="firstClass.identityfile" label="IdentityFile" control={control} register={register} setValue={setValue} />;
  };
  const queryClient = new QueryClient();
  queryClient.setQueryData(syncOverviewKey, overview({ key_slots: slots }));
  return renderToStaticMarkup(
    <QueryClientProvider client={queryClient}>
      <Row />
    </QueryClientProvider>,
  );
}

describe("the host editor's IdentityFile row", () => {
  it("says under the field that a key in SSHelter needs SSHelter running", () => {
    const html = row(SLOT_VALUE, [keySlot({ name: "id_mac", in_vault: true })]);
    expect(html).toContain(`>IdentityFile</label>`);
    expect(html).toContain(`<p class="basis-full text-xs text-muted-foreground">id_mac ${NOTE}</p>`);
    // The value as ssh_config may spell it: quoted, or with %d for the home.
    expect(row(`"%d/.ssh/sshelter/keys/id_mac-3fa2c1d9"`, [keySlot({ name: "id_mac", in_vault: true })])).toContain(NOTE);
  });

  it("says nothing for a key file, a key that is only a file for now, or an empty field", () => {
    const inSSHelter = keySlot({ name: "id_mac", in_vault: true });
    const fileForNow = keySlot({ name: "id_mac", in_vault: false, file_for_now: true });
    for (const html of [row("~/.ssh/id_ed25519", [inSSHelter]), row(SLOT_VALUE, [fileForNow]), row(SLOT_VALUE, []), row("", [inSSHelter])]) {
      expect(html).toContain(`>IdentityFile</label>`);
      expect(html).not.toContain(NOTE);
      expect(html).not.toMatch(/<p[ >]/);
    }
  });

  it("reveals hidden characters in the key's name", () => {
    const html = row(SLOT_VALUE, [keySlot({ name: SPOOFED_NAME, in_vault: true })]);
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(html).toContain(`${SPOOFED_NAME_SHOWN} ${NOTE}`);
  });
});

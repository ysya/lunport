import type { ReactNode } from "react";

/**
 * The main pane's content (key vault spec §7.1): the Hosts view (the selected host's editor, or the empty state), or the selected
 * key's detail while the sidebar shows the Keychain. Hosts stays mounted while the Keychain shows, only hidden: the host editor's
 * unsaved edits live in its form, so they and the save bar come back with it. `display: contents` lays the hosts out as the pane's
 * own children, so the pane scrolls as before. No hooks: exported for the tests.
 */
export function MainPaneContent({ keychain, hosts, keyDetail }: { keychain: boolean; hosts: ReactNode; keyDetail: ReactNode }) {
  return (
    <>
      <div hidden={keychain} className="contents">
        {hosts}
      </div>
      {keychain && keyDetail}
    </>
  );
}

import { create } from "zustand";

/**
 * How far the user has answered the sheet that asks their permission for saved credentials (`CredentialPermissionSheet`) in this
 * window: for how many items (Later, or a Continue that came back), and 0 once the credentials notice reopened it (`reopen`). `null`
 * until then, when what the user put off at an earlier start counts instead (`MigrationStatus.credentials_permission_put_off`), which
 * the backend keeps in its journal (`identity_migration_put_off_credentials`).
 */
interface PermissionSheetState {
  answered: number | null;
  /** The user answered the sheet while `count` items waited for their permission. */
  answer: (count: number) => void;
  /** Shows the sheet again, whatever the user answered before, here or at an earlier start. */
  reopen: () => void;
}

export const usePermissionSheetStore = create<PermissionSheetState>(set => ({
  answered: null,
  answer: count => set({ answered: count }),
  reopen: () => set({ answered: 0 }),
}));

import type { QueryClient } from "@tanstack/react-query";
import {
  applyRecordOverview,
  leaveRecordAccount,
  rotateRecordAccount,
  type AccountLeaveReceipt,
} from "@/lib/records";
export type LifecycleDraft = {
  mode: "leave" | "rotate" | null;
  deviceName: string;
  consent: boolean;
  words: string;
  leaveReceipt: AccountLeaveReceipt | null;
  rotation: { operation_id: string; complete: boolean } | null;
  busy: boolean;
  error: string | null;
};
export function clearLifecycleDraft(
  mode: LifecycleDraft["mode"] = null,
  deviceName = "",
): LifecycleDraft {
  return {
    mode,
    deviceName,
    consent: false,
    words: "",
    leaveReceipt: null,
    rotation: null,
    busy: false,
    error: null,
  };
}
/** Only public overview enters QueryClient; codes remain in the caller's component draft. */
export async function submitLifecycleDraft(
  client: QueryClient,
  state: LifecycleDraft,
  update: (patch: Partial<LifecycleDraft>) => void,
): Promise<boolean> {
  if (
    state.busy ||
    !state.mode ||
    !state.consent ||
    (state.mode === "rotate" && !state.deviceName.trim())
  )
    return false;
  update({ busy: true, error: null });
  try {
    if (state.mode === "leave") {
      const result = await leaveRecordAccount();
      applyRecordOverview(client, result.overview);
      update({
        mode: null,
        consent: false,
        words: "",
        rotation: null,
        leaveReceipt: result.receipt,
        error: result.receipt.complete
          ? null
          : (result.receipt.pending_error ??
            "Leaving account is pending. Retry sync setup to continue."),
      });
    } else {
      const result = await rotateRecordAccount(state.deviceName);
      applyRecordOverview(client, result.overview);
      update({
        mode: null,
        consent: false,
        words: result.words,
        leaveReceipt: null,
        rotation: {
          operation_id: result.operation_id,
          complete: result.complete,
        },
        error: result.complete
          ? null
          : (result.pending_error ??
            "Sync code rotation is pending. Retry sync setup to continue."),
      });
    }
    return true;
  } catch {
    update({
      error:
        "The account operation could not finish. Check pending sync setup before retrying; existing progress is retained.",
    });
    return false;
  } finally {
    update({ busy: false });
  }
}

/** Retire the previous attempt after an explicit native retry, without claiming a receipt completed. */
export function retireLifecycleAttempt(state: LifecycleDraft): LifecycleDraft {
  return { ...state, leaveReceipt: null, rotation: null, error: null };
}

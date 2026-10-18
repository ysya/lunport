import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import type { InstallStatus } from "@/bindings/InstallStatus";
import { tauriInvoke } from "@/lib/ipc";
import { usePlatform } from "@/lib/queries";
import { useUiStore } from "@/stores/ui";
import { Button } from "@/components/ui/button";
import { Section } from "@/components/settings-primitives";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogCancel } from "@/components/ui/alert-dialog";

function useInstallationStatus() {
  const platform = usePlatform();
  return useQuery({ queryKey: ["app", "installation"], queryFn: () => tauriInvoke<InstallStatus>("app_installation_status"), enabled: platform.data === "macos", staleTime: Infinity, retry: false });
}

export function InstallationRenameNotice() {
  const status = useInstallationStatus();
  const shown = useRef(false);
  useEffect(() => {
    if (!status.data?.needs_attention || shown.current) return;
    shown.current = true;
    toast.info("Finish renaming Lunport", {
      description: "Your app remains usable. Review the installation repair in Settings → About.",
      action: { label: "Review", onClick: () => {
        useUiStore.getState().setSettingsCategory("about");
        useUiStore.getState().setSettingsOpen(true);
      } },
    });
  }, [status.data]);
  return null;
}

export function InstallationRenameRepair() {
  const status = useInstallationStatus();
  const [confirm, setConfirm] = useState(false);
  const finish = useMutation({ mutationFn: () => tauriInvoke<void>("app_finish_rename") });
  if (!status.data?.needs_attention) return null;
  return <Section title="Finish the Lunport rename" description={status.data.message ?? undefined}>
    <p className="mb-3 text-sm text-muted-foreground">Lunport can retry the migration without reinstalling. Existing MCP commands and the launch-at-login preference are preserved. macOS may ask for installation permission.</p>
    <Button variant="outline" onClick={() => setConfirm(true)}>Finish rename…</Button>
    {finish.isError && <p role="alert" className="mt-2 text-sm text-destructive">{String(finish.error)}</p>}
    <AlertDialog open={confirm} onOpenChange={open => { if (!finish.isPending) setConfirm(open); }}>
      <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Restart to finish renaming?</AlertDialogTitle><AlertDialogDescription>Restarting ends active SSH sessions and interrupts AI requests. Save your work first. Your hosts, keys and settings stay in this installation.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={finish.isPending}>Cancel</AlertDialogCancel><Button disabled={finish.isPending} onClick={() => finish.mutate()}>{finish.isPending ? "Restarting…" : "Restart and finish rename"}</Button></AlertDialogFooter></AlertDialogContent>
    </AlertDialog>
  </Section>;
}

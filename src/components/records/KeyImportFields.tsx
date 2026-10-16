import { FolderOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { revealHidden } from "@/lib/sync-approvals";
import type { KeyDraft } from "./panel-actions";
import { RecordField } from "./form";

export function KeyImportFields({ draft, update, choose }: {
  draft: KeyDraft;
  update: (patch: Partial<KeyDraft>) => void;
  choose: () => Promise<void>;
}) {
  return <Tabs value={draft.source} onValueChange={(source) => {
    if (source === "file" || source === "paste") update({ source, error: null });
  }}>
    <TabsList aria-label="Private key source">
      <TabsTrigger value="file" disabled={draft.busy}>From a file</TabsTrigger>
      <TabsTrigger value="paste" disabled={draft.busy}>Paste key</TabsTrigger>
    </TabsList>
    <TabsContent value="file" className="space-y-3 pt-2">
      <Button type="button" variant="outline" disabled={draft.busy} onClick={(event) => {
        const trigger = event.currentTarget;
        void choose().finally(() => requestAnimationFrame(() => trigger.focus()));
      }}>
        <FolderOpen className="size-4" />
        {draft.path ? "Choose another file…" : "Choose a file…"}
      </Button>
      <p role="status" className="break-all font-mono text-xs text-muted-foreground">
        {draft.path ? revealHidden(draft.path) : "No file selected."}
      </p>
    </TabsContent>
    <TabsContent value="paste" className="pt-2">
      <RecordField label="Private key">
        <Textarea
          value={draft.privateText}
          autoComplete="off"
          spellCheck={false}
          disabled={draft.busy}
          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          className="min-h-40 max-h-64 font-mono text-xs"
          onChange={(event) => update({ privateText: event.target.value, error: null })}
        />
      </RecordField>
    </TabsContent>
    <p className="text-xs text-muted-foreground">OpenSSH private keys, up to 1 MiB. Public keys (.pub), PuTTY and PEM formats are not supported.</p>
  </Tabs>;
}

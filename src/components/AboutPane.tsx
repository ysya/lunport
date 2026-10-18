import { useEffect, useState } from "react";
import { getName, getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { ExternalLink } from "lucide-react";
import { toast } from "sonner";
import product from "@/brand/product.json";
import terminalNotices from "@/lib/terminal-notices.txt?raw";
import { BrandMark } from "@/components/app/BrandMark";
import { Button } from "@/components/ui/button";
import { Section, SettingsGroup, SettingsRow } from "@/components/settings-primitives";
import { InstallationRenameRepair } from "@/components/InstallationRename";

export function AboutPane() {
  const [installed, setInstalled] = useState<{ name: string; version: string } | null>(null);
  useEffect(() => {
    let mounted = true;
    Promise.all([getName(), getVersion()])
      .then(([name, version]) => { if (mounted) setInstalled({ name, version }); })
      .catch(() => {});
    return () => { mounted = false; };
  }, []);

  const open = async (path: string) => {
    try { await openUrl(`${product.repository}${path}`); }
    catch { toast.error("Could not open the link. Try again from your browser."); }
  };

  return <div className="space-y-6">
    <div className="flex items-center gap-4">
      <div className="flex size-16 shrink-0 items-center justify-center rounded-2xl bg-primary/10 text-primary">
        <BrandMark className="size-10" />
      </div>
      <div>
        <h3 className="text-xl font-semibold tracking-tight">{installed?.name ?? product.name}</h3>
        <p className="mt-1 text-sm text-muted-foreground">{product.tagline}</p>
        <p className="mt-1 text-xs text-muted-foreground">{installed ? `Version ${installed.version}` : "Installed version unavailable"}</p>
      </div>
    </div>
    <p className="max-w-lg text-sm leading-relaxed text-muted-foreground">{product.description}</p>
    <InstallationRenameRepair />
    <Section title="Project & support">
      <SettingsGroup>
        <SettingsRow label="Project" description="Source code and the getting started guide."><Button variant="outline" size="sm" onClick={() => void open("")}>GitHub<ExternalLink className="size-3.5" /></Button></SettingsRow>
        <SettingsRow label="Release notes" description="Changes and downloads for each version."><Button variant="outline" size="sm" onClick={() => void open("/releases")}>View releases<ExternalLink className="size-3.5" /></Button></SettingsRow>
        <SettingsRow label="Report an issue" description="Share a problem or suggest an improvement."><Button variant="outline" size="sm" onClick={() => void open("/issues")}>Open issues<ExternalLink className="size-3.5" /></Button></SettingsRow>
        <SettingsRow label="License" description={product.license}><Button variant="outline" size="sm" onClick={() => void open("/blob/main/LICENSE")}>View license<ExternalLink className="size-3.5" /></Button></SettingsRow>
      </SettingsGroup>
    </Section>
    <p className="text-xs leading-relaxed text-muted-foreground">{product.copyright}<br />Formerly SSHelter.</p>
    <details className="text-xs text-muted-foreground"><summary className="cursor-pointer">Terminal credits and licenses</summary><pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap text-[11px]">{terminalNotices}</pre></details>
  </div>;
}

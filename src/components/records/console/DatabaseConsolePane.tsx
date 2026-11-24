import type { DatabaseTab } from "@/stores/terminals";

export default function DatabaseConsolePane(_props: { tab: DatabaseTab; active: boolean }) {
  return <div className="flex flex-1 items-center justify-center text-muted-foreground">Loading console…</div>;
}

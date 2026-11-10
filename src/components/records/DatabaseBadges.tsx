import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { DatabaseEnvironment } from "@/lib/databases";

/** How each environment reads and is drawn: PROD stands out as a solid badge, STAGING in a warning tint, DEV stays quiet. */
const looks: Record<DatabaseEnvironment, { label: string; className: string }> = {
  prod: { label: "PROD", className: "border-transparent bg-destructive text-background" },
  staging: { label: "STAGING", className: "border-warning/30 bg-warning/10 text-warning" },
  dev: { label: "DEV", className: "border-transparent bg-muted text-muted-foreground" },
};

/** What a database is used for, as a badge next to its name. */
export function EnvironmentBadge({ environment }: { environment: DatabaseEnvironment }) {
  const look = looks[environment];
  return <Badge variant="outline" className={cn("font-semibold tracking-wide", look.className)}>{look.label}</Badge>;
}

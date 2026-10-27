import type { WorkspacePanel } from "@/components/records/LibraryNavigation";

/*
 * The Cloud section of the Library sidebar (design 2026-10-27, The Cloud section and the Google Cloud page): one row per cloud
 * provider, each opening its own page. Google Cloud is the first; another provider (AWS) joins with an entry here and a page of its own.
 */

export type CloudProvider = { id: string; label: string; panel: WorkspacePanel };

export const CLOUD_PROVIDERS: CloudProvider[] = [{ id: "gcp", label: "Google Cloud", panel: "transports" }];

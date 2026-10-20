import { tauriInvoke } from "@/lib/ipc";
import type { CentralStatus } from "./central-sync";

export type MigrationScope = {
  service: string;
  account_id: string;
  device_id: string;
  root_fingerprint: string;
  membership_head: string;
  authorization_epoch: string;
};
export function migrationScope(status: CentralStatus): MigrationScope {
  return {
    service: status.service ?? "",
    account_id: status.account_id ?? "",
    device_id: status.device_id ?? "",
    root_fingerprint: status.root_fingerprint ?? "",
    membership_head: status.membership_head ?? "",
    authorization_epoch: status.authorization_epoch ?? "",
  };
}
export const migrationKey = (status: CentralStatus) =>
  ["central-library-migration", migrationScope(status)] as const;
export type MigrationProgress = {
  phase:
    | "idle"
    | "capturing"
    | "waiting"
    | "review"
    | "staging"
    | "reading"
    | "publishing"
    | "complete";
  mode: "publish" | "join";
  legacy_sources: boolean;
  total: number;
  staged: number;
  verified: number;
  approved: boolean;
};
export type LibraryReview = {
  ticket: string;
  approved: boolean;
  summary: {
    hosts: number;
    groups: number;
    collections: number;
    history_records: number;
    private_key_versions: number;
    key_versions: Array<{
      name: string;
      fingerprint: string;
      key_type: string;
      has_passphrase: boolean;
      storage: "managed" | "hardware" | "external_agent";
      retained: boolean;
    }>;
  };
};
export type MigrationPreparation = {
  progress: MigrationProgress;
  review: LibraryReview | null;
};
export const migrationStatus = (expected: MigrationScope) =>
  tauriInvoke<MigrationProgress>("central_migration_status", { expected });
export const prepareMigration = (expected: MigrationScope) =>
  tauriInvoke<MigrationPreparation>("central_migration_prepare", { expected });
export const confirmMigration = (expected: MigrationScope, ticket: string) =>
  tauriInvoke<MigrationProgress>("central_migration_confirm", {
    expected,
    ticket,
  });
export const continueMigration = (expected: MigrationScope) =>
  tauriInvoke<MigrationProgress>("central_migration_continue", { expected });

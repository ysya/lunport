/** Public, disposable preview data. Every write remains in memory or is rejected. */
import type { HostSummary } from "@/bindings/HostSummary";
import { overview } from "@/lib/sync-fixtures";
const file = "/fixture/.ssh/config";
const hosts: HostSummary[] = [
  { alias: "production-web", hostname: "web.eu.production.example.com", user: "deploy", source_file: file, patterns: ["production-web"], tags: ["production"] },
  { alias: "database-replica", hostname: "replica.us-east.production.example.com", user: "postgres", source_file: "/fixture/.ssh/config.d/database.config", patterns: ["database-replica"], tags: ["reporting"] },
  { alias: "bastion", hostname: "bastion.example.com", user: "ops", source_file: file, patterns: ["bastion"], tags: [] },
];
export const legacyConfig = { files: [file, "/fixture/.ssh/config.d/database.config"], hosts };
const sync = overview({ joined: false, account_short: null, devices: [], spaces: [], key_slots: [], relay_url: "https://relay.example.com" });
export function legacyPreviewRead(command: string, args: Record<string, unknown>): { handled: boolean; value?: unknown } {
  const host = hosts.find((item) => item.alias === args.alias) ?? hosts[0];
  const values: Record<string, unknown> = {
    config_load: legacyConfig,
    config_get_host: { ...host, options: [{ keyword: "HostName", value: host.hostname, enabled: true }, { keyword: "User", value: host.user, enabled: true }, { keyword: "Port", value: "22", enabled: true }] },
    config_check_drift: [],
    config_key_hygiene: { identity_files: [], identities_only: false, explicit: false },
    config_jump_chain: [],
    config_effective: [["hostname", host.hostname], ["user", host.user], ["port", "22"]],
    config_lint: [{ rule: "duplicate-directive", severity: "warning", file, alias: "production-web", keyword: "User", message: "A later User directive is ignored. The first value is used." }],
    config_read_file: "# Disposable interface fixture\nHost production-web\n  HostName web.eu.production.example.com\n  User deploy\n",
    discover_hosts: [{ name: "staging", host_name: "staging.example.com", port: 22, source: "known_hosts", online: null }, { name: "build-runner", host_name: "build-runner.tailnet.example.com", port: 22, source: "tailscale", online: true }],
    config_list_backups: Array.from({ length: 18 }, (_, index) => ({ path: `/fixture/backups/config.${index}.bak`, file, timestamp_ms: 1792130400000 - index * 3600000 })),
    known_hosts_list: Array.from({ length: 18 }, (_, index) => ({ line_index: index, hosts: `${index === 0 ? "web.eu.production.example.com" : `server-${index}.example.com`},192.0.2.${index + 1}`, key_type: "ssh-ed25519", fingerprint_sha256: "SHA256:DemoFingerprintForVisualReviewOnly", hashed: false, marker: null })),
    keys_list: [{ name: "id_ed25519", private_path: "/fixture/.ssh/id_ed25519", public_path: "/fixture/.ssh/id_ed25519.pub", key_type: "ed25519", bits: 256, fingerprint_sha256: "SHA256:DemoFingerprintForVisualReviewOnly", comment: "Demo only", in_agent: false, hosts: [], has_passphrase: false }],
    keys_git_ssh_hint: null,
    secrets_has: false,
    sync_overview: sync,
    sync_duplicate_aliases: [],
    sync_pending_approvals: [],
    sync_unmovable_hosts: [],
    deploy_preflight: { askpassSupported: true, passwordAuthBlocked: false, keychainAvailable: false },
    records_deploy_preview: { id: "fixture-deploy", host_id: args.hostId, key_id: args.keyId, alias: "Production web", hostname: "web.example.com", port: 22, user: "deploy", key_name: "Work key", fingerprint: "SHA256:DemoFingerprintForVisualReviewOnly", public_key: "ssh-ed25519 DEMO-ONLY", route: Array.from({ length: 16 }, (_, index) => `hop-${index}@jump.example.com:22`) },
    records_deploy_cancel: null,
  };
  return Object.prototype.hasOwnProperty.call(values, command) ? { handled: true, value: values[command] } : { handled: false };
}

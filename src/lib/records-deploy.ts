import type { RecordDeployResult } from "./records";
const messages: Record<RecordDeployResult["outcome"], string> = {
  added: "Public key added to the remote account.",
  already_present: "This public key is already present. Existing restrictions were preserved.",
  stale_preview: "The reviewed destination, route, key, or workspace changed, or the preview expired. Refresh the preview and review it again.",
  denied: "Deployment was not authorized. Nothing was installed.",
  canceled: "Deployment canceled. If installation had started, the remote result may be unknown; review the account before trying again.",
  timed_out: "Deployment timed out. The remote result may be unknown; review the account before trying again.",
  auth_abandoned: "Authentication was not completed. No installation command was sent.",
  host_key_refused: "The server identity was not trusted or its confirmation expired. No installation command was sent.",
  unsupported_shell: "A compatible POSIX shell and utilities are required. Remote Windows installation is not supported.",
  remote_failed: "The remote installer failed. Check the account's .ssh paths, permissions, and deployment lock before trying again.",
  connection_failed: "The SSH connection could not be completed. No installation command was sent.",
  unknown: "Installation could not be confirmed. Do not assume the key was installed; review the remote account before trying again.",
};
export function deploymentMessage(result: RecordDeployResult): string {
  return messages[result.outcome] + (result.audit_error ? " The session log could not be saved; this operation was not retried." : "");
}

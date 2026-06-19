/**
 * The target file an Add-host dialog should preselect when it opens.
 *
 * A `requested` file (set by the file-header right-click "New host in this
 * file") wins; otherwise the current sidebar `scope` (fileScope) is used. Only
 * a path that is actually a loaded file counts — anything else yields "" so the
 * picker stays on its "select a file" placeholder.
 */
export function initialAddHostTarget(
  requested: string | null,
  scope: string | null,
  files: string[],
): string {
  if (requested && files.includes(requested)) return requested;
  if (scope && files.includes(scope)) return scope;
  return "";
}

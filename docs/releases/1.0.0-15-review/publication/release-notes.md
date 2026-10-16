- Reorganize Settings into Application, Workspace and Maintenance, with mode-specific categories and searchable sections. Records uses the existing Import and Sync workspaces; Legacy keeps its OpenSSH file and sync settings.
- Keep config-path and Legacy sync drafts while switching settings categories. Confirm before discarding an unapplied path, and keep Settings open while a configuration is loading.
- Unify Legacy hosts, Keychain, deployment, sync reviews and maintenance tools with shared headings, sections, bounded dialogs and visible action bars.
- Add consistent disclosure transitions for Legacy file/tag groups, other key files and effective configuration. Keep collapsed content out of keyboard interaction and align the save bar with the resized sidebar.
- Show clear read failures and Retry actions in known hosts, backups, discovery, config lint and the file viewer. Add host-permission search in AI access and improve keyboard focus restoration.

Validation includes 1,066 frontend tests, production-build fixture exclusion, browser checks at small and large text sizes, and macOS Development Settings checks. SSH, trust, key-sharing and approval gates are preserved. Manual visual acceptance on Windows and Linux remains pending.

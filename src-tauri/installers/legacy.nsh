; The Windows identity Lunport installs had before 2.0, so that an upgrade finds what they registered and replaces it in place.
; Only this file and legacy.wxi may hold these names among the installer sources (scripts/identity-guard.mjs).
; nsis.nsi includes it once BUNDLEID is defined; hooks.nsh puts this directory on the include path.

; Every profile shared the manufacturer (the second part of the old bundle identifier) and the executable names.
!define LEGACY_MANUFACTURER "homelab"
!define LEGACY_BINARY "sshelter"
!define LEGACY_CONSOLE_HELPER "sshelter-cli"

; The previous uninstall key and manufacturer product key; also the previous login entry and shortcut name. The current
; identity comes from Tauri's variables in nsis.nsi; this only says which earlier identity each profile replaces.
!if "${BUNDLEID}" == "dev.ysya.lunport"
  !define LEGACY_INSTALLER_IDENTITY "SSHelter"
!else if "${BUNDLEID}" == "dev.ysya.lunport.dev"
  !define LEGACY_INSTALLER_IDENTITY "SSHelter Dev"
!else
  !error "legacy.nsh knows no earlier Windows identity for ${BUNDLEID}"
!endif

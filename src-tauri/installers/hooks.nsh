; Product-name changes must not leave stale shortcuts or create new ones on an update.
; Only touch links that actually target this installation's executable.
!macro LunportRenameShortcut directory
  !insertmacro IsShortcutTarget "${directory}\${INSTALLERIDENTITY}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
  Pop $R0
  ${If} $R0 = 1
    ${IfNot} ${FileExists} "${directory}\${PRODUCTNAME}.lnk"
      Rename "${directory}\${INSTALLERIDENTITY}.lnk" "${directory}\${PRODUCTNAME}.lnk"
    ${Else}
      !insertmacro IsShortcutTarget "${directory}\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
      Pop $R0
      ${If} $R0 = 1
        Delete "${directory}\${INSTALLERIDENTITY}.lnk"
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro LunportRenameShortcut "$SMPROGRAMS"
  !insertmacro LunportRenameShortcut "$SMPROGRAMS\$AppStartMenuFolder"
  !insertmacro LunportRenameShortcut "$DESKTOP"
!macroend

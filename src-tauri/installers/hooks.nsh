; Installer hooks (bundle.windows.nsis.installerHooks). makensis resolves an include from the generated script's directory, so
; put this one on the include path: nsis.nsi includes the identity of installs from before 2.0 from legacy.nsh, next to it.
!addincludedir "${__FILEDIR__}"

; Points a shortcut that starts this installation's previous executable at the current one, keeping its name, with the current
; AppUserModelID.
!macro LunportRetargetShortcut shortcut
  !insertmacro IsShortcutTarget "${shortcut}" "$INSTDIR\$OldMainBinaryName"
  Pop $R0
  ${If} $R0 = 1
    !insertmacro SetShortcutTarget "${shortcut}" "$INSTDIR\${MAINBINARYNAME}.exe"
    !insertmacro SetLnkAppUserModelId "${shortcut}"
  ${EndIf}
!macroend

; A shortcut may still carry the name from before 2.0 (legacy.nsh). Only links that start this installation's executable get
; the product name; unrelated shortcuts stay as they are.
!macro LunportRenameShortcut directory
  !insertmacro IsShortcutTarget "${directory}\${LEGACY_INSTALLER_IDENTITY}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
  Pop $R0
  ${If} $R0 = 1
    ${IfNot} ${FileExists} "${directory}\${PRODUCTNAME}.lnk"
      Rename "${directory}\${LEGACY_INSTALLER_IDENTITY}.lnk" "${directory}\${PRODUCTNAME}.lnk"
    ${Else}
      !insertmacro IsShortcutTarget "${directory}\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
      Pop $R0
      ${If} $R0 = 1
        Delete "${directory}\${LEGACY_INSTALLER_IDENTITY}.lnk"
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; When this update renamed the executable, CreateOrUpdate*Shortcut has retargeted the product-named shortcuts. The ones it
  ; does not know still start the removed file: shortcuts under the earlier name, and taskbar pins, which are copies the
  ; taskbar finds by file name, so they keep their names.
  ${If} $OldMainBinaryName != ""
  ${AndIf} $OldMainBinaryName != "${MAINBINARYNAME}.exe"
    !insertmacro LunportRetargetShortcut "$SMPROGRAMS\${LEGACY_INSTALLER_IDENTITY}.lnk"
    !insertmacro LunportRetargetShortcut "$SMPROGRAMS\$AppStartMenuFolder\${LEGACY_INSTALLER_IDENTITY}.lnk"
    !insertmacro LunportRetargetShortcut "$DESKTOP\${LEGACY_INSTALLER_IDENTITY}.lnk"
    !insertmacro LunportRetargetShortcut "$APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\${PRODUCTNAME}.lnk"
    !insertmacro LunportRetargetShortcut "$APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\${LEGACY_INSTALLER_IDENTITY}.lnk"
  ${EndIf}
  !insertmacro LunportRenameShortcut "$SMPROGRAMS"
  !insertmacro LunportRenameShortcut "$SMPROGRAMS\$AppStartMenuFolder"
  !insertmacro LunportRenameShortcut "$DESKTOP"
!macroend

; Tauri v2 NSIS extension. Per-machine setup is elevated; the app stays asInvoker.
!include "LogicLib.nsh"
!define THREATLENS_HOOK_DIR "${__FILEDIR__}"

!macro NSIS_HOOK_PREINSTALL
  InitPluginsDir
  File /oname=$PLUGINSDIR\prepare-vault.ps1 "${THREATLENS_HOOK_DIR}\prepare-vault.ps1"
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\prepare-vault.ps1"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Impossibile preparare la cartella protetta di ThreatLens. Installazione interrotta."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  SetShellVarContext all
  CreateShortcut "$DESKTOP\ThreatLens.lnk" "$INSTDIR\threatlens.exe"
  WriteRegStr HKLM "Software\Classes\*\shell\ThreatLensScan" "" "Analizza con ThreatLens"
  WriteRegStr HKLM "Software\Classes\*\shell\ThreatLensScan" "Icon" '$\"$INSTDIR\threatlens.exe$\",0'
  WriteRegStr HKLM "Software\Classes\*\shell\ThreatLensScan\command" "" '$\"$INSTDIR\threatlens.exe$\" --scan $\"%1$\"'
  WriteRegStr HKLM "Software\Classes\Directory\shell\ThreatLensScan" "" "Analizza con ThreatLens"
  WriteRegStr HKLM "Software\Classes\Directory\shell\ThreatLensScan" "Icon" '$\"$INSTDIR\threatlens.exe$\",0'
  WriteRegStr HKLM "Software\Classes\Directory\shell\ThreatLensScan\command" "" '$\"$INSTDIR\threatlens.exe$\" --scan $\"%1$\"'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey HKLM "Software\Classes\*\shell\AegisSecurityScan"
  DeleteRegKey HKLM "Software\Classes\Directory\shell\AegisSecurityScan"
  DeleteRegKey HKLM "Software\Classes\*\shell\ThreatLensScan"
  DeleteRegKey HKLM "Software\Classes\Directory\shell\ThreatLensScan"
  SetShellVarContext all
  Delete "$DESKTOP\Aegis Security.lnk"
  Delete "$SMPROGRAMS\Aegis Security\Aegis Security.lnk"
  RMDir "$SMPROGRAMS\Aegis Security"
  Delete "$DESKTOP\ThreatLens.lnk"
  ; Intentionally preserve ProgramData and quarantined files on uninstall/upgrade.
!macroend

!include "LogicLib.nsh"

; Capture paths at include time; these files are staged by the Windows build job.
!define MAVI_NSIS_DIR "${__FILEDIR__}"

!macro MAVI_SERVICE_ACTION ACTION SCRIPT
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${SCRIPT}" -Action ${ACTION} -InstallDir "$INSTDIR"' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Mavi VPN service ${ACTION} failed. Setup cannot continue."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=mavi-vpn-service.ps1 "${MAVI_NSIS_DIR}\service.ps1"
  !insertmacro MAVI_SERVICE_ACTION Stop "$PLUGINSDIR\mavi-vpn-service.ps1"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  SetOutPath "$INSTDIR"
  File "${MAVI_NSIS_DIR}\..\wix_binaries\mavi-vpn-client.exe"
  File "${MAVI_NSIS_DIR}\..\wix_binaries\mavi-vpn-service.exe"
  File /oname=mavi-vpn-service.ps1 "${MAVI_NSIS_DIR}\service.ps1"
  !insertmacro MAVI_SERVICE_ACTION Install "$INSTDIR\mavi-vpn-service.ps1"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro MAVI_SERVICE_ACTION Uninstall "$INSTDIR\mavi-vpn-service.ps1"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  Delete "$INSTDIR\mavi-vpn-client.exe"
  Delete "$INSTDIR\mavi-vpn-service.exe"
  Delete "$INSTDIR\mavi-vpn-service.ps1"
  RMDir "$INSTDIR"
!macroend

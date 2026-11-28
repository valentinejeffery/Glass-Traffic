; PacketAtlas — NSIS Installer Script (Modern UI 2)
; Build from repo root:
;   makensis "/DBINARY_PATH=..\target\release\packetatlas.exe" installer\packetatlas.nsi

Unicode True

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

!ifndef APP_VERSION
  !define APP_VERSION "0.2.0"
!endif

!ifndef BINARY_PATH
  !define BINARY_PATH "..\target\release\packetatlas.exe"
!endif

!ifndef OUT_FILE
  !define OUT_FILE "..\PacketAtlas-Setup-${APP_VERSION}.exe"
!endif

!define APP_NAME "PacketAtlas"
!define APP_PUBLISHER "PacketAtlas"
!define APP_EXE "packetatlas.exe"
!define UNINSTALL_REG_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\PacketAtlas"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\PacketAtlas"
InstallDirRegKey HKLM "${UNINSTALL_REG_KEY}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

; Modern UI configuration
!define MUI_ICON "..\assets\packetatlas.ico"
!define MUI_UNICON "..\assets\packetatlas.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Welcome to ${APP_NAME} Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will install ${APP_NAME} ${APP_VERSION}, a native desktop network traffic monitor and live OSINT geo-telemetry dashboard.$\r$\n$\r$\nTip: Run PacketAtlas as Administrator to enable exact per-flow raw packet capture (SIO_RCVALL). Standard users can still monitor all active sockets, processes, and bandwidth."
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APP_NAME}"

; Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "PacketAtlas (Required)" SecCore
  SectionIn RO
  SetRegView 64
  SetOutPath "$INSTDIR"

  ; Stop any running instance (including legacy GlassTrace) so upgrade can overwrite cleanly
  DetailPrint "Stopping any running ${APP_NAME} instance..."
  nsExec::ExecToLog 'taskkill /F /IM "${APP_EXE}" /T'
  nsExec::ExecToLog 'taskkill /F /IM "glasstrace.exe" /T'
  Sleep 600

  File "/oname=${APP_EXE}" "${BINARY_PATH}"
  File "..\README.md"
  File "..\LICENSE"

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk" "$INSTDIR\Uninstall.exe"

  ; Register in Windows Add/Remove Programs
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "NoRepair" 1

  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "EstimatedSize" "$0"
SectionEnd

Section "Desktop Shortcut" SecDesktop
  CreateShortCut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
SectionEnd

; Component descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Core PacketAtlas executable, Start Menu shortcuts, and uninstaller."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Create a shortcut on your Windows Desktop."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  SetRegView 64

  ; Ensure PacketAtlas is closed before removing files
  nsExec::ExecToLog 'taskkill /F /IM "${APP_EXE}" /T'
  Sleep 600

  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$DESKTOP\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"

  DeleteRegKey HKLM "${UNINSTALL_REG_KEY}"
SectionEnd

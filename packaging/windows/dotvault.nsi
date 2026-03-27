!define APP_NAME "dotvault"
!ifndef APP_VERSION
  !define APP_VERSION "0.0.0"
!endif
!ifndef BINARY
  !define BINARY "dotvault.exe"
!endif

!define PATH_KEY "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"

!include "MUI2.nsh"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "dotvault_${APP_VERSION}_windows_amd64_setup.exe"
InstallDir "$PROGRAMFILES\${APP_NAME}"
RequestExecutionLevel admin

; UI pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File "${BINARY}"
  File "LICENSE"

  ; Add $INSTDIR to system PATH if not already present
  ReadRegStr $0 HKLM "${PATH_KEY}" "Path"
  StrCmp $0 "" 0 +2
    StrCpy $0 ""
  ; Check if already in PATH
  ${If} $0 != ""
    StrCpy $1 $0 "" -1
    StrCmp $1 ";" 0 +2
      StrCpy $0 $0 -1
  ${EndIf}
  ; Search for our directory in PATH
  Push "$0;"
  Push "$INSTDIR;"
  Call StrContains
  Pop $1
  StrCmp $1 "" 0 skip_path_add
    ; Append to PATH
    StrCmp $0 "" 0 +3
      WriteRegExpandStr HKLM "${PATH_KEY}" "Path" "$INSTDIR"
      Goto path_done
    WriteRegExpandStr HKLM "${PATH_KEY}" "Path" "$0;$INSTDIR"
  skip_path_add:
  path_done:

  ; Notify running applications of environment change
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Start menu
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  ; Uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Add/Remove Programs entry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
    "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
    "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
    "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
    "Publisher" "goodtune"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\dotvault.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"

  ; Remove $INSTDIR from system PATH
  ReadRegStr $0 HKLM "${PATH_KEY}" "Path"
  ; Remove ";$INSTDIR" or "$INSTDIR;" or standalone "$INSTDIR"
  Push $0
  Push "$INSTDIR"
  Call un.RemoveFromPath
  Pop $0
  WriteRegExpandStr HKLM "${PATH_KEY}" "Path" $0

  ; Notify running applications of environment change
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Remove Add/Remove Programs entry
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
SectionEnd

; ---------------------------------------------------------------------------
; String helper: check if $needle is a substring of $haystack
; Usage: Push $haystack / Push $needle / Call StrContains / Pop $result
;   $result is "" if not found, otherwise the needle
; ---------------------------------------------------------------------------
Function StrContains
  Exch $R1 ; needle
  Exch
  Exch $R2 ; haystack
  Push $R3
  Push $R4
  StrLen $R3 $R1
  StrCpy $R4 0
  loop:
    StrCpy $0 $R2 $R3 $R4
    StrCmp $0 "" done
    StrCmp $0 $R1 found
    IntOp $R4 $R4 + 1
    Goto loop
  found:
    StrCpy $R1 $R1
    Goto exit
  done:
    StrCpy $R1 ""
  exit:
  Pop $R4
  Pop $R3
  Pop $R2
  Exch $R1
FunctionEnd

; ---------------------------------------------------------------------------
; Remove a directory from a semicolon-delimited PATH string
; Usage: Push $path_string / Push $dir_to_remove / Call un.RemoveFromPath / Pop $result
; ---------------------------------------------------------------------------
Function un.RemoveFromPath
  Exch $R1 ; dir to remove
  Exch
  Exch $R2 ; current PATH
  Push $R3 ; result
  Push $R4 ; temp segment
  Push $R5 ; remaining
  Push $R6 ; segment length

  StrCpy $R3 ""
  StrCpy $R5 "$R2;"

  loop:
    ; Find next semicolon
    StrCpy $R6 0
    find_semi:
      StrCpy $R4 $R5 1 $R6
      StrCmp $R4 "" extract
      StrCmp $R4 ";" extract
      IntOp $R6 $R6 + 1
      Goto find_semi

    extract:
      StrCpy $R4 $R5 $R6       ; segment before semicolon
      IntOp $R6 $R6 + 1
      StrCpy $R5 $R5 "" $R6    ; remainder after semicolon

      ; Skip if this segment matches the dir to remove
      StrCmp $R4 $R1 skip_segment
      StrCmp $R4 "" skip_segment
        ; Append to result
        StrCmp $R3 "" 0 +3
          StrCpy $R3 $R4
          Goto skip_segment
        StrCpy $R3 "$R3;$R4"
      skip_segment:

    ; Continue if there's more
    StrCmp $R5 "" done
    Goto loop

  done:

  Pop $R6
  Pop $R5
  Pop $R4
  Pop $R2
  StrCpy $R1 $R3
  Exch $R1
FunctionEnd

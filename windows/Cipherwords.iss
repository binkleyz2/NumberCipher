; Cipherwords Windows installer
; CI invocation (from repo root, shell: bash):
;   ISCC="/c/Program Files (x86)/Inno Setup 6/ISCC.exe"
;   "$ISCC" /O. \
;     "/DAppVersion=X.Y.Z" \
;     "/DExeSource=C:/path/to/Cipherwords.exe" \
;     "/DOutputBasename=Cipherwords-Windows-x64-setup" \
;     windows/Cipherwords.iss

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#ifndef ExeSource
  #define ExeSource "out\x64-small\Cipherwords.exe"
#endif
#ifndef OutputBasename
  #define OutputBasename "Cipherwords-Windows-x64-setup"
#endif

[Setup]
AppName=Cipherwords
AppVersion={#AppVersion}
AppVerName=Cipherwords {#AppVersion}
AppPublisher=binkleyz2
AppPublisherURL=https://github.com/binkleyz2/NumberCipher
AppSupportURL=https://github.com/binkleyz2/NumberCipher/issues
AppUpdatesURL=https://github.com/binkleyz2/NumberCipher/releases
DefaultDirName={localappdata}\Programs\Cipherwords
DefaultGroupName=Cipherwords
DisableProgramGroupPage=yes
; Per-user install — no UAC prompt needed.
PrivilegesRequired=lowest
OutputBaseFilename={#OutputBasename}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\Cipherwords.exe
ChangesAssociations=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#ExeSource}"; DestDir: "{app}"; DestName: "Cipherwords.exe"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Cipherwords"; Filename: "{app}\Cipherwords.exe"
Name: "{autodesktop}\Cipherwords"; Filename: "{app}\Cipherwords.exe"; Tasks: desktopicon

[Run]
; Register File Explorer context menu at the installed path.
Filename: "{app}\Cipherwords.exe"; Parameters: "--register-shell"; Flags: runhidden waituntilterminated; StatusMsg: "Registering File Explorer integration..."
; Offer to launch after install.
Filename: "{app}\Cipherwords.exe"; Description: "{cm:LaunchProgram,Cipherwords}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove context menu entries before files are deleted.
Filename: "{app}\Cipherwords.exe"; Parameters: "--unregister-shell"; Flags: runhidden waituntilterminated

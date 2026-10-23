# Agent prompt: Package VaultKey as a zero-dependency Windows distributable

Paste everything below this line to your AI coding agent (Claude Code, etc.),
running in a Windows environment with PowerShell.

---

## Context

I have a working C++/Qt6 desktop app called VaultKey (source in the current
folder: `CMakeLists.txt`, `src/`, `login.html`, `dashboard.html`). It already
builds successfully with CMake + vcpkg + MSVC into `build/Release/vaultkey.exe`.

That build only runs on *this* machine because `vaultkey.exe` dynamically
links against Qt6 DLLs, argon2, OpenSSL, and SQLite3, all currently sitting in
the vcpkg install tree - they are not next to the exe.

**Goal**: produce a distributable that a person with NO developer tools, NO
Qt, NO Visual Studio, and NO vcpkg installed can download and run. Concretely,
two deliverables, in this order:

1. **`VaultKeySetup.exe`** - a single installer file. Running it installs
   VaultKey into `Program Files`, creates Start Menu / Desktop shortcuts, and
   needs nothing else downloaded. This is how essentially all commercial
   Windows software (games included) actually ships - "one exe" from the
   user's perspective, even though it contains many files once installed.
2. **`VaultKey-Portable.exe`** - a single portable file (no installer, no
   admin rights, no Start Menu entry) that silently unpacks its bundled
   dependencies to a temp folder at launch and runs from there. This is the
   closer match to "just an exe that runs," for anyone who doesn't want an
   installer at all.

Do not skip straight to reasoning about how to do this - work through the
phases below in order, and actually run each command rather than assuming it
worked. Verify every phase before moving to the next.

---

## Phase 1 - Confirm the baseline dev build still works

1. From the project root, confirm a clean Release build succeeds:
   ```powershell
   Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
   mkdir build; cd build
   cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\path\to\vcpkg\scripts\buildsystems\vcpkg.cmake
   cmake --build . --config Release
   cd ..
   ```
   (Substitute the real vcpkg path.) Confirm `build\Release\vaultkey.exe`,
   `login.html`, and `dashboard.html` all exist in that folder afterward.

2. Run `build\Release\vaultkey.exe` directly and confirm the login screen
   appears. This is your known-good baseline - if later phases break
   something, you can diff against this.

---

## Phase 2 - Gather every runtime dependency into one self-contained folder

Create a clean staging folder, e.g. `dist\VaultKey\`, and populate it so that
folder alone - copied to any Windows machine - runs correctly with nothing
else installed.

1. Copy the app itself:
   ```powershell
   mkdir dist\VaultKey
   Copy-Item build\Release\vaultkey.exe, build\Release\login.html, build\Release\dashboard.html dist\VaultKey\
   ```

2. Locate Qt's `windeployqt.exe` (it's inside the vcpkg Qt install, typically
   `<vcpkg>\installed\x64-windows\tools\qt6\bin\windeployqt.exe` - find the
   exact path with `Get-ChildItem -Recurse -Filter windeployqt.exe` under the
   vcpkg root if unsure). Run it against the exe in the staging folder:
   ```powershell
   & "<path>\windeployqt.exe" dist\VaultKey\vaultkey.exe --webenginewidgets --release --compiler-runtime --no-translations
   ```
   This is the critical step - it copies every Qt DLL, platform plugin,
   and (crucially for this app) the entire QtWebEngine runtime: `QtWebEngineProcess.exe`,
   `icudtl.dat`, `qtwebengine_resources.pak`,
   `qtwebengine_resources_100p.pak`, `qtwebengine_resources_200p.pak`, and the
   `translations\qtwebengine_locales\` folder. **Do not proceed if any of
   those files are missing from `dist\VaultKey\` afterward** - the app will
   silently fail to show the web view without them. Check with:
   ```powershell
   Get-ChildItem dist\VaultKey -Recurse | Where-Object { $_.Name -match "icudtl|QtWebEngineProcess|qtwebengine_resources" }
   ```
   If `windeployqt` did not copy the WebEngine resources (this happens on
   some Qt packagings), manually locate and copy them from the vcpkg Qt
   install's `resources\` and `translations\qtwebengine_locales\`
   subfolders into `dist\VaultKey\` at the same relative paths
   `windeployqt` would have used (same folder as the exe, or a `resources\`
   subfolder next to it - check `windeployqt`'s own output log for the
   expected layout it assumed).

3. `windeployqt` does not know about this app's non-Qt dependencies. Find and
   copy these three manually - locate each with
   `Get-ChildItem -Recurse -Filter <name>.dll` under the vcpkg root:
   - `argon2.dll`
   - `libcrypto-3-x64.dll` and `libssl-3-x64.dll` (OpenSSL)
   - `sqlite3.dll`
   ```powershell
   Copy-Item <located-path>\argon2.dll dist\VaultKey\
   Copy-Item <located-path>\libcrypto-3-x64.dll dist\VaultKey\
   Copy-Item <located-path>\libssl-3-x64.dll dist\VaultKey\
   Copy-Item <located-path>\sqlite3.dll dist\VaultKey\
   ```

4. **Verification - this is the step that actually proves the goal is met.**
   Copy the entire `dist\VaultKey\` folder to a machine (or a clean VM, or at
   minimum a different user account) that has never had Qt, Visual Studio, or
   vcpkg installed. Double-click `vaultkey.exe` there. It must launch and
   show the login screen with no "missing DLL" error dialogs. If any DLL is
   reported missing, go back to step 3 and locate/copy it - do not consider
   this phase done until it runs clean on a machine with none of the dev
   tooling installed. If you don't have a second machine available, at
   minimum use `Dependencies.exe` (the open-source Dependency Walker
   successor, https://github.com/lucasg/Dependencies) against `vaultkey.exe`
   and every `.dll` in the folder to confirm nothing resolves outside
   `dist\VaultKey\` itself or the Windows system directories.

---

## Phase 3 - Build the installer (`VaultKeySetup.exe`)

1. Install Inno Setup (free): download from `jrsoftware.org/isinfo.php` and
   install it normally (this is a build-time tool on your machine only - it
   does not end up as a dependency for the people receiving your installer).

2. Create `installer.iss` in the project root:
   ```iss
   [Setup]
   AppName=VaultKey
   AppVersion=1.0
   DefaultDirName={autopf}\VaultKey
   DefaultGroupName=VaultKey
   OutputDir=dist
   OutputBaseFilename=VaultKeySetup
   Compression=lzma2
   SolidCompression=yes
   ArchitecturesInstallIn64BitMode=x64
   PrivilegesRequired=lowest

   [Files]
   Source: "dist\VaultKey\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs

   [Icons]
   Name: "{group}\VaultKey"; Filename: "{app}\vaultkey.exe"
   Name: "{autodesktop}\VaultKey"; Filename: "{app}\vaultkey.exe"

   [Run]
   Filename: "{app}\vaultkey.exe"; Description: "Launch VaultKey"; Flags: nowait postinstall skipifsilent
   ```
   `PrivilegesRequired=lowest` matters - it installs to the current user's
   folder without asking for admin rights, which is both friendlier and one
   less thing that looks suspicious to SmartScreen/AV heuristics for an app
   that has no business needing elevation.

3. Compile it:
   ```powershell
   & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
   ```
   This produces `dist\VaultKeySetup.exe`.

4. **Verify** the same way as Phase 2 step 4: copy only
   `dist\VaultKeySetup.exe` to a clean machine/VM, run it, confirm it
   installs and launches with zero additional downloads or errors. This is
   the deliverable people can download and run like a normal Windows
   installer.

---

## Phase 4 - Build the portable single-file (`VaultKey-Portable.exe`)

This is optional - do it only after Phase 3 is verified working, since it's a
convenience wrapper around the same verified folder rather than a separate
thing that could hide new bugs.

1. Install Enigma Virtual Box (free): `enigmaprotector.com/en/downloads.html`
   - the "Virtual Box" tool specifically, not the unrelated virtualization
   software of a similar name.

2. Open Enigma Virtual Box, set:
   - **Input file**: `dist\VaultKey\vaultkey.exe`
   - **Output file**: `dist\VaultKey-Portable.exe`
3. Add every other file in `dist\VaultKey\` (all the DLLs, `login.html`,
   `dashboard.html`, the WebEngine resource files, the whole `translations\`
   and any `resources\`/`plugins\` subfolders) as virtual files, preserving
   their relative paths exactly as they sit next to `vaultkey.exe` in the
   staging folder. Enigma Virtual Box has a "Add Folder" option - use it on
   the whole `dist\VaultKey\` folder rather than adding files one by one, to
   avoid missing something.
4. Under Enigma's options, set files to extract to a temp directory at
   runtime (not memory-mapped) - QtWebEngine spawns a separate
   `QtWebEngineProcess.exe` subprocess that needs to find these files as real
   files on disk, not purely virtualized in the parent process's memory.
5. Compile.
6. **Verify** on a clean machine again: copy only `VaultKey-Portable.exe`,
   double-click it, confirm the login screen appears with no errors, no
   missing-DLL dialogs, and no visible extraction/console flash that looks
   broken.

If `QtWebEngineProcess.exe` fails to launch as a subprocess from inside
Enigma's virtualized filesystem (a known rough edge with WebEngine
specifically, because of that subprocess model), fall back to shipping
Phase 3's installer as the primary deliverable instead - it's the more
reliable option for this specific app and is genuinely the standard way
software like this ships.

---

## Phase 5 - Final report back to me

When done, tell me:
- Which of Phase 3 / Phase 4 actually passed the clean-machine test.
- The final file size of each deliverable.
- Exact list of every file that ended up in `dist\VaultKey\` (so I have a
  record of what's actually being shipped).
- Anything in Phase 2 step 2/3 that had to be located manually rather than
  being auto-copied by `windeployqt`, so I know where those paths were on
  this machine if it needs redoing after a Qt/vcpkg update later.

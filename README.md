# memocry

A secure, self-contained Python utility for symmetric file-level encryption and decryption using authenticated Fernet cryptography. Zero persistent state. No configuration files. No logs written to disk.

Current version: **v0.1.2**

---

## Requirements

- Python 3.10 or later
- `cryptography` library

---

## Setup

Create and activate a virtual environment named `memo` before installing dependencies.

### Windows

```
python -m venv memo
memo\Scripts\activate
pip install cryptography
```

### macOS and Linux

```
python3 -m venv memo
source memo/bin/activate
pip install cryptography
```

The environment only needs to be created once. Activate it before each session with the same `activate` command.

---

## Running

With the virtual environment active:

```
python memocry.py
```

The window auto-sizes to fit all interface elements on launch and centers on screen.

---

## Interface Layout

### Top Bar (Session Options + Log Toggle)

A strip of six toggle switches and a log visibility toggle. All switches are off by default. State resets entirely on every restart, leaving no persistent footprint.

**Toggle switches:**
- **Delete source after encrypt** - Deletes the original plain file after successful encryption.
- **Delete .enc after decrypt** - Deletes the encrypted file after successful decryption.
- **Delete key after encrypt** - Deletes the active encryption key after the batch completes.
- **Delete key after decrypt** - Deletes the active decryption key after the batch completes.
- **Extra warnings** - Enables confirmation dialogs before every batch operation and destructive action. Recommended for interactive use.
- **No warnings** - Suppresses all optional confirmation dialogs and pre-flight checks for system files and files in use. Safety-critical warnings (key file in selection, encrypting memocry.py itself) always fire regardless.

**Log button:** Show/Hide toggles the Session Log panel below the three file lists.

### Title Bar

The **memocry** title and a **Refresh** button sit at the top left. A second Refresh appears at the top of the Operations sidebar. The Family Folder controls sit at the top right.

### Family Folder Bar

Sets the monitored working directory. Use Browse to pick a folder, then Set to apply. The three file lists refresh automatically. Use Add Folder to queue a folder for encryption.

### Three-Column File Panel

The left panel is divided into three equal columns, each aligned with its corresponding right-side operation panel.

**Plain Files (left column - aligns with ENCRYPT)**
Lists all non-encrypted, non-key files discovered recursively in the Family Folder. Columns: type indicator (F = file), name without extension, extension, and size. Supports Ctrl+click and Shift+click for multi-selection. Right-click for context menu.

**Encrypted Files (center column - aligns with DECRYPT)**
Lists all `.enc` files discovered recursively. Columns: type indicator, name, original extension, key status, and size. Key status is color-coded: green = matched key found by exact prefix match, red = missing. Supports multi-selection. Selecting a row auto-fills the Decrypt key field if a paired key is found. Right-click for context menu.

**Detected Keys (right column - aligns with KEY MANAGEMENT)**
Lists all `.key` files discovered recursively in the Family Folder. Columns: key file name, size, and last modified date and time. Right-click to assign a key to the Encrypt or Decrypt field, view properties, rename, move, or delete.

### Session Log

A volatile, RAM-only activity ledger. Toggled via the Show/Hide button in the top bar. Records every operation outcome, skipped file, deletion event, rename, move, and folder zip action. Purged on clear or on exit. Never written to disk.

### Operations Panel (right sidebar)

**ENCRYPT**
- Key file: path to the Fernet key. Browse or type manually. The file name and full directory path are shown below the entry field once a key is selected.
- Browse Files: multi-file picker to add files outside the Family Folder.
- Encrypt Selected: encrypts all files selected in the Plain Files list plus any manually added files.
- If no key is selected, a prompt offers to generate one immediately.

**DECRYPT**
- Key file: path to the Fernet key. Browse or type manually. The file name and full directory path are shown below the entry field once a key is selected.
- Browse Files: multi-file picker for encrypted files outside the Family Folder.
- Decrypt Selected: decrypts all files selected in the Encrypted Files list plus any manually added files.

**KEY MANAGEMENT**
- Generate & Save Key: opens a dialog to name the key, choose where to save it, and generate it using the system CSPRNG.
- Delete All Detected Keys: permanently removes all `.key` files found in the Family Folder. Requires double confirmation.

---

## Right-Click Context Menu

Right-clicking any row in the three file lists opens a context menu. The menu disappears when clicking elsewhere in the window or pressing Escape.

**Plain Files list:**
- Encrypt Selected
- Rename
- Move to...
- Compress (zip)
- Properties (name, extension, location, size, created, modified, permissions)
- Remove from list
- Delete file

**Encrypted Files list:**
- Decrypt Selected
- Find Key
- Rename
- Move to...
- Compress (zip)
- Properties
- Remove from list
- Delete file

**Detected Keys list:**
- Use for Encryption (populates the Encrypt key field)
- Use for Decryption (populates the Decrypt key field)
- Rename
- Move to...
- Properties
- Delete key

---

## Folder Encryption

Click **Add Folder** in the folder bar. A dialog asks how to process the folder:

- **Encrypt each file individually** - Recursively collects every plain file and queues them as separate encryption jobs. Key files and already-encrypted files are excluded.
- **Zip folder, then encrypt the zip** - Creates a `.zip` archive of the entire folder next to the folder itself, adds it to the plain files queue, and refreshes the list. Click Encrypt Selected to encrypt the zip file.

---

## Key Management

### Generating a Key

1. Click **Generate & Save Key** in the Key Management panel.
2. Enter a file name and choose a save location.
3. Click **Generate & Save**.

If no key is selected when starting encryption, the application prompts to generate one at that moment.

### Key Display in Operations

When a key file is selected in either the Encrypt or Decrypt field, both the file name and its full directory path are displayed below the entry. This makes it easy to confirm the correct key at a glance without expanding the path manually.

### Key Auto-Pairing

The Smart Key Mapper pairs encrypted files with their keys strictly by prefix match:
- `document.pdf.enc` looks only for `document.pdf.key` in the same directory.
- No fallback to a generic `encryption.key`. Only exact stem matches are auto-paired.

### Finding Keys Manually

Use **Find Key** from the right-click menu on any encrypted file. The key search dialog scans the Family Folder, the file's own directory, and the user home directory for all `.key` files. An additional location can be browsed and searched manually. Select any candidate and click Use Selected Key to assign it to the Decrypt field.

### Key Safety Warning

The encryption key is the sole mechanism for recovering encrypted data. If the key file is lost, destroyed, or corrupted, the encrypted data is permanently and mathematically unrecoverable. There is no bypass or recovery path.

Back up keys immediately to a secure, separate location such as a password manager, encrypted USB drive, or physical vault. Do not store keys alongside the encrypted files.

---

## Pre-flight Warnings

memocry checks the following before any encryption operation. System file and in-use checks are suppressed when **No warnings** is on. Safety-critical warnings always fire.

- **memocry.py itself is in the selection** - Encrypting the application file makes it unrunnable.
- **The active key file is in the selection** - Encrypting the key currently selected for the operation.
- **Other key files are in the selection** - Encrypting a key without a backup makes it permanently inaccessible.
- **System files are detected** - Files in system directories or root-owned files that may affect OS stability.
- **Files in use by another process** - Files currently open that may be corrupted if modified.

---

## Progress Bar

The progress bar in the status bar is only visible during active encrypt or decrypt operations. When idle, the status bar shows only the current status text with no extra elements.

---

## Security Model

**Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256). Authenticated encryption. Any tampered or corrupted file causes decryption to abort. The failed output file is never written to disk.

**Key handling:** Key material is loaded into volatile memory only for the duration of the operation. References are explicitly nullified on completion.

**No persistence:** No settings, history, temporary files, or logs are written to disk at any time. All state is session-scoped and RAM-resident only.

**Stream processing:** Files are read in 64 KB chunks to maintain a constant memory footprint regardless of file size.

**Atomic writes:** Output is staged to a `.tmp` path and atomically replaced on success. Partial output is cleaned up on failure. Failed decryptions do not produce or retain output files.

**Input validation:** All file paths are validated before any I/O. Path traversal attempts and invalid file types are rejected.

**Background threading:** All cryptographic operations run on a dedicated daemon thread. The interface remains responsive with live progress reporting.

**Generic error messaging:** No stack traces or internal diagnostics are shown in the interface. Error reporting is intentionally high-level to prevent information leakage.

---

## Troubleshooting

**No key selected on encrypt click**
A dialog will offer to generate one. Accept to open the key generation window.

**Decryption failed**
The key does not match the one used for encryption, or the file has been modified or corrupted. Use Find Key from the right-click menu to search for matching keys. The source encrypted file is never modified or deleted on failure.

**Key pairing shows Missing**
Auto-pairing only matches by exact stem. Example: `file.txt.enc` requires `file.txt.key` in the same directory. Use Browse or Find Key to locate the correct key manually.

**Files not appearing in lists**
Ensure the correct Family Folder is set and click Refresh. Files are discovered recursively.

**Application not launching**
Confirm Python 3.10+ is installed, the `memo` virtual environment is active, and `cryptography` is installed. Re-run `pip install cryptography` inside the active environment if needed.

**Zip mode queued but not encrypting**
After choosing "Zip folder, then encrypt the zip", the zip is queued but not yet encrypted. Click Encrypt Selected to proceed with the encryption step.

---

## File Scope

This project is delivered as exactly two files:

- `memocry.py` - complete application logic
- `README.md` - this document

No additional scripts, modules, or configuration files are required or permitted beyond the virtual environment and the `cryptography` library.

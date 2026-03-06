# memocry

A secure, self-contained Python utility for symmetric file-level encryption and decryption using authenticated Fernet cryptography. Zero persistent state. No configuration files. No logs written to disk.

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

The window auto-sizes to fit all interface elements on launch. No configuration is required.

---

## Interface Layout
![Memocry v0.1.0 Screenshot](memocry%20v0.1.0.png)
### Toggle Bar (top strip)

Five session-only toggle switches. Off by default. State resets on every restart, leaving no persistent footprint.

- **Delete source after encrypt** - Deletes the original plain file after successful encryption.
- **Delete .enc after decrypt** - Deletes the encrypted file after successful decryption.
- **Delete key after encrypt** - Deletes the active encryption key after the batch completes.
- **Delete key after decrypt** - Deletes the active decryption key after the batch completes.
- **Extra warnings** - Enables confirmation dialogs before every destructive action, including batch confirmation prompts. Recommended for interactive use.

### Family Folder Bar

Sets the monitored working directory. Use Browse to pick a folder, then Set to apply. The file lists refresh automatically. Use Add Folder to recursively queue an entire folder for encryption without changing the Family Folder itself.

### Encrypted Files (left panel, top)

Lists all `.enc` files discovered recursively within the Family Folder, showing their relative path, key pairing status, and size. Key status is color-coded: green means a matching key was found, red means missing. Supports Ctrl+click and Shift+click for multi-selection. Selecting a row auto-fills the Decrypt key field if a paired key is detected.

### Plain Files (left panel, middle)

Lists all non-encrypted, non-key files discovered recursively. Supports multi-selection for batch encryption.

### Session Log (left panel, bottom)

A volatile, RAM-only activity ledger. Records every operation outcome, skipped file, and deletion event. Purged on clear or on exit. Never written to disk.

### Operations Panel (right sidebar)

**ENCRYPT**
- Key file: path to the Fernet key to use. Browse or type manually.
- Browse Files: open a multi-file picker to queue additional files.
- Encrypt Selected: encrypts all files selected in the Plain Files list plus any manually browsed files.
- If no key is selected when clicking Encrypt, a prompt offers to generate one immediately.

**DECRYPT**
- Key file: path to the Fernet key to use. Browse or type manually.
- Browse Files: open a multi-file picker for encrypted files outside the Family Folder.
- Decrypt Selected: decrypts all files selected in the Encrypted Files list plus any manually browsed files.

**KEY MANAGEMENT**
- Generate & Save Key: opens a dialog to name the key, choose where to save it, and generate it using the system CSPRNG.
- Delete All Detected Keys: permanently removes all `.key` files found recursively in the Family Folder. Requires double confirmation.

---

## Folder Encryption

To encrypt an entire folder, click **Add Folder** in the folder bar. The application recursively collects every plain file in the chosen folder and queues them for the next Encrypt Selected operation. Key files and already-encrypted files are excluded automatically.

---

## Key Management

### Generating a Key

1. Click **Generate & Save Key** in the Key Management panel.
2. Enter a file name and choose a save location.
3. Click **Generate & Save**.

The key is generated using a cryptographically secure pseudo-random number generator (CSPRNG) and saved to the chosen path. If no key is selected when starting encryption, the application prompts to generate one at that moment.

### Key Pairing

The Smart Key Mapper automatically pairs encrypted files with their keys:
- A file named `document.pdf.enc` looks for `document.pdf.key` in the same directory first.
- If no specific key is found, it falls back to `encryption.key` in the Family Folder root.

### Key Safety Warning

The encryption key is the sole mechanism for recovering encrypted data. If the key file is lost, destroyed, or corrupted, the encrypted data is permanently and mathematically unrecoverable. There is no bypass or recovery path.

Back up keys immediately to a secure, separate location such as a password manager, encrypted USB drive, or physical vault. Do not store keys in the same location as the encrypted files.

---

## Key File Warnings

memocry warns before encrypting a `.key` file included in a selection. Encrypting a key file without a secure backup of that key - or encrypting the same key currently selected for the operation - will result in permanent data loss if the key cannot be recovered afterward.

---

## Security Model

**Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256). Authenticated encryption. Any tampered or corrupted file will cause decryption to abort.

**Key handling:** Key material is loaded into volatile memory only for the duration of the operation. References are explicitly nullified on completion.

**No persistence:** No settings, history, temporary files, or logs are written to disk at any time. All state is session-scoped and RAM-resident only.

**Stream processing:** Files are read in 64 KB chunks to maintain a constant memory footprint regardless of file size.

**Atomic writes:** Output is staged to a `.tmp` path and atomically replaced on success. Partial output is cleaned up on failure.

**Input validation:** All file paths are validated before any I/O. Path traversal attempts and invalid file types are rejected.

**Background threading:** All cryptographic operations run on a dedicated daemon thread. The interface remains responsive with live progress reporting.

**Generic error messaging:** No stack traces or internal diagnostics are shown in the interface. Error reporting is intentionally high-level to prevent information leakage.

---

## Troubleshooting

**No key selected on encrypt click**
A dialog will offer to generate one. Accept to open the key generation window, then retry.

**Decryption failed**
The key does not match the one used for encryption, or the file has been modified or corrupted. Verify you are using the correct key.

**Files not appearing in lists**
Ensure the correct Family Folder is set and click Refresh. Plain files and encrypted files are discovered recursively.

**Application not launching**
Confirm Python 3.10+ is installed, the `memo` virtual environment is active, and `cryptography` is installed. Re-run `pip install cryptography` inside the active environment if needed.

**Key pairing shows Missing**
No `.key` file matching the encrypted file's stem and no `encryption.key` in the Family Folder root were found. Locate the correct key file and specify it manually in the Decrypt key field.

---

## File Scope

This project is delivered as exactly two files:

- `memocry.py` - complete application logic
- `README.md` - this document

No additional scripts, modules, or configuration files are required or permitted beyond the virtual environment and the `cryptography` library.

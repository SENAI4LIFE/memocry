# memocry

A secure, self-contained Python utility for symmetric file-level encryption and decryption using authenticated Fernet cryptography.

---

## Purpose

memocry provides a portable, graphical encryption tool with zero persistent state. All configuration, keys, and operational data exist exclusively in volatile memory during execution. No logs, settings files, or temporary artifacts are written to disk at any point.

---

## Requirements

- Python 3.10 or later
- `cryptography` library (installed into a virtual environment)

---

## Setup

A virtual environment isolates the `cryptography` dependency from your system Python installation and is required before running memocry.

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

The virtual environment only needs to be created once. On subsequent uses, activate it with the same `activate` command before running the application.

memocry performs a dependency check at startup and will print installation instructions if the library is missing.

---

## Running the Application

With the virtual environment active, execute from any directory:

```
python memocry.py
```

No configuration files or setup steps beyond venv activation are required. All file system interactions use paths resolved dynamically at runtime.

---

## Interface Overview

The interface is divided into three zones.

**Top bar** - Displays and controls the active Family Folder, which is the monitored directory for automatic file and key discovery. Defaults to the working directory at launch.

**Center panel** - Lists all discovered encrypted files (`.enc`) alongside their key pairing status. A secondary list shows plain files available for encryption. Both lists update automatically on refresh.

**Right sidebar** - Contains the Encrypt, Decrypt, and Key Management operation panels. Files can be selected from the lists or specified manually via browse dialogs.

**Status bar** - Displays operation status and a progress indicator for active tasks.

---

## Key Management

### Generating a Key

1. Click **Generate New Key** in the Key Management panel.
2. Confirm the action in the dialog.
3. The key is saved as `encryption.key` in the current Family Folder.

> **Critical Warning:** The encryption key is the sole mechanism for recovering encrypted data. If the key file is lost, destroyed, or corrupted, the encrypted data becomes permanently and mathematically unrecoverable. There is no fallback, bypass, or recovery mechanism.

**Back up your key immediately** to a secure, redundant location such as a password manager, encrypted USB drive, or physical vault. Do not store the key in the same location as the encrypted files.

### Key File Naming

By default, memocry uses `encryption.key` as the key filename. For automatic key pairing, a key named `<filename>.key` placed alongside `<filename>.enc` will be detected and associated automatically.

---

## Encrypting a File

1. Ensure a key exists in the Family Folder (generate one if needed).
2. Select a plain file from the lower list, or use the **...** button in the Encrypt panel to browse manually.
3. Click **Encrypt File**.
4. Confirm the dialog.

The output file is saved as `<original_filename><extension>.enc` in the same directory. The original file is not modified or deleted.

---

## Decrypting a File

1. Select an encrypted file from the upper list (the key field is populated automatically if a paired key is found), or specify both paths manually using the browse buttons in the Decrypt panel.
2. Click **Decrypt File**.
3. Confirm the dialog.

The output file is restored to its original filename by removing the `.enc` extension.

---

## Family Folder

The Family Folder is the directory memocry monitors for automatic discovery. It defaults to the working directory at launch. To change it:

1. Enter a new path in the folder field in the top bar, or click **Browse**.
2. Click **Set** to apply.

Files outside the Family Folder can still be processed using manual path entry or browse dialogs.

---

## Security Model

**Encryption algorithm:** Fernet (AES-128-CBC with HMAC-SHA256 authentication). Fernet guarantees that encrypted data cannot be read or modified without the correct key.

**Key material handling:** Keys are loaded into volatile memory only for the duration of the cryptographic operation. References are nullified immediately upon task completion.

**No persistent state:** No settings, usage history, temporary files, or logs are written to disk at any time.

**File processing:** Files are processed using chunked stream reading (64 KB blocks) to maintain a constant memory footprint regardless of file size.

**Atomic writes:** Output files are written to a temporary path first and atomically renamed upon successful completion, preventing partial or corrupted output if an operation is interrupted.

**Input validation:** All file paths are validated for existence, type, and permissions before any I/O operation begins. Path traversal inputs are rejected.

**Threading:** Cryptographic operations run on a background thread. The interface remains responsive during processing and displays a live progress indicator.

**Data at rest:** Application-level file shredding is not implemented, as it is ineffective against modern storage wear-leveling and filesystem journaling. Security for data at rest should be enforced via operating system-level full-disk encryption.

---

## Troubleshooting

**"No Key Found" error during encryption**
Generate a key using the Key Management panel before encrypting.

**"Operation Failed" during decryption**
Verify that the key file matches the one used during encryption. Fernet keys are not interchangeable. Confirm the encrypted file has not been modified or corrupted.

**Files not appearing in the list**
Ensure the correct Family Folder is set and click **Refresh**. Only files with the `.enc` extension appear in the encrypted file list.

**Application not launching**
Confirm Python 3.10+ is installed, the virtual environment is active, and the `cryptography` package is installed. Re-run `pip install cryptography` inside the active venv if needed.

**Output file already exists warning**
A confirmation dialog is shown before overwriting any existing file. Decline to cancel the operation without data loss.

---

## File Scope

This project is delivered as exactly two files:

- `memocry.py` - complete application logic
- `README.md` - this document

No additional scripts, modules, or configuration files are required or permitted beyond the virtual environment and the `cryptography` library.

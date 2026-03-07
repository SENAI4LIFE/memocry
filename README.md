# memocry

A self-contained, zero-footprint Python utility for symmetric file-level encryption and decryption. Built on authenticated Fernet cryptography with a modern dark-themed GUI. Two files. No installation. Runs anywhere Python 3.10+ is available.

---

## Requirements

- Python 3.10 or higher
- `cryptography` library

```
pip install cryptography
```

---

## Usage

```
python memocry.py
```

On first launch memocry opens in your current working directory as the **Family Folder** — the directory it scans and operates on by default.

---

## How it Works

### Family Folder

The Family Folder is the root directory memocry watches. All three file panels — Plain Files, Encrypted Files, and Detected Keys — are populated by scanning this folder recursively. You can change it at any time using the **Browse** and **Set** controls in the header.

### Encrypting Files

1. Select files in the **Plain Files** panel (Ctrl/Shift+click for multi-select), or click **Browse Files** in the ENCRYPT panel.
2. Select or generate a key in the ENCRYPT panel.
3. Click **Encrypt Selected**.

### Decrypting Files

1. Select files in the **Encrypted Files** panel, or click **Browse Files** in the DECRYPT panel.
2. Select a key in the DECRYPT panel (it auto-fills if a paired key is detected).
3. Click **Decrypt Selected**.

### Keys

Keys are standard Fernet keys stored as `.key` files. Generate them with **Generate & Save Key** in KEY MANAGEMENT or from within the ENCRYPT panel when no key is loaded. **Back up every key to a separate secure location immediately.** Loss of a key makes all files encrypted with it permanently unrecoverable.

---

## Features

### File Panels

| Panel | Color | Shows |
|---|---|---|
| 📄 Plain Files | Green | Regular files and subfolders |
| 🔒 Encrypted Files | Purple | `.enc` files with key-pairing status |
| 🗝 Detected Keys | Orange | `.key` files in the family folder |

- **Folders** appear in the Plain Files panel with a 📁 icon and file count
- Column widths are fixed and never auto-resize the window
- File names are shown without full path — name only

### Right-click Context Menus

Files and folders support different context menus:

**Plain files:** Encrypt, Rename, Move to, Compress (zip), Secure Wipe, Properties, Remove from list, Delete

**Folders:** Encrypt files individually, Zip folder then Encrypt, Compress (zip only), Rename, Move to, Properties

**Encrypted files:** Decrypt, Find Key, Rename, Move to, Compress (zip), Secure Wipe, Properties, Remove from list, Delete

**Keys:** Use for Encryption, Use for Decryption, Rename, Move to, Properties, Delete key

### Add Folder

The **Add Folder** button lets you choose a folder and pick one of two modes:

- **Encrypt each file individually** — queues all plain files from the folder for the next encrypt operation
- **Zip folder then encrypt the zip** — creates a `.zip` archive from the folder, then immediately encrypts it using the currently loaded key; the intermediate zip is deleted after successful encryption

### Session Toggles (top bar)

| Toggle | Effect |
|---|---|
| Delete source after encrypt | Deletes original plain files after successful encryption |
| Delete .enc after decrypt | Deletes the `.enc` file after successful decryption |
| Delete key after encrypt | Deletes the key file after successful encryption |
| Delete key after decrypt | Deletes the key file after successful decryption |
| Extra warnings | Adds confirmation dialogs before every operation |
| No warnings | Suppresses all optional confirmation dialogs |

Safety-critical warnings (encrypting memocry.py itself, encrypting the active key) always fire regardless of toggle state.

### Key Management

- **Generate & Save Key** — creates a new Fernet key and saves it to a location of your choice
- **Remove Selected Key** — deletes the key selected in the Detected Keys panel
- **Delete All Detected Keys** — deletes all `.key` files found in the family folder (double-confirmed)

### Tools Panel

- **Refresh Files** — re-scans the family folder
- **Disk Space Info** — shows total, used, and free space for the family folder's volume
- **Verify Key Format** — validates the Fernet format of the currently loaded key

### Secure Wipe

Available via right-click on any file. Performs a 3-pass random overwrite before deletion, making file recovery significantly harder than a standard delete.

### Session Log

A volatile, session-only log of all operations. Accessible via the **Show/Hide** button in the top bar. Cleared automatically on exit. Never written to disk.

---

## Security Model

- **Fernet (AES-128-CBC + HMAC-SHA256)** — authenticated encryption; any tampering or wrong key aborts decryption immediately
- **Atomic writes** — all files are written to a `.tmp` file first and renamed on success; partial writes never corrupt the destination
- **System file protection** — known system paths and root-owned files are flagged before encryption
- **In-use detection** — files open by another process are warned about before modification
- **No persistence** — all preferences, session state, and key material exist only in RAM during the session
- **Separation of concerns** — the GUI never holds raw key material; the cryptographic engine is isolated

---

## Architecture

```
memocry.py
├── CryptographicEngine     — Fernet encrypt/decrypt, key gen, zip, secure wipe
├── PathValidator           — input/output/key path sanitization
├── FamilyFolderScanner     — discovers plain files, encrypted files, keys, folders
├── BatchOperationWorker    — background thread for batch encrypt/decrypt
├── ToggleButton            — session option toggle widget
├── KeySaveDialog           — key generation dialog
├── KeySearchDialog         — key search/match dialog
├── ContextMenu             — right-click menus (file, folder, encrypted, key)
├── KeyInfoLabel            — key display widget in operation panels
└── MemocryApp              — main application window and orchestration
```

---

## Changelog

See `v0_1.3` for the latest release notes.

---


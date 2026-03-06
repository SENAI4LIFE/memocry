import sys
import os
import stat
import importlib
import threading
import queue
import pathlib
import zipfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


REQUIRED_PACKAGES = ["cryptography"]


def verify_dependencies():
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"Missing required packages: {', '.join(missing)}")
        print(f"Install with: pip install {' '.join(missing)}")
        sys.exit(1)


verify_dependencies()

from cryptography.fernet import Fernet, InvalidToken


CHUNK_SIZE = 64 * 1024
ENCRYPTED_EXTENSION = ".enc"
KEY_EXTENSION = ".key"
DEFAULT_KEY_NAME = "encryption.key"
APP_TITLE = "memocry"
SELF_PATH = pathlib.Path(__file__).resolve()

SYSTEM_PATH_PREFIXES = []
if sys.platform.startswith("win"):
    SYSTEM_PATH_PREFIXES = [
        pathlib.Path("C:/Windows"),
        pathlib.Path("C:/Program Files"),
        pathlib.Path("C:/Program Files (x86)"),
    ]
else:
    SYSTEM_PATH_PREFIXES = [
        pathlib.Path("/etc"),
        pathlib.Path("/bin"),
        pathlib.Path("/sbin"),
        pathlib.Path("/usr"),
        pathlib.Path("/boot"),
        pathlib.Path("/sys"),
        pathlib.Path("/proc"),
        pathlib.Path("/dev"),
        pathlib.Path("/lib"),
        pathlib.Path("/lib64"),
    ]


def is_system_file(path: pathlib.Path) -> bool:
    resolved = path.resolve()
    for prefix in SYSTEM_PATH_PREFIXES:
        try:
            resolved.relative_to(prefix)
            return True
        except ValueError:
            continue
    if sys.platform.startswith("win"):
        return False
    try:
        file_stat = resolved.stat()
        mode = file_stat.st_mode
        if stat.S_ISSOCK(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode):
            return True
        if file_stat.st_uid == 0 and not os.access(resolved, os.W_OK):
            return True
    except Exception:
        pass
    return False


def is_file_in_use(path: pathlib.Path) -> bool:
    resolved = path.resolve()
    if not resolved.is_file():
        return False
    if sys.platform.startswith("win"):
        try:
            with open(resolved, "r+b"):
                pass
            return False
        except (IOError, OSError, PermissionError):
            return True
    else:
        try:
            import fcntl
            with open(resolved, "r+b") as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False
                except (IOError, OSError):
                    return True
        except Exception:
            return False


class CryptographicEngine:

    def generate_key(self) -> bytes:
        return Fernet.generate_key()

    def validate_key_material(self, raw: bytes) -> bool:
        try:
            Fernet(raw.strip())
            return True
        except Exception:
            return False

    def load_key(self, key_path: pathlib.Path) -> bytes:
        resolved = key_path.resolve()
        if not resolved.is_file():
            raise FileNotFoundError("Key file not found.")
        raw = resolved.read_bytes().strip()
        if not self.validate_key_material(raw):
            raise ValueError("Key file does not contain valid Fernet key material.")
        return raw

    def encrypt_file(self, source_path: pathlib.Path, key_material: bytes,
                     output_path: pathlib.Path, progress_callback=None):
        fernet = Fernet(key_material)
        resolved_source = source_path.resolve()
        if not resolved_source.is_file():
            raise ValueError("Source is not a valid file.")
        total_size = resolved_source.stat().st_size
        bytes_read = 0
        chunks = []
        try:
            with open(resolved_source, "rb") as src:
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    bytes_read += len(chunk)
                    if progress_callback and total_size > 0:
                        progress_callback(bytes_read / total_size * 50)
        finally:
            pass
        plaintext = b"".join(chunks)
        del chunks
        ciphertext = fernet.encrypt(plaintext)
        del plaintext
        temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
        try:
            with open(temp_path, "wb") as dst:
                dst.write(ciphertext)
            del ciphertext
            temp_path.replace(output_path)
            if progress_callback:
                progress_callback(100)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

    def decrypt_file(self, source_path: pathlib.Path, key_material: bytes,
                     output_path: pathlib.Path, progress_callback=None):
        fernet = Fernet(key_material)
        resolved_source = source_path.resolve()
        if not resolved_source.is_file():
            raise ValueError("Source is not a valid file.")
        total_size = resolved_source.stat().st_size
        bytes_read = 0
        chunks = []
        try:
            with open(resolved_source, "rb") as src:
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    bytes_read += len(chunk)
                    if progress_callback and total_size > 0:
                        progress_callback(bytes_read / total_size * 50)
        finally:
            pass
        ciphertext = b"".join(chunks)
        del chunks
        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken:
            raise ValueError("Decryption failed: invalid key or corrupted data.")
        finally:
            del ciphertext
        temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
        try:
            with open(temp_path, "wb") as dst:
                dst.write(plaintext)
            del plaintext
            temp_path.replace(output_path)
            if progress_callback:
                progress_callback(100)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

    def zip_folder(self, folder_path: pathlib.Path, zip_output_path: pathlib.Path,
                   progress_callback=None):
        all_files = [f for f in sorted(folder_path.rglob("*")) if f.is_file()]
        total = len(all_files)
        with zipfile.ZipFile(zip_output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for idx, f in enumerate(all_files):
                arcname = f.relative_to(folder_path.parent)
                zf.write(f, arcname)
                if progress_callback and total > 0:
                    progress_callback((idx + 1) / total * 40)

    def save_key(self, key_material: bytes, key_path: pathlib.Path):
        temp_path = key_path.with_suffix(key_path.suffix + ".tmp")
        try:
            with open(temp_path, "wb") as f:
                f.write(key_material)
            temp_path.replace(key_path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

    def safe_delete(self, file_path: pathlib.Path):
        resolved = file_path.resolve()
        if resolved.is_file():
            resolved.unlink()

    def find_candidate_keys(self, encrypted_path: pathlib.Path,
                             search_roots: list[pathlib.Path]) -> list[pathlib.Path]:
        stem = encrypted_path.stem
        exact_name = stem + KEY_EXTENSION
        candidates = []
        seen = set()
        for root in search_roots:
            if not root.exists():
                continue
            for kf in root.rglob(f"*{KEY_EXTENSION}"):
                if not kf.is_file():
                    continue
                resolved = kf.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                if kf.name == exact_name:
                    candidates.insert(0, kf)
                elif kf.name == DEFAULT_KEY_NAME:
                    candidates.append(kf)
                else:
                    candidates.append(kf)
        return candidates


class PathValidator:

    def __init__(self, family_folder: pathlib.Path):
        self.family_folder = family_folder.resolve()

    def validate_input_file(self, file_path: pathlib.Path) -> pathlib.Path:
        resolved = file_path.resolve()
        if not resolved.exists():
            raise ValueError(f"File does not exist: {resolved.name}")
        if not resolved.is_file():
            raise ValueError(f"Not a regular file: {resolved.name}")
        if not os.access(resolved, os.R_OK):
            raise ValueError(f"File is not readable: {resolved.name}")
        return resolved

    def validate_output_path(self, file_path: pathlib.Path) -> pathlib.Path:
        resolved = file_path.resolve()
        parent = resolved.parent
        if not parent.exists():
            raise ValueError("Output directory does not exist.")
        if not os.access(parent, os.W_OK):
            raise ValueError("Output directory is not writable.")
        return resolved

    def validate_key_file(self, key_path: pathlib.Path) -> pathlib.Path:
        return self.validate_input_file(key_path)


class FamilyFolderScanner:

    def __init__(self, family_folder: pathlib.Path):
        self.family_folder = family_folder.resolve()

    def discover_encrypted_files(self) -> list[dict]:
        discovered = []
        if not self.family_folder.exists():
            return discovered
        for enc_file in sorted(self.family_folder.rglob(f"*{ENCRYPTED_EXTENSION}")):
            if not enc_file.is_file():
                continue
            stem = enc_file.stem
            candidate_key = enc_file.parent / (stem + KEY_EXTENSION)
            paired_key = candidate_key if candidate_key.is_file() else None
            size_bytes = enc_file.stat().st_size
            rel = enc_file.relative_to(self.family_folder)
            discovered.append({
                "encrypted_file": enc_file,
                "paired_key": paired_key,
                "display_name": str(rel),
                "key_status": "Found" if paired_key else "Missing",
                "size_bytes": size_bytes,
            })
        return discovered

    def discover_plain_files(self) -> list[pathlib.Path]:
        results = []
        if not self.family_folder.exists():
            return results
        for f in sorted(self.family_folder.rglob("*")):
            if f.is_file() and f.suffix != ENCRYPTED_EXTENSION and f.suffix != KEY_EXTENSION:
                results.append(f)
        return results

    def discover_key_files(self) -> list[pathlib.Path]:
        results = []
        if not self.family_folder.exists():
            return results
        for f in sorted(self.family_folder.rglob(f"*{KEY_EXTENSION}")):
            if f.is_file():
                results.append(f)
        return results


class BatchOperationWorker(threading.Thread):

    def __init__(self, tasks: list, result_queue: queue.Queue, progress_queue: queue.Queue):
        super().__init__(daemon=True)
        self.tasks = tasks
        self.result_queue = result_queue
        self.progress_queue = progress_queue

    def run(self):
        total = len(self.tasks)
        completed = 0
        errors = []
        for task_label, task_fn in self.tasks:
            try:
                task_fn()
                completed += 1
                self.progress_queue.put(("progress", task_label, completed, total, None))
            except Exception as exc:
                errors.append((task_label, str(exc)))
                self.progress_queue.put(("progress", task_label, completed, total, str(exc)))
        self.result_queue.put(("done", completed, total, errors))


class ToggleButton(tk.Frame):

    def __init__(self, parent, label: str, bg_color: str, colors: dict,
                 on_change=None, **kwargs):
        super().__init__(parent, bg=bg_color, **kwargs)
        self._colors = colors
        self._bg = bg_color
        self._on_change = on_change
        self._state = False

        self._track = tk.Canvas(self, width=36, height=18, bg=bg_color,
                                highlightthickness=0, cursor="hand2")
        self._track.pack(side="left", padx=(0, 6))
        self._track.bind("<Button-1>", self._toggle)

        self._label = tk.Label(self, text=label, bg=bg_color,
                               fg=colors["muted"], font=("Segoe UI", 8), cursor="hand2")
        self._label.pack(side="left")
        self._label.bind("<Button-1>", self._toggle)
        self._draw()

    def _draw(self):
        c = self._colors
        self._track.delete("all")
        track_color = c["accent"] if self._state else "#3a3a52"
        self._track.create_oval(0, 1, 36, 17, fill=track_color, outline="")
        knob_x = 20 if self._state else 4
        knob_color = "#ffffff" if self._state else c["muted"]
        self._track.create_oval(knob_x, 3, knob_x + 12, 15, fill=knob_color, outline="")
        self._label.configure(fg=c["fg"] if self._state else c["muted"])

    def _toggle(self, _event=None):
        self._state = not self._state
        self._draw()
        if self._on_change:
            self._on_change(self._state)

    @property
    def value(self) -> bool:
        return self._state


class KeySaveDialog(tk.Toplevel):

    def __init__(self, parent, default_folder: pathlib.Path, engine: CryptographicEngine):
        super().__init__(parent)
        self.title("Generate & Save Key")
        self.resizable(False, False)
        self.grab_set()
        self.result_key_path = None
        self._engine = engine
        self._default_folder = default_folder
        self._colors = parent._colors
        self.configure(bg=self._colors["bg"])
        self._build()
        self.transient(parent)
        self.wait_visibility()
        self.focus_set()

    def _build(self):
        c = self._colors
        outer = tk.Frame(self, bg=c["bg"], padx=22, pady=20)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="Generate New Key", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 13, "bold")).pack(anchor="w")
        tk.Frame(outer, bg="#3a3a52", height=1).pack(fill="x", pady=(8, 14))

        tk.Label(outer, text="Key file name:", bg=c["bg"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w")
        self._name_var = tk.StringVar(value=DEFAULT_KEY_NAME)
        ttk.Entry(outer, textvariable=self._name_var, width=38).pack(fill="x", pady=(3, 10))

        tk.Label(outer, text="Save location:", bg=c["bg"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w")
        loc_row = tk.Frame(outer, bg=c["bg"])
        loc_row.pack(fill="x", pady=(3, 10))
        self._loc_var = tk.StringVar(value=str(self._default_folder))
        ttk.Entry(loc_row, textvariable=self._loc_var, width=30).pack(side="left",
                                                                        expand=True, fill="x")
        ttk.Button(loc_row, text="Browse", style="Secondary.TButton",
                   command=self._browse_location).pack(side="right", padx=(6, 0))

        warn = tk.Frame(outer, bg=c["surface"], padx=10, pady=10)
        warn.pack(fill="x", pady=(0, 14))
        tk.Label(warn, text="WARNING", bg=c["surface"], fg=c["warning"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(warn,
                 text="Loss of this key makes all encrypted files permanently unrecoverable.\n"
                      "Back it up to a secure, separate location immediately.",
                 bg=c["surface"], fg=c["warning"],
                 font=("Segoe UI", 8), wraplength=330, justify="left").pack(anchor="w", pady=(4, 0))

        btn_row = tk.Frame(outer, bg=c["bg"])
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Cancel", style="Secondary.TButton",
                   command=self.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(btn_row, text="Generate & Save", style="Accent.TButton",
                   command=self._confirm).pack(side="right")

    def _browse_location(self):
        chosen = filedialog.askdirectory(title="Select Key Save Location",
                                          initialdir=self._loc_var.get())
        if chosen:
            self._loc_var.set(chosen)

    def _confirm(self):
        name = self._name_var.get().strip()
        if not name:
            messagebox.showerror("Invalid Name", "Key file name cannot be empty.", parent=self)
            return
        if not name.endswith(KEY_EXTENSION):
            name = name + KEY_EXTENSION
        loc = pathlib.Path(self._loc_var.get().strip()).resolve()
        if not loc.is_dir():
            messagebox.showerror("Invalid Location",
                                  "The save location is not a valid directory.", parent=self)
            return
        key_path = loc / name
        if key_path.exists():
            if not messagebox.askyesno(
                    "File Exists",
                    f"A key already exists at:\n{key_path}\n\n"
                    "Overwriting will make files encrypted with the old key inaccessible.\n"
                    "Continue?", parent=self):
                return
        try:
            key_material = self._engine.generate_key()
            self._engine.save_key(key_material, key_path)
            key_material = None
            self.result_key_path = key_path
            self.destroy()
        except Exception:
            key_material = None
            messagebox.showerror("Error", "Key generation failed. Check folder permissions.",
                                  parent=self)


class KeySearchDialog(tk.Toplevel):

    def __init__(self, parent, enc_path: pathlib.Path, engine: CryptographicEngine,
                 family_folder: pathlib.Path):
        super().__init__(parent)
        self.title("Find Key")
        self.resizable(True, False)
        self.grab_set()
        self.result_key_path = None
        self._engine = engine
        self._enc_path = enc_path
        self._family_folder = family_folder
        self._colors = parent._colors
        self.configure(bg=self._colors["bg"])
        self._build()
        self.transient(parent)
        self.wait_visibility()
        self.focus_set()
        self._run_search()

    def _build(self):
        c = self._colors
        outer = tk.Frame(self, bg=c["bg"], padx=20, pady=18)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text=f"Key Search: {self._enc_path.name}",
                 bg=c["bg"], fg=c["fg"], font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(outer, text="Scanning for compatible key files...",
                 bg=c["bg"], fg=c["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 10))

        list_outer = tk.Frame(outer, bg=c["surface"])
        list_outer.pack(fill="x", pady=(0, 10))
        cols = ("key_name", "location")
        self._key_tree = ttk.Treeview(list_outer, columns=cols, show="headings",
                                       selectmode="browse", height=8)
        self._key_tree.heading("key_name", text="Key File")
        self._key_tree.heading("location", text="Location")
        self._key_tree.column("key_name", width=160)
        self._key_tree.column("location", width=280)
        ks = ttk.Scrollbar(list_outer, orient="vertical", command=self._key_tree.yview)
        self._key_tree.configure(yscrollcommand=ks.set)
        self._key_tree.pack(side="left", fill="x", expand=True)
        ks.pack(side="right", fill="y")

        self._search_var = tk.StringVar()
        search_row = tk.Frame(outer, bg=c["bg"])
        search_row.pack(fill="x", pady=(0, 10))
        tk.Label(search_row, text="Search more locations:", bg=c["bg"], fg=c["muted"],
                 font=("Segoe UI", 8)).pack(side="left", padx=(0, 6))
        ttk.Entry(search_row, textvariable=self._search_var, width=24).pack(side="left",
                                                                              expand=True, fill="x")
        ttk.Button(search_row, text="Browse", style="Secondary.TButton",
                   command=self._browse_search_path).pack(side="right", padx=(6, 0))
        ttk.Button(search_row, text="Search", style="Secondary.TButton",
                   command=self._search_additional).pack(side="right", padx=(4, 0))

        btn_row = tk.Frame(outer, bg=c["bg"])
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Cancel", style="Secondary.TButton",
                   command=self.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(btn_row, text="Use Selected Key", style="Accent.TButton",
                   command=self._confirm).pack(side="right")

    def _run_search(self):
        roots = [self._family_folder, self._enc_path.parent]
        home = pathlib.Path.home()
        if home not in roots:
            roots.append(home)
        candidates = self._engine.find_candidate_keys(self._enc_path, roots)
        self._populate_results(candidates)

    def _populate_results(self, candidates: list[pathlib.Path]):
        for iid in self._key_tree.get_children():
            self._key_tree.delete(iid)
        for kf in candidates:
            self._key_tree.insert("", "end", iid=str(kf),
                                   values=(kf.name, str(kf.parent)))

    def _browse_search_path(self):
        chosen = filedialog.askdirectory(title="Select folder to search for keys",
                                          initialdir=str(self._family_folder))
        if chosen:
            self._search_var.set(chosen)

    def _search_additional(self):
        raw = self._search_var.get().strip()
        if not raw:
            return
        extra = pathlib.Path(raw).resolve()
        existing = {self._family_folder, self._enc_path.parent, pathlib.Path.home()}
        candidates = self._engine.find_candidate_keys(self._enc_path,
                                                       list(existing) + [extra])
        self._populate_results(candidates)

    def _confirm(self):
        sel = self._key_tree.selection()
        if not sel:
            messagebox.showerror("No Selection", "Select a key from the list.", parent=self)
            return
        self.result_key_path = pathlib.Path(sel[0])
        self.destroy()


class ContextMenu(tk.Menu):

    def __init__(self, parent, tree: ttk.Treeview, tree_type: str, app):
        super().__init__(parent, tearoff=0,
                         bg=app._colors["surface"],
                         fg=app._colors["fg"],
                         activebackground=app._colors["accent"],
                         activeforeground="#ffffff",
                         font=("Segoe UI", 9),
                         relief="flat",
                         borderwidth=1)
        self._tree = tree
        self._tree_type = tree_type
        self._app = app
        tree.bind("<Button-3>", self._show)
        if sys.platform == "darwin":
            tree.bind("<Button-2>", self._show)

    def _show(self, event):
        row = self._tree.identify_row(event.y)
        if not row:
            return
        current = list(self._tree.selection())
        if row not in current:
            self._tree.selection_set(row)

        self.delete(0, "end")

        if self._tree_type == "plain":
            self.add_command(label="Encrypt Selected",
                             command=self._app._initiate_encrypt)
            self.add_separator()
            self.add_command(label="Properties",
                             command=lambda: self._show_properties(row))
            self.add_separator()
            self.add_command(label="Remove from list",
                             command=lambda: self._remove_from_list(row))
            self.add_command(label="Delete file",
                             command=lambda: self._delete_file(row))

        elif self._tree_type == "enc":
            self.add_command(label="Decrypt Selected",
                             command=self._app._initiate_decrypt)
            self.add_command(label="Find Key",
                             command=lambda: self._find_key(row))
            self.add_separator()
            self.add_command(label="Properties",
                             command=lambda: self._show_properties(row))
            self.add_separator()
            self.add_command(label="Remove from list",
                             command=lambda: self._remove_from_list(row))
            self.add_command(label="Delete file",
                             command=lambda: self._delete_file(row))

        elif self._tree_type == "keys":
            self.add_command(label="Use for Encryption",
                             command=lambda: self._use_for_encrypt(row))
            self.add_command(label="Use for Decryption",
                             command=lambda: self._use_for_decrypt(row))
            self.add_separator()
            self.add_command(label="Properties",
                             command=lambda: self._show_properties(row))
            self.add_separator()
            self.add_command(label="Delete key",
                             command=lambda: self._delete_file(row))

        try:
            self.tk_popup(event.x_root, event.y_root)
        finally:
            self.grab_release()

    def _show_properties(self, iid: str):
        path = pathlib.Path(iid)
        c = self._app._colors
        if not path.exists():
            messagebox.showerror("Not Found", "File no longer exists.")
            return
        s = path.stat()
        size_b = s.st_size
        size_str = (f"{size_b} bytes" if size_b < 1024
                    else f"{size_b/1024:.1f} KB" if size_b < 1024**2
                    else f"{size_b/1024**2:.2f} MB")
        import datetime
        mtime = datetime.datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        info = (f"Name:     {path.name}\n"
                f"Location: {path.parent}\n"
                f"Size:     {size_str}\n"
                f"Modified: {mtime}\n"
                f"Readable: {'Yes' if os.access(path, os.R_OK) else 'No'}\n"
                f"Writable: {'Yes' if os.access(path, os.W_OK) else 'No'}")
        win = tk.Toplevel(self._app)
        win.title("Properties")
        win.resizable(False, False)
        win.configure(bg=c["bg"])
        win.grab_set()
        win.transient(self._app)
        f = tk.Frame(win, bg=c["bg"], padx=20, pady=18)
        f.pack()
        tk.Label(f, text=path.name, bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        tk.Label(f, text=info, bg=c["bg"], fg=c["muted"],
                 font=("Segoe UI", 9), justify="left").pack(anchor="w")
        ttk.Button(f, text="Close", style="Secondary.TButton",
                   command=win.destroy).pack(anchor="e", pady=(14, 0))

    def _remove_from_list(self, iid: str):
        self._tree.delete(iid)

    def _delete_file(self, iid: str):
        path = pathlib.Path(iid)
        if not messagebox.askyesno("Delete File",
                                    f"Permanently delete:\n{path.name}\n\nThis cannot be undone."):
            return
        try:
            self._app.engine.safe_delete(path)
            self._tree.delete(iid)
            self._app._append_log(f"Deleted: {path.name}")
            self._app._refresh_file_list()
        except Exception:
            messagebox.showerror("Error", "Could not delete the file.")

    def _find_key(self, iid: str):
        enc_path = pathlib.Path(iid)
        dialog = KeySearchDialog(self._app, enc_path, self._app.engine,
                                  self._app.family_folder)
        self._app.wait_window(dialog)
        if dialog.result_key_path:
            self._app.dec_key_var.set(str(dialog.result_key_path))
            self._app._append_log(f"Key selected: {dialog.result_key_path.name}")

    def _use_for_encrypt(self, iid: str):
        self._app.enc_key_var.set(iid)

    def _use_for_decrypt(self, iid: str):
        self._app.dec_key_var.set(iid)


class MemocryApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.resizable(True, True)

        self.engine = CryptographicEngine()
        self.family_folder = pathlib.Path.cwd()
        self.validator = PathValidator(self.family_folder)
        self.scanner = FamilyFolderScanner(self.family_folder)
        self.operation_in_progress = False
        self._session_log: list[str] = []
        self._enc_manual_files: list[pathlib.Path] = []
        self._dec_manual_files: list[pathlib.Path] = []
        self._active_result_queue: queue.Queue | None = None
        self._active_progress_queue: queue.Queue | None = None
        self._pending_post_action = None

        self._apply_theme()
        self._build_layout()
        self._auto_size_window()
        self._refresh_file_list()
        self._poll_operation_queue()

    def _auto_size_window(self):
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        w = min(max(self.winfo_reqwidth() + 80, 1100), screen_w - 60)
        h = min(max(self.winfo_reqheight() + 80, 760), screen_h - 60)
        x = (screen_w - w) // 2
        y = (screen_h - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(960, 680)

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        bg = "#1e1e2e"
        surface = "#2a2a3e"
        accent = "#7c6af7"
        accent_hover = "#9d8fff"
        fg = "#cdd6f4"
        muted = "#6c7086"
        success = "#a6e3a1"
        danger = "#f38ba8"
        warning = "#fab387"

        self.configure(bg=bg)
        self._colors = {
            "bg": bg, "surface": surface, "accent": accent,
            "accent_hover": accent_hover, "fg": fg, "muted": muted,
            "success": success, "danger": danger, "warning": warning,
        }

        style.configure(".", background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure("TFrame", background=bg)
        style.configure("Surface.TFrame", background=surface)
        style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=bg, foreground=muted, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=bg, foreground=fg,
                        font=("Segoe UI", 16, "bold"))
        style.configure("Status.TLabel", background=surface, foreground=muted,
                        font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground=surface, foreground=fg,
                        insertcolor=fg, borderwidth=1, relief="flat")
        style.map("TEntry", fieldbackground=[("focus", "#3a3a52")])
        style.configure("Treeview", background=surface, foreground=fg,
                        fieldbackground=surface, rowheight=24, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#3a3a52", foreground=accent,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", accent)],
                  foreground=[("selected", "#ffffff")])
        style.configure("Accent.TButton", background=accent, foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), relief="flat", padding=(12, 7))
        style.map("Accent.TButton",
                  background=[("active", accent_hover), ("disabled", muted)],
                  foreground=[("disabled", "#888888")])
        style.configure("Secondary.TButton", background=surface, foreground=fg,
                        font=("Segoe UI", 9), relief="flat", padding=(9, 6))
        style.map("Secondary.TButton", background=[("active", "#3a3a52")])
        style.configure("Danger.TButton", background=danger, foreground="#1e1e2e",
                        font=("Segoe UI", 9, "bold"), relief="flat", padding=(9, 6))
        style.map("Danger.TButton", background=[("active", "#ff8fa8")])
        style.configure("Success.TButton", background=success, foreground="#1e1e2e",
                        font=("Segoe UI", 10, "bold"), relief="flat", padding=(12, 7))
        style.map("Success.TButton", background=[("active", "#c3f0be")])
        style.configure("TProgressbar", troughcolor=surface, background=accent,
                        thickness=5, borderwidth=0)
        style.configure("TSeparator", background="#3a3a52")

    def _build_layout(self):
        c = self._colors

        self._build_top_bar()

        ttk.Separator(self, orient="horizontal").pack(fill="x")

        header = tk.Frame(self, bg=c["bg"], padx=20, pady=8)
        header.pack(fill="x")
        tk.Label(header, text="memocry", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 16, "bold")).pack(side="left")

        folder_frame = tk.Frame(header, bg=c["bg"])
        folder_frame.pack(side="right")
        tk.Label(folder_frame, text="Family Folder:", bg=c["bg"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))
        self.folder_var = tk.StringVar(value=str(self.family_folder))
        ttk.Entry(folder_frame, textvariable=self.folder_var, width=32).pack(side="left",
                                                                               padx=(0, 4))
        ttk.Button(folder_frame, text="Browse", style="Secondary.TButton",
                   command=self._browse_folder).pack(side="left")
        ttk.Button(folder_frame, text="Add Folder", style="Secondary.TButton",
                   command=self._add_folder_to_encrypt).pack(side="left", padx=(4, 0))
        ttk.Button(folder_frame, text="Set", style="Secondary.TButton",
                   command=self._set_family_folder).pack(side="left", padx=(4, 0))

        ttk.Separator(self, orient="horizontal").pack(fill="x")

        content = tk.Frame(self, bg=c["bg"])
        content.pack(fill="both", expand=True, padx=16, pady=10)

        left = tk.Frame(content, bg=c["bg"])
        left.pack(side="left", fill="both", expand=True)

        right = tk.Frame(content, bg=c["bg"], padx=12)
        right.pack(side="right", fill="y")

        self._build_left_panel(left, c)
        self._build_right_panel(right, c)

        ttk.Separator(self, orient="horizontal").pack(fill="x")
        status_bar = tk.Frame(self, bg=c["surface"], padx=16, pady=6)
        status_bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(status_bar, textvariable=self.status_var, bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(side="left")
        self.progress_var = tk.DoubleVar(value=0)
        ttk.Progressbar(status_bar, variable=self.progress_var,
                        maximum=100, length=180, style="TProgressbar").pack(side="right")

    def _build_top_bar(self):
        c = self._colors
        bar = tk.Frame(self, bg=c["surface"], padx=14, pady=7)
        bar.pack(fill="x")

        tk.Label(bar, text="Session:", bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 12))

        toggles = [
            ("Delete source after encrypt", "_toggle_delete_after_encrypt"),
            ("Delete .enc after decrypt", "_toggle_delete_after_decrypt"),
            ("Delete key after encrypt", "_toggle_delete_key_after_encrypt"),
            ("Delete key after decrypt", "_toggle_delete_key_after_decrypt"),
            ("Extra warnings", "_toggle_warnings"),
        ]
        for label, attr in toggles:
            t = ToggleButton(bar, label, c["surface"], c)
            t.pack(side="left", padx=(0, 18))
            setattr(self, attr, t)

        tk.Frame(bar, bg=c["surface"], width=1).pack(side="left", fill="y", padx=(8, 12))

        tk.Label(bar, text="Log", bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 6))
        self._log_open = False
        self._log_btn = ttk.Button(bar, text="Show", style="Secondary.TButton",
                                    command=self._toggle_log_panel)
        self._log_btn.pack(side="left")

    def _build_left_panel(self, parent, c):
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.columnconfigure(2, weight=1)
        parent.rowconfigure(1, weight=1)

        plain_hdr = tk.Frame(parent, bg=c["bg"])
        plain_hdr.grid(row=0, column=0, sticky="ew", pady=(0, 4), padx=(0, 6))
        tk.Label(plain_hdr, text="Plain Files", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(plain_hdr, text="  Ctrl/Shift+click", bg=c["bg"], fg=c["muted"],
                 font=("Segoe UI", 7)).pack(side="left")

        enc_hdr = tk.Frame(parent, bg=c["bg"])
        enc_hdr.grid(row=0, column=1, sticky="ew", pady=(0, 4), padx=(0, 6))
        tk.Label(enc_hdr, text="Encrypted Files", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(enc_hdr, text="  Ctrl/Shift+click", bg=c["bg"], fg=c["muted"],
                 font=("Segoe UI", 7)).pack(side="left")
        ttk.Button(enc_hdr, text="Refresh", style="Secondary.TButton",
                   command=self._refresh_file_list).pack(side="right")

        key_hdr = tk.Frame(parent, bg=c["bg"])
        key_hdr.grid(row=0, column=2, sticky="ew", pady=(0, 4))
        tk.Label(key_hdr, text="Detected Keys", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 10, "bold")).pack(side="left")

        plain_outer = tk.Frame(parent, bg=c["surface"])
        plain_outer.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        plain_cols = ("name", "size")
        self.plain_tree = ttk.Treeview(plain_outer, columns=plain_cols,
                                        show="headings", selectmode="extended")
        self.plain_tree.heading("name", text="File")
        self.plain_tree.heading("size", text="Size")
        self.plain_tree.column("name", width=200, minwidth=120)
        self.plain_tree.column("size", width=65, anchor="e")
        ps = ttk.Scrollbar(plain_outer, orient="vertical", command=self.plain_tree.yview)
        self.plain_tree.configure(yscrollcommand=ps.set)
        self.plain_tree.pack(side="left", fill="both", expand=True)
        ps.pack(side="right", fill="y")
        ContextMenu(self, self.plain_tree, "plain", self)

        enc_outer = tk.Frame(parent, bg=c["surface"])
        enc_outer.grid(row=1, column=1, sticky="nsew", padx=(0, 6))
        enc_cols = ("file", "key_status", "size")
        self.file_tree = ttk.Treeview(enc_outer, columns=enc_cols,
                                       show="headings", selectmode="extended")
        self.file_tree.heading("file", text="File")
        self.file_tree.heading("key_status", text="Key")
        self.file_tree.heading("size", text="Size")
        self.file_tree.column("file", width=200, minwidth=120)
        self.file_tree.column("key_status", width=55, anchor="center")
        self.file_tree.column("size", width=65, anchor="e")
        es = ttk.Scrollbar(enc_outer, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=es.set)
        self.file_tree.pack(side="left", fill="both", expand=True)
        es.pack(side="right", fill="y")
        self.file_tree.bind("<<TreeviewSelect>>", self._on_enc_tree_select)
        ContextMenu(self, self.file_tree, "enc", self)

        key_outer = tk.Frame(parent, bg=c["surface"])
        key_outer.grid(row=1, column=2, sticky="nsew")
        key_cols = ("key_name", "location")
        self.key_tree = ttk.Treeview(key_outer, columns=key_cols,
                                      show="headings", selectmode="browse")
        self.key_tree.heading("key_name", text="Key File")
        self.key_tree.heading("location", text="Location")
        self.key_tree.column("key_name", width=130, minwidth=80)
        self.key_tree.column("location", width=120, minwidth=80)
        ks2 = ttk.Scrollbar(key_outer, orient="vertical", command=self.key_tree.yview)
        self.key_tree.configure(yscrollcommand=ks2.set)
        self.key_tree.pack(side="left", fill="both", expand=True)
        ks2.pack(side="right", fill="y")
        ContextMenu(self, self.key_tree, "keys", self)

        self._log_panel_frame = tk.Frame(parent, bg=c["surface"])
        self._log_panel_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        log_hdr = tk.Frame(self._log_panel_frame, bg=c["surface"], padx=6, pady=4)
        log_hdr.pack(fill="x")
        tk.Label(log_hdr, text="Session Log", bg=c["surface"], fg=c["fg"],
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Button(log_hdr, text="Clear", style="Secondary.TButton",
                   command=self._clear_log).pack(side="right")
        self.log_text = tk.Text(self._log_panel_frame, height=4, state="disabled",
                                bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8),
                                relief="flat", borderwidth=0, wrap="word",
                                insertbackground=c["fg"], padx=6, pady=4)
        log_s = ttk.Scrollbar(self._log_panel_frame, orient="vertical",
                               command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_s.set)
        self.log_text.pack(side="left", fill="x", expand=True)
        log_s.pack(side="right", fill="y")
        self._log_panel_frame.grid_remove()

    def _build_right_panel(self, parent, c):
        tk.Label(parent, text="Operations", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))

        enc_card = tk.Frame(parent, bg=c["surface"], padx=14, pady=12)
        enc_card.pack(fill="x", pady=(0, 8))
        tk.Label(enc_card, text="ENCRYPT", bg=c["surface"], fg=c["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Frame(enc_card, bg="#3a3a52", height=1).pack(fill="x", pady=(5, 8))
        tk.Label(enc_card, text="Key file:", bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w")
        enc_key_row = tk.Frame(enc_card, bg=c["surface"])
        enc_key_row.pack(fill="x", pady=(2, 6))
        self.enc_key_var = tk.StringVar()
        ttk.Entry(enc_key_row, textvariable=self.enc_key_var, width=15).pack(side="left",
                                                                               expand=True, fill="x")
        ttk.Button(enc_key_row, text="...", style="Secondary.TButton", width=3,
                   command=self._browse_enc_key).pack(side="right", padx=(4, 0))
        tk.Label(enc_card, text="Select rows or browse files",
                 bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 4))
        ttk.Button(enc_card, text="Browse Files", style="Secondary.TButton",
                   command=self._browse_plain_files_manual).pack(fill="x", pady=(0, 4))
        ttk.Button(enc_card, text="Encrypt Selected", style="Accent.TButton",
                   command=self._initiate_encrypt).pack(fill="x")

        dec_card = tk.Frame(parent, bg=c["surface"], padx=14, pady=12)
        dec_card.pack(fill="x", pady=(0, 8))
        tk.Label(dec_card, text="DECRYPT", bg=c["surface"], fg=c["success"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Frame(dec_card, bg="#3a3a52", height=1).pack(fill="x", pady=(5, 8))
        tk.Label(dec_card, text="Key file:", bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w")
        dec_key_row = tk.Frame(dec_card, bg=c["surface"])
        dec_key_row.pack(fill="x", pady=(2, 6))
        self.dec_key_var = tk.StringVar()
        ttk.Entry(dec_key_row, textvariable=self.dec_key_var, width=15).pack(side="left",
                                                                               expand=True, fill="x")
        ttk.Button(dec_key_row, text="...", style="Secondary.TButton", width=3,
                   command=self._browse_dec_key).pack(side="right", padx=(4, 0))
        tk.Label(dec_card, text="Select rows or browse files",
                 bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 4))
        ttk.Button(dec_card, text="Browse Files", style="Secondary.TButton",
                   command=self._browse_enc_files_manual).pack(fill="x", pady=(0, 4))
        ttk.Button(dec_card, text="Decrypt Selected", style="Success.TButton",
                   command=self._initiate_decrypt).pack(fill="x")

        key_card = tk.Frame(parent, bg=c["surface"], padx=14, pady=12)
        key_card.pack(fill="x", pady=(0, 8))
        tk.Label(key_card, text="KEY MANAGEMENT", bg=c["surface"], fg=c["warning"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Frame(key_card, bg="#3a3a52", height=1).pack(fill="x", pady=(5, 8))
        ttk.Button(key_card, text="Generate & Save Key", style="Secondary.TButton",
                   command=self._generate_standalone_key).pack(fill="x", pady=(0, 6))
        ttk.Button(key_card, text="Delete All Detected Keys", style="Danger.TButton",
                   command=self._delete_all_keys).pack(fill="x", pady=(0, 8))
        tk.Label(key_card,
                 text="Loss of a key makes encrypted files\npermanently unrecoverable.\nBack up to a secure location.",
                 bg=c["surface"], fg=c["warning"],
                 font=("Segoe UI", 8), justify="left").pack(anchor="w")

    def _toggle_log_panel(self):
        self._log_open = not self._log_open
        if self._log_open:
            self._log_panel_frame.grid()
            self._log_btn.configure(text="Hide")
        else:
            self._log_panel_frame.grid_remove()
            self._log_btn.configure(text="Show")

    def _set_status(self, message: str, _color_key: str = "muted"):
        self.status_var.set(message)

    def _append_log(self, message: str):
        self._session_log.append(message)
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self):
        self._session_log.clear()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _refresh_file_list(self):
        self.file_tree.delete(*self.file_tree.get_children())
        self.plain_tree.delete(*self.plain_tree.get_children())
        self.key_tree.delete(*self.key_tree.get_children())

        for item in self.scanner.discover_encrypted_files():
            enc_file = item["encrypted_file"]
            size_kb = item["size_bytes"] / 1024
            size_lbl = f"{size_kb:.1f}K" if size_kb < 1024 else f"{size_kb/1024:.1f}M"
            tag = "keyed" if item["key_status"] == "Found" else "unkeyed"
            self.file_tree.insert("", "end", iid=str(enc_file),
                                   values=(item["display_name"], item["key_status"], size_lbl),
                                   tags=(tag,))
        self.file_tree.tag_configure("keyed", foreground=self._colors["success"])
        self.file_tree.tag_configure("unkeyed", foreground=self._colors["danger"])

        for plain_file in self.scanner.discover_plain_files():
            size_kb = plain_file.stat().st_size / 1024
            size_lbl = f"{size_kb:.1f}K" if size_kb < 1024 else f"{size_kb/1024:.1f}M"
            try:
                rel = plain_file.relative_to(self.family_folder)
            except ValueError:
                rel = plain_file
            self.plain_tree.insert("", "end", iid=str(plain_file),
                                    values=(str(rel), size_lbl))

        for kf in self.scanner.discover_key_files():
            self.key_tree.insert("", "end", iid=str(kf),
                                  values=(kf.name, str(kf.parent)))

        self._set_status(f"Scanned: {self.family_folder}")

    def _on_enc_tree_select(self, _event):
        selected = self.file_tree.selection()
        if not selected:
            return
        last = pathlib.Path(selected[-1])
        if not self.dec_key_var.get().strip():
            for item in self.scanner.discover_encrypted_files():
                if item["encrypted_file"] == last and item["paired_key"]:
                    self.dec_key_var.set(str(item["paired_key"]))
                    break

    def _browse_folder(self):
        chosen = filedialog.askdirectory(title="Select Family Folder",
                                          initialdir=str(self.family_folder))
        if chosen:
            self.folder_var.set(chosen)

    def _add_folder_to_encrypt(self):
        chosen = filedialog.askdirectory(title="Select Folder",
                                          initialdir=str(self.family_folder))
        if not chosen:
            return
        folder = pathlib.Path(chosen).resolve()

        choice = self._ask_folder_mode(folder.name)
        if choice is None:
            return

        if choice == "zip":
            zip_out = folder.parent / (folder.name + ".zip")
            try:
                self.engine.zip_folder(folder, zip_out)
                if zip_out not in self._enc_manual_files:
                    self._enc_manual_files.append(zip_out)
                self._append_log(f"Folder zipped: {zip_out.name} queued for encryption.")
            except Exception:
                messagebox.showerror("Zip Failed", "Could not create zip archive.")
        else:
            added = 0
            for f in sorted(folder.rglob("*")):
                if f.is_file() and f.suffix != ENCRYPTED_EXTENSION and f.suffix != KEY_EXTENSION:
                    if f not in self._enc_manual_files:
                        self._enc_manual_files.append(f)
                        added += 1
            self._append_log(f"Folder added: {folder.name} ({added} file(s) queued).")

    def _ask_folder_mode(self, folder_name: str):
        win = tk.Toplevel(self)
        win.title("Folder Encryption Mode")
        win.resizable(False, False)
        win.grab_set()
        win.transient(self)
        win.configure(bg=self._colors["bg"])
        result = [None]

        c = self._colors
        f = tk.Frame(win, bg=c["bg"], padx=22, pady=18)
        f.pack()
        tk.Label(f, text=f"How to encrypt folder: {folder_name}",
                 bg=c["bg"], fg=c["fg"], font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(f, text="Choose how the folder contents should be encrypted:",
                 bg=c["bg"], fg=c["muted"], font=("Segoe UI", 9)).pack(anchor="w", pady=(6, 12))

        def pick(val):
            result[0] = val
            win.destroy()

        ttk.Button(f, text="Encrypt each file individually",
                   style="Secondary.TButton",
                   command=lambda: pick("files")).pack(fill="x", pady=(0, 6))
        ttk.Button(f, text="Zip folder then encrypt the zip",
                   style="Accent.TButton",
                   command=lambda: pick("zip")).pack(fill="x", pady=(0, 6))
        ttk.Button(f, text="Cancel",
                   style="Secondary.TButton",
                   command=win.destroy).pack(fill="x")

        self.wait_window(win)
        return result[0]

    def _set_family_folder(self):
        raw = self.folder_var.get().strip()
        candidate = pathlib.Path(raw).resolve()
        if not candidate.is_dir():
            messagebox.showerror("Invalid Folder", "The specified path is not a valid directory.")
            return
        self.family_folder = candidate
        self.validator = PathValidator(self.family_folder)
        self.scanner = FamilyFolderScanner(self.family_folder)
        self._refresh_file_list()

    def _browse_enc_key(self):
        chosen = filedialog.askopenfilename(
            title="Select Key File for Encryption",
            filetypes=[("Key Files", f"*{KEY_EXTENSION}"), ("All Files", "*.*")],
            initialdir=str(self.family_folder))
        if chosen:
            self.enc_key_var.set(chosen)

    def _browse_dec_key(self):
        chosen = filedialog.askopenfilename(
            title="Select Key File for Decryption",
            filetypes=[("Key Files", f"*{KEY_EXTENSION}"), ("All Files", "*.*")],
            initialdir=str(self.family_folder))
        if chosen:
            self.dec_key_var.set(chosen)

    def _browse_plain_files_manual(self):
        chosen = filedialog.askopenfilenames(title="Select Files to Encrypt",
                                              initialdir=str(self.family_folder))
        if chosen:
            added = []
            for p in [pathlib.Path(x) for x in chosen]:
                if p not in self._enc_manual_files:
                    self._enc_manual_files.append(p)
                    added.append(p)
            self._append_log(f"Manual: {len(added)} file(s) queued for encryption.")

    def _browse_enc_files_manual(self):
        chosen = filedialog.askopenfilenames(
            title="Select Encrypted Files to Decrypt",
            filetypes=[("Encrypted Files", f"*{ENCRYPTED_EXTENSION}"), ("All Files", "*.*")],
            initialdir=str(self.family_folder))
        if chosen:
            added = []
            for p in [pathlib.Path(x) for x in chosen]:
                if p not in self._dec_manual_files:
                    self._dec_manual_files.append(p)
                    added.append(p)
            self._append_log(f"Manual: {len(added)} file(s) queued for decryption.")

    def _generate_standalone_key(self):
        dialog = KeySaveDialog(self, self.family_folder, self.engine)
        self.wait_window(dialog)
        if dialog.result_key_path:
            self._append_log(f"Key generated: {dialog.result_key_path.name}")
            self._refresh_file_list()
            messagebox.showinfo("Key Generated",
                                f"Key saved to:\n{dialog.result_key_path}\n\n"
                                "Back up this file immediately to a secure location.")

    def _delete_all_keys(self):
        key_files = self.scanner.discover_key_files()
        if not key_files:
            messagebox.showinfo("No Keys Found", "No key files detected in the family folder.")
            return
        names = "\n".join(f.name for f in key_files[:10])
        extra = f"\n... and {len(key_files) - 10} more" if len(key_files) > 10 else ""
        if not messagebox.askyesno(
                "Delete All Keys",
                f"Permanently delete {len(key_files)} key file(s):\n\n"
                f"{names}{extra}\n\n"
                "Encrypted files will become PERMANENTLY UNRECOVERABLE.\nAre you sure?"):
            return
        if not messagebox.askyesno("Final Confirmation",
                                    "This cannot be undone. Delete all detected keys now?"):
            return
        deleted = failed = 0
        for kf in key_files:
            try:
                self.engine.safe_delete(kf)
                self._append_log(f"Key deleted: {kf.name}")
                deleted += 1
            except Exception:
                self._append_log(f"Failed to delete key: {kf.name}")
                failed += 1
        self._refresh_file_list()
        if not failed:
            messagebox.showinfo("Keys Deleted", f"{deleted} key file(s) deleted.")
        else:
            messagebox.showwarning("Partial Deletion",
                                    f"{deleted} deleted, {failed} could not be deleted.")

    def _check_pre_encrypt_warnings(self, source_paths: list[pathlib.Path],
                                     active_key_path: pathlib.Path) -> bool:
        warnings = []

        self_files = [p for p in source_paths if p.resolve() == SELF_PATH]
        if self_files:
            warnings.append(
                "You are about to encrypt memocry.py itself.\n"
                "Encrypting the application file will make it unrunnable until decrypted.")

        own_key = [p for p in source_paths if p.resolve() == active_key_path.resolve()]
        if own_key:
            warnings.append(
                "You are about to encrypt the key file currently selected for this operation.\n"
                "This is almost always a mistake.")

        key_files = [p for p in source_paths
                     if p.suffix == KEY_EXTENSION and p.resolve() != active_key_path.resolve()]
        if key_files:
            names = ", ".join(p.name for p in key_files)
            warnings.append(
                f"Key file(s) are included in the selection:\n{names}\n\n"
                "Encrypting a key without a backup makes it permanently inaccessible.")

        system_files = [p for p in source_paths if is_system_file(p)]
        if system_files:
            names = ", ".join(p.name for p in system_files[:5])
            warnings.append(
                f"The following file(s) appear to be system files:\n{names}\n\n"
                "Encrypting system files may cause your operating system to malfunction.")

        in_use = [p for p in source_paths if is_file_in_use(p)]
        if in_use:
            names = ", ".join(p.name for p in in_use[:5])
            warnings.append(
                f"The following file(s) appear to be in use by another process:\n{names}\n\n"
                "Encrypting files that are currently open may cause data corruption.")

        if warnings:
            full = "\n\n".join(warnings) + "\n\nContinue anyway?"
            return messagebox.askyesno("Pre-flight Warning", full)
        return True

    def _resolve_encrypt_targets(self) -> list[pathlib.Path]:
        targets = []
        seen = set()
        for iid in self.plain_tree.selection():
            p = pathlib.Path(iid)
            if p not in seen:
                targets.append(p)
                seen.add(p)
        for p in self._enc_manual_files:
            if p not in seen:
                targets.append(p)
                seen.add(p)
        return targets

    def _resolve_decrypt_targets(self) -> list[pathlib.Path]:
        targets = []
        seen = set()
        for iid in self.file_tree.selection():
            p = pathlib.Path(iid)
            if p not in seen:
                targets.append(p)
                seen.add(p)
        for p in self._dec_manual_files:
            if p not in seen:
                targets.append(p)
                seen.add(p)
        return targets

    def _initiate_encrypt(self):
        if self.operation_in_progress:
            messagebox.showwarning("Busy", "An operation is already in progress.")
            return

        raw_key = self.enc_key_var.get().strip()
        if not raw_key:
            if messagebox.askyesno("No Key Selected",
                                    "No key selected.\n\nGenerate a new key now?"):
                dialog = KeySaveDialog(self, self.family_folder, self.engine)
                self.wait_window(dialog)
                if dialog.result_key_path:
                    self.enc_key_var.set(str(dialog.result_key_path))
                    self._append_log(f"Key generated: {dialog.result_key_path.name}")
                    self._refresh_file_list()
            raw_key = self.enc_key_var.get().strip()
            if not raw_key:
                return

        key_path = pathlib.Path(raw_key)
        targets = self._resolve_encrypt_targets()

        if not targets:
            messagebox.showerror("No Files Selected",
                                  "Select files from the Plain Files list or use Browse Files.")
            return

        if not self._check_pre_encrypt_warnings(targets, key_path):
            return

        if self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Confirm Encryption",
                    f"Encrypt {len(targets)} file(s) using:\n{key_path.name}\n\nProceed?"):
                return

        delete_source = self._toggle_delete_after_encrypt.value
        delete_key = self._toggle_delete_key_after_encrypt.value

        if delete_source and self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Delete Source",
                    f"'Delete source after encrypt' is ON.\n"
                    f"Original {len(targets)} file(s) will be deleted.\n\nContinue?"):
                return

        if delete_key and self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Delete Key",
                    f"'Delete key after encrypt' is ON.\n"
                    f"Key '{key_path.name}' will be deleted after encryption.\n\n"
                    "Encrypted files become UNRECOVERABLE without a backup.\n\nContinue?"):
                return

        validated_tasks = []
        for source_path in targets:
            try:
                validated_source = self.validator.validate_input_file(source_path)
                output_path = source_path.with_name(source_path.name + ENCRYPTED_EXTENSION)
                validated_output = self.validator.validate_output_path(output_path)
            except ValueError as ve:
                self._append_log(f"Skipped {source_path.name}: {ve}")
                continue
            validated_tasks.append((source_path.name, validated_source, validated_output))

        try:
            validated_key = self.validator.validate_key_file(key_path)
        except ValueError as ve:
            messagebox.showerror("Key Error", str(ve))
            return

        if not validated_tasks:
            messagebox.showerror("No Valid Files", "All selected files failed validation.")
            return

        sources_to_delete = [t[1] for t in validated_tasks] if delete_source else []

        def make_enc_task(vsrc, vout, vkey):
            def task():
                key_material = self.engine.load_key(vkey)
                try:
                    self.engine.encrypt_file(vsrc, key_material, vout)
                finally:
                    key_material = None
            return task

        batch = [(lbl, make_enc_task(vsrc, vout, validated_key))
                 for lbl, vsrc, vout in validated_tasks]
        self._enc_manual_files.clear()

        def post_encrypt():
            for src in sources_to_delete:
                try:
                    self.engine.safe_delete(src)
                    self._append_log(f"Source deleted: {src.name}")
                except Exception:
                    self._append_log(f"Could not delete source: {src.name}")
            if delete_key:
                try:
                    self.engine.safe_delete(validated_key)
                    self._append_log(f"Key deleted: {validated_key.name}")
                except Exception:
                    self._append_log(f"Could not delete key: {validated_key.name}")

        self._pending_post_action = post_encrypt
        self._run_batch(batch, f"Encrypting {len(batch)} file(s)...")

    def _initiate_decrypt(self):
        if self.operation_in_progress:
            messagebox.showwarning("Busy", "An operation is already in progress.")
            return

        raw_key = self.dec_key_var.get().strip()
        if not raw_key:
            messagebox.showerror("No Key Selected",
                                  "Select a key file using the Browse button next to Key file.")
            return

        key_path = pathlib.Path(raw_key)
        targets = self._resolve_decrypt_targets()

        if not targets:
            messagebox.showerror("No Files Selected",
                                  "Select files from the Encrypted Files list or use Browse Files.")
            return

        if self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Confirm Decryption",
                    f"Decrypt {len(targets)} file(s) using:\n{key_path.name}\n\nProceed?"):
                return

        delete_source = self._toggle_delete_after_decrypt.value
        delete_key = self._toggle_delete_key_after_decrypt.value

        if delete_source and self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Delete Encrypted Files",
                    f"'Delete .enc after decrypt' is ON.\n"
                    f"{len(targets)} encrypted file(s) will be deleted.\n\nContinue?"):
                return

        if delete_key and self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Delete Key",
                    f"'Delete key after decrypt' is ON.\n"
                    f"Key '{key_path.name}' will be deleted after decryption.\n\nContinue?"):
                return

        validated_tasks = []
        for enc_path in targets:
            try:
                validated_enc = self.validator.validate_input_file(enc_path)
                output_path = enc_path.parent / enc_path.stem
                validated_output = self.validator.validate_output_path(output_path)
            except ValueError as ve:
                self._append_log(f"Skipped {enc_path.name}: {ve}")
                continue
            validated_tasks.append((enc_path.name, validated_enc, validated_output))

        try:
            validated_key = self.validator.validate_key_file(key_path)
        except ValueError as ve:
            messagebox.showerror("Key Error", str(ve))
            return

        if not validated_tasks:
            messagebox.showerror("No Valid Files", "All selected files failed validation.")
            return

        sources_to_delete = [t[1] for t in validated_tasks] if delete_source else []

        def make_dec_task(venc, vout, vkey):
            def task():
                key_material = self.engine.load_key(vkey)
                try:
                    self.engine.decrypt_file(venc, key_material, vout)
                finally:
                    key_material = None
            return task

        batch = [(lbl, make_dec_task(venc, vout, validated_key))
                 for lbl, venc, vout in validated_tasks]
        self._dec_manual_files.clear()

        def post_decrypt():
            for src in sources_to_delete:
                try:
                    self.engine.safe_delete(src)
                    self._append_log(f"Encrypted file deleted: {src.name}")
                except Exception:
                    self._append_log(f"Could not delete: {src.name}")
            if delete_key:
                try:
                    self.engine.safe_delete(validated_key)
                    self._append_log(f"Key deleted: {validated_key.name}")
                except Exception:
                    self._append_log(f"Could not delete key: {validated_key.name}")

        self._pending_post_action = post_decrypt
        self._run_batch(batch, f"Decrypting {len(batch)} file(s)...")

    def _run_batch(self, tasks: list, status_message: str):
        self.operation_in_progress = True
        self.progress_var.set(0)
        self._set_status(status_message)
        result_queue = queue.Queue()
        progress_queue = queue.Queue()
        self._active_result_queue = result_queue
        self._active_progress_queue = progress_queue
        BatchOperationWorker(tasks, result_queue, progress_queue).start()

    def _poll_operation_queue(self):
        if self.operation_in_progress and self._active_progress_queue:
            try:
                while True:
                    msg = self._active_progress_queue.get_nowait()
                    if msg[0] == "progress":
                        _, label, completed, total, error = msg
                        pct = (completed / total) * 100 if total > 0 else 0
                        self.progress_var.set(pct)
                        if error:
                            self._append_log(f"FAILED  {label}")
                        else:
                            self._append_log(f"OK      {label}")
            except queue.Empty:
                pass

        if self.operation_in_progress and self._active_result_queue:
            try:
                msg_type, completed, total, errors = self._active_result_queue.get_nowait()
                if msg_type == "done":
                    self.operation_in_progress = False
                    self.progress_var.set(0)
                    self._active_result_queue = None
                    self._active_progress_queue = None

                    post = self._pending_post_action
                    self._pending_post_action = None
                    if post:
                        post()

                    self._refresh_file_list()
                    if not errors:
                        self._set_status(f"Completed: {completed}/{total} file(s).")
                        messagebox.showinfo("Complete",
                                             f"All {completed} file(s) processed successfully.")
                    else:
                        self._set_status(f"Completed with errors: {completed}/{total}.")
                        messagebox.showwarning(
                            "Partial Completion",
                            f"{completed} of {total} processed.\n"
                            f"{len(errors)} failed.\n\nCheck Session Log for details.")
            except queue.Empty:
                pass

        self.after(150, self._poll_operation_queue)


def main():
    app = MemocryApp()
    app.mainloop()


if __name__ == "__main__":
    main()

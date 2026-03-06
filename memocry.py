import sys
import os
import importlib
import threading
import queue
import pathlib
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
WINDOW_WIDTH = 980
WINDOW_HEIGHT = 680


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


class PathValidator:

    def __init__(self, family_folder: pathlib.Path):
        self.family_folder = family_folder.resolve()

    def validate_input_file(self, file_path: pathlib.Path) -> pathlib.Path:
        resolved = file_path.resolve()
        if not resolved.exists():
            raise ValueError(f"File does not exist: {resolved.name}")
        if not resolved.is_file():
            raise ValueError(f"Path is not a regular file: {resolved.name}")
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
        for enc_file in sorted(self.family_folder.glob(f"*{ENCRYPTED_EXTENSION}")):
            if not enc_file.is_file():
                continue
            stem = enc_file.stem
            candidate_key = self.family_folder / (stem + KEY_EXTENSION)
            default_key = self.family_folder / DEFAULT_KEY_NAME
            paired_key = None
            if candidate_key.is_file():
                paired_key = candidate_key
            elif default_key.is_file():
                paired_key = default_key
            size_bytes = enc_file.stat().st_size
            discovered.append({
                "encrypted_file": enc_file,
                "paired_key": paired_key,
                "display_name": enc_file.name,
                "key_status": "Found" if paired_key else "Missing",
                "size_bytes": size_bytes,
            })
        return discovered

    def discover_plain_files(self) -> list[pathlib.Path]:
        results = []
        if not self.family_folder.exists():
            return results
        for f in sorted(self.family_folder.iterdir()):
            if f.is_file() and f.suffix != ENCRYPTED_EXTENSION and f.suffix != KEY_EXTENSION:
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
        outer = ttk.Frame(self, style="TFrame", padding=20)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Generate New Key", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=(8, 14))

        ttk.Label(outer, text="Key file name:", style="Muted.TLabel").pack(anchor="w")
        self._name_var = tk.StringVar(value=DEFAULT_KEY_NAME)
        ttk.Entry(outer, textvariable=self._name_var, width=36).pack(fill="x", pady=(3, 10))

        ttk.Label(outer, text="Save location:", style="Muted.TLabel").pack(anchor="w")
        loc_row = ttk.Frame(outer, style="TFrame")
        loc_row.pack(fill="x", pady=(3, 10))
        self._loc_var = tk.StringVar(value=str(self._default_folder))
        ttk.Entry(loc_row, textvariable=self._loc_var, width=28).pack(side="left", expand=True, fill="x")
        ttk.Button(loc_row, text="Browse", style="Secondary.TButton",
                   command=self._browse_location).pack(side="right", padx=(6, 0))

        warn = ttk.Frame(outer, style="Surface.TFrame", padding=10)
        warn.pack(fill="x", pady=(0, 14))
        ttk.Label(warn, text="WARNING", foreground=c["warning"], background=c["surface"],
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Label(warn,
                  text="Loss of this key makes all files encrypted with it permanently unrecoverable.\n"
                       "Back it up immediately to a secure, separate location.",
                  background=c["surface"], foreground=c["warning"],
                  font=("Segoe UI", 8), wraplength=320, justify="left").pack(anchor="w", pady=(4, 0))

        btn_row = ttk.Frame(outer, style="TFrame")
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
            messagebox.showerror("Invalid Location", "The selected save location is not a valid directory.", parent=self)
            return
        key_path = loc / name
        if key_path.exists():
            overwrite = messagebox.askyesno(
                "File Exists",
                f"A key file already exists at:\n{key_path}\n\n"
                "Overwriting it will make any files encrypted with the old key inaccessible.\n"
                "Continue?",
                parent=self)
            if not overwrite:
                return
        try:
            key_material = self._engine.generate_key()
            self._engine.save_key(key_material, key_path)
            key_material = None
            self.result_key_path = key_path
            self.destroy()
        except Exception:
            key_material = None
            messagebox.showerror("Error", "Key generation failed. Check folder permissions.", parent=self)


class MemocryApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.resizable(True, True)
        self.minsize(800, 560)

        self.engine = CryptographicEngine()
        self.family_folder = pathlib.Path.cwd()
        self.validator = PathValidator(self.family_folder)
        self.scanner = FamilyFolderScanner(self.family_folder)
        self.operation_in_progress = False
        self._session_log: list[str] = []

        self._apply_theme()
        self._build_layout()
        self._refresh_file_list()
        self._poll_operation_queue()

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
        style.configure("Surface.TLabel", background=surface, foreground=fg)
        style.configure("Title.TLabel", background=bg, foreground=fg,
                        font=("Segoe UI", 18, "bold"))
        style.configure("Status.TLabel", background=surface, foreground=muted,
                        font=("Segoe UI", 9))
        style.configure("Log.TLabel", background=surface, foreground=muted,
                        font=("Segoe UI", 8))

        style.configure("TEntry", fieldbackground=surface, foreground=fg,
                        insertcolor=fg, borderwidth=1, relief="flat")
        style.map("TEntry", fieldbackground=[("focus", "#3a3a52")])

        style.configure("Treeview", background=surface, foreground=fg,
                        fieldbackground=surface, rowheight=26,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#3a3a52", foreground=accent,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", accent)],
                  foreground=[("selected", "#ffffff")])

        style.configure("Accent.TButton", background=accent, foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), relief="flat", padding=(12, 8))
        style.map("Accent.TButton",
                  background=[("active", accent_hover), ("disabled", muted)],
                  foreground=[("disabled", "#888888")])

        style.configure("Secondary.TButton", background=surface, foreground=fg,
                        font=("Segoe UI", 10), relief="flat", padding=(10, 7))
        style.map("Secondary.TButton",
                  background=[("active", "#3a3a52"), ("disabled", "#2a2a3e")])

        style.configure("Success.TButton", background=success, foreground="#1e1e2e",
                        font=("Segoe UI", 10, "bold"), relief="flat", padding=(12, 8))
        style.map("Success.TButton", background=[("active", "#c3f0be")])

        style.configure("TProgressbar", troughcolor=surface, background=accent,
                        thickness=6, borderwidth=0)

        style.configure("TSeparator", background="#3a3a52")

    def _build_layout(self):
        c = self._colors

        header = ttk.Frame(self, style="TFrame", padding=(20, 14, 20, 8))
        header.pack(fill="x")

        title_row = ttk.Frame(header, style="TFrame")
        title_row.pack(fill="x")

        ttk.Label(title_row, text="memocry", style="Title.TLabel").pack(side="left")

        folder_frame = ttk.Frame(title_row, style="TFrame")
        folder_frame.pack(side="right")

        ttk.Label(folder_frame, text="Family Folder:", style="Muted.TLabel").pack(side="left", padx=(0, 6))
        self.folder_var = tk.StringVar(value=str(self.family_folder))
        ttk.Entry(folder_frame, textvariable=self.folder_var, width=32).pack(side="left", padx=(0, 4))
        ttk.Button(folder_frame, text="Browse", style="Secondary.TButton",
                   command=self._browse_folder).pack(side="left")
        ttk.Button(folder_frame, text="Set", style="Secondary.TButton",
                   command=self._set_family_folder).pack(side="left", padx=(4, 0))

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=20, pady=(4, 0))

        main_pane = ttk.Frame(self, style="TFrame", padding=(20, 12, 20, 0))
        main_pane.pack(fill="both", expand=True)

        left_panel = ttk.Frame(main_pane, style="TFrame")
        left_panel.pack(side="left", fill="both", expand=True)

        enc_list_header = ttk.Frame(left_panel, style="TFrame")
        enc_list_header.pack(fill="x", pady=(0, 6))
        ttk.Label(enc_list_header, text="Encrypted Files",
                  font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(enc_list_header, text="(Ctrl+click to multi-select)",
                  style="Muted.TLabel").pack(side="left", padx=(8, 0))
        ttk.Button(enc_list_header, text="Refresh", style="Secondary.TButton",
                   command=self._refresh_file_list).pack(side="right")

        enc_tree_frame = ttk.Frame(left_panel, style="Surface.TFrame")
        enc_tree_frame.pack(fill="both", expand=True)

        enc_cols = ("file", "key_status", "size")
        self.file_tree = ttk.Treeview(enc_tree_frame, columns=enc_cols, show="headings",
                                       selectmode="extended")
        self.file_tree.heading("file", text="File Name")
        self.file_tree.heading("key_status", text="Key")
        self.file_tree.heading("size", text="Size")
        self.file_tree.column("file", width=260, minwidth=160)
        self.file_tree.column("key_status", width=70, anchor="center")
        self.file_tree.column("size", width=80, anchor="e")

        enc_scroll = ttk.Scrollbar(enc_tree_frame, orient="vertical",
                                    command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=enc_scroll.set)
        self.file_tree.pack(side="left", fill="both", expand=True)
        enc_scroll.pack(side="right", fill="y")
        self.file_tree.bind("<<TreeviewSelect>>", self._on_enc_tree_select)

        plain_list_header = ttk.Frame(left_panel, style="TFrame")
        plain_list_header.pack(fill="x", pady=(10, 6))
        ttk.Label(plain_list_header, text="Plain Files",
                  font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(plain_list_header, text="(Ctrl+click to multi-select)",
                  style="Muted.TLabel").pack(side="left", padx=(8, 0))

        plain_tree_frame = ttk.Frame(left_panel, style="Surface.TFrame")
        plain_tree_frame.pack(fill="x")

        plain_cols = ("plain_file", "plain_size")
        self.plain_tree = ttk.Treeview(plain_tree_frame, columns=plain_cols, show="headings",
                                        selectmode="extended", height=5)
        self.plain_tree.heading("plain_file", text="File Name")
        self.plain_tree.heading("plain_size", text="Size")
        self.plain_tree.column("plain_file", width=310, minwidth=160)
        self.plain_tree.column("plain_size", width=80, anchor="e")

        plain_scroll = ttk.Scrollbar(plain_tree_frame, orient="vertical",
                                      command=self.plain_tree.yview)
        self.plain_tree.configure(yscrollcommand=plain_scroll.set)
        self.plain_tree.pack(side="left", fill="x", expand=True)
        plain_scroll.pack(side="right", fill="y")

        log_header = ttk.Frame(left_panel, style="TFrame")
        log_header.pack(fill="x", pady=(10, 4))
        ttk.Label(log_header, text="Session Log",
                  font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(log_header, text="Clear", style="Secondary.TButton",
                   command=self._clear_log).pack(side="right")

        log_frame = ttk.Frame(left_panel, style="Surface.TFrame")
        log_frame.pack(fill="x")

        self.log_text = tk.Text(log_frame, height=4, state="disabled",
                                bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8),
                                relief="flat", borderwidth=0, wrap="word",
                                insertbackground=c["fg"])
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical",
                                    command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="x", expand=True)
        log_scroll.pack(side="right", fill="y")

        right_panel = ttk.Frame(main_pane, style="TFrame", padding=(18, 0, 0, 0))
        right_panel.pack(side="right", fill="y")
        right_panel.configure(width=230)

        ttk.Label(right_panel, text="Operations",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 10))

        enc_section = ttk.Frame(right_panel, style="Surface.TFrame", padding=14)
        enc_section.pack(fill="x", pady=(0, 10))

        ttk.Label(enc_section, text="ENCRYPT", foreground=c["accent"],
                  background=c["surface"], font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Separator(enc_section, orient="horizontal").pack(fill="x", pady=(6, 10))

        ttk.Label(enc_section, text="Key file:", background=c["surface"],
                  foreground=c["muted"], font=("Segoe UI", 9)).pack(anchor="w")
        self.enc_key_var = tk.StringVar()
        enc_key_row = ttk.Frame(enc_section, style="Surface.TFrame")
        enc_key_row.pack(fill="x", pady=(2, 6))
        ttk.Entry(enc_key_row, textvariable=self.enc_key_var, width=14).pack(side="left", expand=True, fill="x")
        ttk.Button(enc_key_row, text="...", style="Secondary.TButton", width=3,
                   command=self._browse_enc_key).pack(side="right", padx=(4, 0))

        ttk.Button(enc_section, text="Generate Key", style="Secondary.TButton",
                   command=self._generate_key_for_encrypt).pack(fill="x", pady=(0, 6))

        ttk.Label(enc_section, text="Files: select from list or browse",
                  background=c["surface"], foreground=c["muted"],
                  font=("Segoe UI", 8), wraplength=196).pack(anchor="w", pady=(0, 4))

        enc_browse_row = ttk.Frame(enc_section, style="Surface.TFrame")
        enc_browse_row.pack(fill="x", pady=(0, 6))
        ttk.Button(enc_browse_row, text="Browse Files", style="Secondary.TButton",
                   command=self._browse_plain_files_manual).pack(fill="x")

        ttk.Button(enc_section, text="Encrypt Selected", style="Accent.TButton",
                   command=self._initiate_encrypt).pack(fill="x", pady=(4, 0))

        dec_section = ttk.Frame(right_panel, style="Surface.TFrame", padding=14)
        dec_section.pack(fill="x", pady=(0, 10))

        ttk.Label(dec_section, text="DECRYPT", foreground=c["success"],
                  background=c["surface"], font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Separator(dec_section, orient="horizontal").pack(fill="x", pady=(6, 10))

        ttk.Label(dec_section, text="Key file:", background=c["surface"],
                  foreground=c["muted"], font=("Segoe UI", 9)).pack(anchor="w")
        self.dec_key_var = tk.StringVar()
        dec_key_row = ttk.Frame(dec_section, style="Surface.TFrame")
        dec_key_row.pack(fill="x", pady=(2, 6))
        ttk.Entry(dec_key_row, textvariable=self.dec_key_var, width=14).pack(side="left", expand=True, fill="x")
        ttk.Button(dec_key_row, text="...", style="Secondary.TButton", width=3,
                   command=self._browse_dec_key).pack(side="right", padx=(4, 0))

        ttk.Label(dec_section, text="Files: select from list or browse",
                  background=c["surface"], foreground=c["muted"],
                  font=("Segoe UI", 8), wraplength=196).pack(anchor="w", pady=(0, 4))

        ttk.Button(dec_section, text="Browse Files", style="Secondary.TButton",
                   command=self._browse_enc_files_manual).pack(fill="x", pady=(0, 6))

        ttk.Button(dec_section, text="Decrypt Selected", style="Success.TButton",
                   command=self._initiate_decrypt).pack(fill="x", pady=(4, 0))

        key_section = ttk.Frame(right_panel, style="Surface.TFrame", padding=14)
        key_section.pack(fill="x", pady=(0, 10))

        ttk.Label(key_section, text="KEY MANAGEMENT", foreground=c["warning"],
                  background=c["surface"], font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Separator(key_section, orient="horizontal").pack(fill="x", pady=(6, 10))

        ttk.Button(key_section, text="Generate & Save Key", style="Secondary.TButton",
                   command=self._generate_standalone_key).pack(fill="x", pady=(0, 6))

        ttk.Label(key_section,
                  text="Loss of your key file makes\nencrypted data permanently\nunrecoverable. Back it up.",
                  background=c["surface"], foreground=c["warning"],
                  font=("Segoe UI", 8), justify="left").pack(anchor="w")

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=20, pady=(10, 0))

        status_bar = ttk.Frame(self, style="Surface.TFrame", padding=(20, 7))
        status_bar.pack(fill="x", side="bottom")

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(status_bar, textvariable=self.status_var,
                  style="Status.TLabel").pack(side="left")

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(status_bar, variable=self.progress_var,
                                             maximum=100, length=180, style="TProgressbar")
        self.progress_bar.pack(side="right", padx=(10, 0))

        self._enc_manual_files: list[pathlib.Path] = []
        self._dec_manual_files: list[pathlib.Path] = []
        self._active_result_queue: queue.Queue | None = None
        self._active_progress_queue: queue.Queue | None = None

    def _set_status(self, message: str, color_key: str = "muted"):
        self.status_var.set(message)
        ttk.Style().configure("Status.TLabel",
                               foreground=self._colors.get(color_key, self._colors["muted"]))

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

        for item in self.scanner.discover_encrypted_files():
            enc_file = item["encrypted_file"]
            size_kb = item["size_bytes"] / 1024
            size_label = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb / 1024:.1f} MB"
            tag = "keyed" if item["key_status"] == "Found" else "unkeyed"
            self.file_tree.insert("", "end", iid=str(enc_file),
                                   values=(item["display_name"], item["key_status"], size_label),
                                   tags=(tag,))

        self.file_tree.tag_configure("keyed", foreground=self._colors["success"])
        self.file_tree.tag_configure("unkeyed", foreground=self._colors["danger"])

        for plain_file in self.scanner.discover_plain_files():
            size_kb = plain_file.stat().st_size / 1024
            size_label = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb / 1024:.1f} MB"
            self.plain_tree.insert("", "end", iid=str(plain_file),
                                    values=(plain_file.name, size_label))

        self._set_status(f"Scanned: {self.family_folder}", "muted")

    def _on_enc_tree_select(self, _event):
        selected = self.file_tree.selection()
        if not selected:
            return
        last = pathlib.Path(selected[-1])
        for item in self.scanner.discover_encrypted_files():
            if item["encrypted_file"] == last and item["paired_key"]:
                if not self.dec_key_var.get().strip():
                    self.dec_key_var.set(str(item["paired_key"]))
                break

    def _browse_folder(self):
        chosen = filedialog.askdirectory(title="Select Family Folder",
                                          initialdir=str(self.family_folder))
        if chosen:
            self.folder_var.set(chosen)

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
        chosen = filedialog.askopenfilenames(
            title="Select Files to Encrypt",
            initialdir=str(self.family_folder))
        if chosen:
            self._enc_manual_files = [pathlib.Path(p) for p in chosen]
            self._append_log(f"Manual selection: {len(self._enc_manual_files)} file(s) queued for encryption.")

    def _browse_enc_files_manual(self):
        chosen = filedialog.askopenfilenames(
            title="Select Encrypted Files to Decrypt",
            filetypes=[("Encrypted Files", f"*{ENCRYPTED_EXTENSION}"), ("All Files", "*.*")],
            initialdir=str(self.family_folder))
        if chosen:
            self._dec_manual_files = [pathlib.Path(p) for p in chosen]
            self._append_log(f"Manual selection: {len(self._dec_manual_files)} file(s) queued for decryption.")

    def _generate_key_for_encrypt(self):
        dialog = KeySaveDialog(self, self.family_folder, self.engine)
        self.wait_window(dialog)
        if dialog.result_key_path:
            self.enc_key_var.set(str(dialog.result_key_path))
            self._append_log(f"Key generated: {dialog.result_key_path.name}")
            self._refresh_file_list()
            messagebox.showinfo("Key Generated",
                                f"Key saved to:\n{dialog.result_key_path}\n\n"
                                "Back up this file immediately to a secure location.")

    def _generate_standalone_key(self):
        dialog = KeySaveDialog(self, self.family_folder, self.engine)
        self.wait_window(dialog)
        if dialog.result_key_path:
            self._append_log(f"Key generated: {dialog.result_key_path.name}")
            self._refresh_file_list()
            messagebox.showinfo("Key Generated",
                                f"Key saved to:\n{dialog.result_key_path}\n\n"
                                "Back up this file immediately to a secure location.")

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
            answer = messagebox.askyesno(
                "No Key Selected",
                "No key file is selected.\n\nWould you like to generate a new key now?")
            if answer:
                self._generate_key_for_encrypt()
                raw_key = self.enc_key_var.get().strip()
            if not raw_key:
                return

        key_path = pathlib.Path(raw_key)
        targets = self._resolve_encrypt_targets()

        if not targets:
            messagebox.showerror("No Files Selected",
                                  "Select files from the Plain Files list or use Browse Files.")
            return

        confirm = messagebox.askyesno(
            "Confirm Batch Encryption",
            f"Encrypt {len(targets)} file(s) using key:\n{key_path.name}\n\nProceed?")
        if not confirm:
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

        def make_encrypt_task(vsrc, vout, vkey):
            def task():
                key_material = self.engine.load_key(vkey)
                try:
                    self.engine.encrypt_file(vsrc, key_material, vout)
                finally:
                    key_material = None
            return task

        batch = [(label, make_encrypt_task(vsrc, vout, validated_key))
                 for label, vsrc, vout in validated_tasks]
        self._enc_manual_files.clear()
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

        confirm = messagebox.askyesno(
            "Confirm Batch Decryption",
            f"Decrypt {len(targets)} file(s) using key:\n{key_path.name}\n\nProceed?")
        if not confirm:
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

        def make_decrypt_task(venc, vout, vkey):
            def task():
                key_material = self.engine.load_key(vkey)
                try:
                    self.engine.decrypt_file(venc, key_material, vout)
                finally:
                    key_material = None
            return task

        batch = [(label, make_decrypt_task(venc, vout, validated_key))
                 for label, venc, vout in validated_tasks]
        self._dec_manual_files.clear()
        self._run_batch(batch, f"Decrypting {len(batch)} file(s)...")

    def _run_batch(self, tasks: list, status_message: str):
        self.operation_in_progress = True
        self.progress_var.set(0)
        self._set_status(status_message, "accent")

        result_queue = queue.Queue()
        progress_queue = queue.Queue()
        self._active_result_queue = result_queue
        self._active_progress_queue = progress_queue

        worker = BatchOperationWorker(tasks, result_queue, progress_queue)
        worker.start()

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
                            self._append_log(f"FAILED  {label}: operation could not be completed.")
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
                    self._refresh_file_list()
                    if not errors:
                        self._set_status(f"Completed: {completed}/{total} file(s).", "success")
                        messagebox.showinfo("Complete",
                                             f"All {completed} file(s) processed successfully.")
                    else:
                        self._set_status(f"Completed with errors: {completed}/{total}.", "warning")
                        messagebox.showwarning(
                            "Partial Completion",
                            f"{completed} of {total} file(s) processed.\n"
                            f"{len(errors)} file(s) failed.\n\n"
                            "Check the Session Log for details.")
            except queue.Empty:
                pass

        self.after(150, self._poll_operation_queue)


def main():
    app = MemocryApp()
    app.mainloop()


if __name__ == "__main__":
    main()

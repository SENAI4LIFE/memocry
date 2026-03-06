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

    def safe_delete(self, file_path: pathlib.Path):
        resolved = file_path.resolve()
        if resolved.is_file():
            resolved.unlink()


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
            default_key = self.family_folder / DEFAULT_KEY_NAME
            paired_key = None
            if candidate_key.is_file():
                paired_key = candidate_key
            elif default_key.is_file():
                paired_key = default_key
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

    def __init__(self, parent, label: str, colors: dict, on_change=None, **kwargs):
        c = colors
        super().__init__(parent, bg=c["bg"], **kwargs)
        self._colors = c
        self._on_change = on_change
        self._state = False

        self._track = tk.Canvas(self, width=36, height=18, bg=c["bg"],
                                highlightthickness=0, cursor="hand2")
        self._track.pack(side="left", padx=(0, 6))
        self._track.bind("<Button-1>", self._toggle)

        self._label = tk.Label(self, text=label, bg=c["bg"], fg=c["muted"],
                               font=("Segoe UI", 8), cursor="hand2")
        self._label.pack(side="left")
        self._label.bind("<Button-1>", self._toggle)

        self._draw()

    def _draw(self):
        c = self._colors
        self._track.delete("all")
        track_color = c["accent"] if self._state else c["surface"]
        self._track.create_rounded_rect = None
        self._track.create_oval(0, 1, 36, 17, fill=track_color, outline="")
        knob_x = 20 if self._state else 4
        knob_color = "#ffffff" if self._state else c["muted"]
        self._track.create_oval(knob_x, 3, knob_x + 12, 15, fill=knob_color, outline="")
        label_color = c["fg"] if self._state else c["muted"]
        self._label.configure(fg=label_color)

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
        outer = ttk.Frame(self, style="TFrame", padding=22)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Generate New Key", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=(8, 14))

        ttk.Label(outer, text="Key file name:", style="Muted.TLabel").pack(anchor="w")
        self._name_var = tk.StringVar(value=DEFAULT_KEY_NAME)
        ttk.Entry(outer, textvariable=self._name_var, width=38).pack(fill="x", pady=(3, 10))

        ttk.Label(outer, text="Save location:", style="Muted.TLabel").pack(anchor="w")
        loc_row = ttk.Frame(outer, style="TFrame")
        loc_row.pack(fill="x", pady=(3, 10))
        self._loc_var = tk.StringVar(value=str(self._default_folder))
        ttk.Entry(loc_row, textvariable=self._loc_var, width=30).pack(side="left", expand=True, fill="x")
        ttk.Button(loc_row, text="Browse", style="Secondary.TButton",
                   command=self._browse_location).pack(side="right", padx=(6, 0))

        warn = ttk.Frame(outer, style="Surface.TFrame", padding=10)
        warn.pack(fill="x", pady=(0, 14))
        ttk.Label(warn, text="WARNING", foreground=c["warning"], background=c["surface"],
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Label(warn,
                  text="Loss of this key makes all files encrypted with it permanently "
                       "unrecoverable. Back it up immediately to a secure, separate location.",
                  background=c["surface"], foreground=c["warning"],
                  font=("Segoe UI", 8), wraplength=330, justify="left").pack(anchor="w", pady=(4, 0))

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
            messagebox.showerror("Invalid Location", "The save location is not a valid directory.",
                                  parent=self)
            return
        key_path = loc / name
        if key_path.exists():
            if not messagebox.askyesno(
                    "File Exists",
                    f"A key already exists at:\n{key_path}\n\n"
                    "Overwriting will make files encrypted with the old key inaccessible.\nContinue?",
                    parent=self):
                return
        try:
            key_material = self.engine_generate_and_save(key_path)
            key_material = None
            self.result_key_path = key_path
            self.destroy()
        except Exception:
            messagebox.showerror("Error", "Key generation failed. Check folder permissions.",
                                  parent=self)

    def engine_generate_and_save(self, key_path: pathlib.Path):
        key_material = self._engine.generate_key()
        self._engine.save_key(key_material, key_path)
        return key_material


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

        self._apply_theme()
        self._build_layout()
        self._auto_size_window()
        self._refresh_file_list()
        self._poll_operation_queue()

    def _auto_size_window(self):
        self.update_idletasks()
        req_w = self.winfo_reqwidth()
        req_h = self.winfo_reqheight()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        w = min(max(req_w + 60, 1020), screen_w - 80)
        h = min(max(req_h + 60, 720), screen_h - 80)
        x = (screen_w - w) // 2
        y = (screen_h - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(900, 640)

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
        style.configure("Title.TLabel", background=bg, foreground=fg, font=("Segoe UI", 16, "bold"))
        style.configure("Status.TLabel", background=surface, foreground=muted, font=("Segoe UI", 9))
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

        self._build_toggle_bar()

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=0, pady=0)

        header = tk.Frame(self, bg=c["bg"], padx=20, pady=10)
        header.pack(fill="x")

        ttk.Label(header, text="memocry", style="Title.TLabel").pack(side="left")

        folder_frame = tk.Frame(header, bg=c["bg"])
        folder_frame.pack(side="right")
        ttk.Label(folder_frame, text="Family Folder:", style="Muted.TLabel").pack(side="left", padx=(0, 6))
        self.folder_var = tk.StringVar(value=str(self.family_folder))
        ttk.Entry(folder_frame, textvariable=self.folder_var, width=34).pack(side="left", padx=(0, 4))
        ttk.Button(folder_frame, text="Browse", style="Secondary.TButton",
                   command=self._browse_folder).pack(side="left")
        ttk.Button(folder_frame, text="Add Folder", style="Secondary.TButton",
                   command=self._add_folder_to_encrypt).pack(side="left", padx=(4, 0))
        ttk.Button(folder_frame, text="Set", style="Secondary.TButton",
                   command=self._set_family_folder).pack(side="left", padx=(4, 0))

        ttk.Separator(self, orient="horizontal").pack(fill="x")

        main_pane = tk.Frame(self, bg=c["bg"], padx=18, pady=10)
        main_pane.pack(fill="both", expand=True)

        left_panel = tk.Frame(main_pane, bg=c["bg"])
        left_panel.pack(side="left", fill="both", expand=True)

        enc_header_row = tk.Frame(left_panel, bg=c["bg"])
        enc_header_row.pack(fill="x", pady=(0, 4))
        tk.Label(enc_header_row, text="Encrypted Files", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(enc_header_row, text="  Ctrl/Shift+click = multi-select",
                 bg=c["bg"], fg=c["muted"], font=("Segoe UI", 8)).pack(side="left")
        ttk.Button(enc_header_row, text="Refresh", style="Secondary.TButton",
                   command=self._refresh_file_list).pack(side="right")

        enc_tree_outer = tk.Frame(left_panel, bg=c["surface"])
        enc_tree_outer.pack(fill="both", expand=True)
        enc_cols = ("file", "key_status", "size")
        self.file_tree = ttk.Treeview(enc_tree_outer, columns=enc_cols,
                                       show="headings", selectmode="extended")
        self.file_tree.heading("file", text="File Name")
        self.file_tree.heading("key_status", text="Key")
        self.file_tree.heading("size", text="Size")
        self.file_tree.column("file", width=280, minwidth=160)
        self.file_tree.column("key_status", width=65, anchor="center")
        self.file_tree.column("size", width=80, anchor="e")
        enc_scroll = ttk.Scrollbar(enc_tree_outer, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=enc_scroll.set)
        self.file_tree.pack(side="left", fill="both", expand=True)
        enc_scroll.pack(side="right", fill="y")
        self.file_tree.bind("<<TreeviewSelect>>", self._on_enc_tree_select)

        plain_header_row = tk.Frame(left_panel, bg=c["bg"])
        plain_header_row.pack(fill="x", pady=(10, 4))
        tk.Label(plain_header_row, text="Plain Files", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(plain_header_row, text="  Ctrl/Shift+click = multi-select",
                 bg=c["bg"], fg=c["muted"], font=("Segoe UI", 8)).pack(side="left")

        plain_tree_outer = tk.Frame(left_panel, bg=c["surface"])
        plain_tree_outer.pack(fill="x")
        plain_cols = ("plain_file", "plain_size")
        self.plain_tree = ttk.Treeview(plain_tree_outer, columns=plain_cols,
                                        show="headings", selectmode="extended", height=5)
        self.plain_tree.heading("plain_file", text="File Name")
        self.plain_tree.heading("plain_size", text="Size")
        self.plain_tree.column("plain_file", width=310, minwidth=160)
        self.plain_tree.column("plain_size", width=80, anchor="e")
        plain_scroll = ttk.Scrollbar(plain_tree_outer, orient="vertical",
                                      command=self.plain_tree.yview)
        self.plain_tree.configure(yscrollcommand=plain_scroll.set)
        self.plain_tree.pack(side="left", fill="x", expand=True)
        plain_scroll.pack(side="right", fill="y")

        log_header_row = tk.Frame(left_panel, bg=c["bg"])
        log_header_row.pack(fill="x", pady=(10, 4))
        tk.Label(log_header_row, text="Session Log", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(log_header_row, text="Clear", style="Secondary.TButton",
                   command=self._clear_log).pack(side="right")

        log_outer = tk.Frame(left_panel, bg=c["surface"])
        log_outer.pack(fill="x")
        self.log_text = tk.Text(log_outer, height=5, state="disabled",
                                bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8),
                                relief="flat", borderwidth=0, wrap="word",
                                insertbackground=c["fg"], padx=6, pady=4)
        log_scroll = ttk.Scrollbar(log_outer, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="x", expand=True)
        log_scroll.pack(side="right", fill="y")

        right_panel = tk.Frame(main_pane, bg=c["bg"], padx=16)
        right_panel.pack(side="right", fill="y")

        tk.Label(right_panel, text="Operations", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))

        enc_card = tk.Frame(right_panel, bg=c["surface"], padx=14, pady=12)
        enc_card.pack(fill="x", pady=(0, 8))
        tk.Label(enc_card, text="ENCRYPT", bg=c["surface"], fg=c["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Separator(enc_card, orient="horizontal").pack(fill="x", pady=(5, 8))

        tk.Label(enc_card, text="Key file:", bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w")
        enc_key_row = tk.Frame(enc_card, bg=c["surface"])
        enc_key_row.pack(fill="x", pady=(2, 6))
        self.enc_key_var = tk.StringVar()
        ttk.Entry(enc_key_row, textvariable=self.enc_key_var, width=15).pack(side="left",
                                                                               expand=True, fill="x")
        ttk.Button(enc_key_row, text="...", style="Secondary.TButton", width=3,
                   command=self._browse_enc_key).pack(side="right", padx=(4, 0))

        tk.Label(enc_card, text="Files: select list rows or browse",
                 bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 4))
        ttk.Button(enc_card, text="Browse Files", style="Secondary.TButton",
                   command=self._browse_plain_files_manual).pack(fill="x", pady=(0, 4))
        ttk.Button(enc_card, text="Encrypt Selected", style="Accent.TButton",
                   command=self._initiate_encrypt).pack(fill="x")

        dec_card = tk.Frame(right_panel, bg=c["surface"], padx=14, pady=12)
        dec_card.pack(fill="x", pady=(0, 8))
        tk.Label(dec_card, text="DECRYPT", bg=c["surface"], fg=c["success"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Separator(dec_card, orient="horizontal").pack(fill="x", pady=(5, 8))

        tk.Label(dec_card, text="Key file:", bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w")
        dec_key_row = tk.Frame(dec_card, bg=c["surface"])
        dec_key_row.pack(fill="x", pady=(2, 6))
        self.dec_key_var = tk.StringVar()
        ttk.Entry(dec_key_row, textvariable=self.dec_key_var, width=15).pack(side="left",
                                                                               expand=True, fill="x")
        ttk.Button(dec_key_row, text="...", style="Secondary.TButton", width=3,
                   command=self._browse_dec_key).pack(side="right", padx=(4, 0))

        tk.Label(dec_card, text="Files: select list rows or browse",
                 bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 4))
        ttk.Button(dec_card, text="Browse Files", style="Secondary.TButton",
                   command=self._browse_enc_files_manual).pack(fill="x", pady=(0, 4))
        ttk.Button(dec_card, text="Decrypt Selected", style="Success.TButton",
                   command=self._initiate_decrypt).pack(fill="x")

        key_card = tk.Frame(right_panel, bg=c["surface"], padx=14, pady=12)
        key_card.pack(fill="x", pady=(0, 8))
        tk.Label(key_card, text="KEY MANAGEMENT", bg=c["surface"], fg=c["warning"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Separator(key_card, orient="horizontal").pack(fill="x", pady=(5, 8))

        ttk.Button(key_card, text="Generate & Save Key", style="Secondary.TButton",
                   command=self._generate_standalone_key).pack(fill="x", pady=(0, 6))
        ttk.Button(key_card, text="Delete All Detected Keys", style="Danger.TButton",
                   command=self._delete_all_keys).pack(fill="x", pady=(0, 8))

        tk.Label(key_card,
                 text="Loss of a key makes all files encrypted\nwith it permanently unrecoverable.\nBack up keys to a secure location.",
                 bg=c["surface"], fg=c["warning"], font=("Segoe UI", 8), justify="left").pack(anchor="w")

        ttk.Separator(self, orient="horizontal").pack(fill="x")

        status_bar = tk.Frame(self, bg=c["surface"], padx=20, pady=7)
        status_bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(status_bar, textvariable=self.status_var, bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(side="left")
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(status_bar, variable=self.progress_var,
                                             maximum=100, length=200, style="TProgressbar")
        self.progress_bar.pack(side="right")

    def _build_toggle_bar(self):
        c = self._colors
        toggle_bar = tk.Frame(self, bg=c["surface"], padx=16, pady=8)
        toggle_bar.pack(fill="x")

        tk.Label(toggle_bar, text="Session Options:", bg=c["surface"], fg=c["muted"],
                 font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 16))

        self._toggle_delete_after_encrypt = ToggleButton(
            toggle_bar, "Delete source after encrypt", c)
        self._toggle_delete_after_encrypt.configure(bg=c["surface"])
        self._toggle_delete_after_encrypt._label.configure(bg=c["surface"])
        self._toggle_delete_after_encrypt._track.configure(bg=c["surface"])
        self._toggle_delete_after_encrypt.pack(side="left", padx=(0, 20))

        self._toggle_delete_after_decrypt = ToggleButton(
            toggle_bar, "Delete .enc after decrypt", c)
        self._toggle_delete_after_decrypt.configure(bg=c["surface"])
        self._toggle_delete_after_decrypt._label.configure(bg=c["surface"])
        self._toggle_delete_after_decrypt._track.configure(bg=c["surface"])
        self._toggle_delete_after_decrypt.pack(side="left", padx=(0, 20))

        self._toggle_delete_key_after_encrypt = ToggleButton(
            toggle_bar, "Delete key after encrypt", c)
        self._toggle_delete_key_after_encrypt.configure(bg=c["surface"])
        self._toggle_delete_key_after_encrypt._label.configure(bg=c["surface"])
        self._toggle_delete_key_after_encrypt._track.configure(bg=c["surface"])
        self._toggle_delete_key_after_encrypt.pack(side="left", padx=(0, 20))

        self._toggle_delete_key_after_decrypt = ToggleButton(
            toggle_bar, "Delete key after decrypt", c)
        self._toggle_delete_key_after_decrypt.configure(bg=c["surface"])
        self._toggle_delete_key_after_decrypt._label.configure(bg=c["surface"])
        self._toggle_delete_key_after_decrypt._track.configure(bg=c["surface"])
        self._toggle_delete_key_after_decrypt.pack(side="left", padx=(0, 20))

        self._toggle_warnings = ToggleButton(
            toggle_bar, "Extra warnings", c)
        self._toggle_warnings.configure(bg=c["surface"])
        self._toggle_warnings._label.configure(bg=c["surface"])
        self._toggle_warnings._track.configure(bg=c["surface"])
        self._toggle_warnings.pack(side="left")

    def _set_status(self, message: str, color_key: str = "muted"):
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
            rel = plain_file.relative_to(self.family_folder)
            self.plain_tree.insert("", "end", iid=str(plain_file),
                                    values=(str(rel), size_label))

        self._set_status(f"Scanned: {self.family_folder}", "muted")

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
        chosen = filedialog.askdirectory(title="Select Folder to Add for Encryption",
                                          initialdir=str(self.family_folder))
        if not chosen:
            return
        folder = pathlib.Path(chosen).resolve()
        added = 0
        for f in sorted(folder.rglob("*")):
            if f.is_file() and f.suffix != ENCRYPTED_EXTENSION and f.suffix != KEY_EXTENSION:
                if f not in self._enc_manual_files:
                    self._enc_manual_files.append(f)
                    added += 1
        self._append_log(f"Folder added: {folder.name} ({added} file(s) queued for encryption).")

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
            added = []
            for p in [pathlib.Path(x) for x in chosen]:
                if p not in self._enc_manual_files:
                    self._enc_manual_files.append(p)
                    added.append(p)
            self._append_log(f"Manual selection: {len(added)} file(s) queued for encryption.")

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
            self._append_log(f"Manual selection: {len(added)} file(s) queued for decryption.")

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
            messagebox.showinfo("No Keys Found", "No key files were detected in the family folder.")
            return
        names = "\n".join(f.name for f in key_files[:10])
        extra = f"\n... and {len(key_files) - 10} more" if len(key_files) > 10 else ""
        confirmed = messagebox.askyesno(
            "Delete All Keys",
            f"This will permanently delete {len(key_files)} key file(s):\n\n"
            f"{names}{extra}\n\n"
            "Files encrypted with these keys will become PERMANENTLY UNRECOVERABLE.\n\n"
            "Are you absolutely sure?")
        if not confirmed:
            return
        final_confirm = messagebox.askyesno(
            "Final Confirmation",
            "This action cannot be undone.\n\nDelete all detected keys now?")
        if not final_confirm:
            return
        deleted = 0
        failed = 0
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

    def _check_key_file_warnings(self, source_paths: list[pathlib.Path],
                                  active_key_path: pathlib.Path) -> bool:
        key_files_in_selection = [p for p in source_paths if p.suffix == KEY_EXTENSION]
        encrypting_own_key = [p for p in source_paths
                               if p.resolve() == active_key_path.resolve()]
        warnings = []
        if encrypting_own_key:
            warnings.append(
                "You are about to encrypt the key file currently selected for encryption.\n"
                "This is almost always a mistake.")
        if key_files_in_selection:
            names = ", ".join(p.name for p in key_files_in_selection)
            warnings.append(
                f"The following key file(s) are included in your selection:\n{names}\n\n"
                "Encrypting a key file without knowing where its key is stored will make "
                "the key permanently inaccessible.")
        if warnings:
            full_warning = "\n\n".join(warnings) + "\n\nContinue anyway?"
            return messagebox.askyesno("Key File Warning", full_warning)
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
                                    "No key file is selected.\n\nGenerate a new key now?"):
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

        if not self._check_key_file_warnings(targets, key_path):
            return

        if self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Confirm Batch Encryption",
                    f"Encrypt {len(targets)} file(s) using key:\n{key_path.name}\n\nProceed?"):
                return

        delete_source = self._toggle_delete_after_encrypt.value
        delete_key = self._toggle_delete_key_after_encrypt.value

        if delete_source and self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Delete Source Files",
                    f"'Delete source after encrypt' is ON.\n"
                    f"The original {len(targets)} file(s) will be deleted after encryption.\n\n"
                    "Continue?"):
                return

        if delete_key and self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Delete Key After Encrypt",
                    f"'Delete key after encrypt' is ON.\n"
                    f"The key file '{key_path.name}' will be deleted after all files are encrypted.\n\n"
                    "Files encrypted with this key will become UNRECOVERABLE if you do not have a backup.\n\n"
                    "Continue?"):
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

        sources_to_delete = ([t[1] for t in validated_tasks] if delete_source else [])

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
                    "Confirm Batch Decryption",
                    f"Decrypt {len(targets)} file(s) using key:\n{key_path.name}\n\nProceed?"):
                return

        delete_source = self._toggle_delete_after_decrypt.value
        delete_key = self._toggle_delete_key_after_decrypt.value

        if delete_source and self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Delete Encrypted Files",
                    f"'Delete .enc after decrypt' is ON.\n"
                    f"The encrypted {len(targets)} file(s) will be deleted after decryption.\n\n"
                    "Continue?"):
                return

        if delete_key and self._toggle_warnings.value:
            if not messagebox.askyesno(
                    "Delete Key After Decrypt",
                    f"'Delete key after decrypt' is ON.\n"
                    f"The key file '{key_path.name}' will be deleted after all files are decrypted.\n\n"
                    "Continue?"):
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

        sources_to_delete = ([t[1] for t in validated_tasks] if delete_source else [])

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
        self._set_status(status_message, "accent")
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

                    post_action = getattr(self, "_pending_post_action", None)
                    self._pending_post_action = None
                    if post_action:
                        post_action()

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

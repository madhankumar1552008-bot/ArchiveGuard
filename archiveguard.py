#!/usr/bin/env python3

import os
import sys
import json
import logging
import zipfile
import argparse
import datetime
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


DEFAULT_MAX_RATIO: float = 100.0
DEFAULT_MAX_TOTAL_SIZE: int = 500 * 1024 * 1024
DEFAULT_MAX_SINGLE_FILE_SIZE: int = 100 * 1024 * 1024
DEFAULT_MAX_FILE_COUNT: int = 10_000
DEFAULT_MAX_NESTED_DEPTH: int = 5

SUSPECT_EXTENSIONS: Set[str] = {
    ".exe", ".bat", ".cmd", ".vbs", ".scr", ".ps1", ".sh",
    ".dll", ".so", ".dylib", ".com", ".pif", ".application",
    ".gadget", ".msi", ".msp", ".hta", ".cpl", ".msc", ".jar",
    ".js", ".jse", ".ws", ".wsc", ".wsf", ".wsh"
}


class ArchiveGuardError(Exception):
    pass


class SecurityViolationError(ArchiveGuardError):
    pass


class InvalidArchiveError(ArchiveGuardError):
    pass


def setup_logger(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger("ArchiveGuard")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


class GuardPolicy:
    def __init__(
        self,
        max_ratio: float = DEFAULT_MAX_RATIO,
        max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
        max_single_file_size: int = DEFAULT_MAX_SINGLE_FILE_SIZE,
        max_file_count: int = DEFAULT_MAX_FILE_COUNT,
        max_depth: int = DEFAULT_MAX_NESTED_DEPTH,
        blocked_extensions: Optional[Set[str]] = None,
        block_hidden_files: bool = False,
    ):
        self.max_ratio = max_ratio
        self.max_total_size = max_total_size
        self.max_single_file_size = max_single_file_size
        self.max_file_count = max_file_count
        self.max_depth = max_depth
        self.blocked_extensions = blocked_extensions if blocked_extensions is not None else SUSPECT_EXTENSIONS
        self.block_hidden_files = block_hidden_files

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_ratio": self.max_ratio,
            "max_total_size_mb": self.max_total_size / (1024 * 1024),
            "max_single_file_size_mb": self.max_single_file_size / (1024 * 1024),
            "max_file_count": self.max_file_count,
            "max_depth": self.max_depth,
            "blocked_extensions": sorted(list(self.blocked_extensions)),
            "block_hidden_files": self.block_hidden_files,
        }


class ArchiveInspector:
    def __init__(self, file_path: str, policy: Optional[GuardPolicy] = None, logger: Optional[logging.Logger] = None):
        self.file_path = Path(file_path).resolve()
        self.policy = policy or GuardPolicy()
        self.logger = logger or logging.getLogger("ArchiveGuard")

        if not self.file_path.exists():
            raise FileNotFoundError(f"Target archive does not exist: {self.file_path}")
        if not self.file_path.is_file():
            raise ValueError(f"Path is not a regular file: {self.file_path}")

    def compute_file_hash(self, algorithm: str = "sha256") -> str:
        hasher = hashlib.new(algorithm)
        with open(self.file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def inspect(self) -> Dict[str, Any]:
        self.logger.info(f"Starting inspection of: {self.file_path.name}")

        total_compressed = 0
        total_uncompressed = 0
        warnings: List[str] = []
        threats: List[str] = []
        entry_manifest: List[Dict[str, Any]] = []

        try:
            with zipfile.ZipFile(self.file_path, "r") as zf:
                infolist = zf.infolist()
                file_count = len(infolist)

                if file_count > self.policy.max_file_count:
                    threats.append(
                        f"File Count Violation: Archive contains {file_count} entries, "
                        f"exceeding policy limit of {self.policy.max_file_count}."
                    )

                for info in infolist:
                    total_compressed += info.compress_size
                    total_uncompressed += info.file_size

                    entry_path = Path(info.filename)
                    depth = len(entry_path.parts) - 1

                    if depth > self.policy.max_depth:
                        warnings.append(
                            f"Excessive Path Depth: '{info.filename}' depth is {depth} (Limit: {self.policy.max_depth})."
                        )

                    if entry_path.is_absolute() or ".." in entry_path.parts:
                        threats.append(f"Zip Slip / Path Traversal Hazard: '{info.filename}' attempts path escape.")

                    if info.file_size > self.policy.max_single_file_size:
                        threats.append(
                            f"File Size Limit Exceeded: '{info.filename}' ({info.file_size / (1024*1024):.2f} MB) "
                            f"exceeds limit ({self.policy.max_single_file_size / (1024*1024):.0f} MB)."
                        )

                    ext = entry_path.suffix.lower()
                    if ext in self.policy.blocked_extensions:
                        warnings.append(f"Suspicious Extension: '{info.filename}' has restricted extension ({ext}).")

                    if self.policy.block_hidden_files and entry_path.name.startswith("."):
                        warnings.append(f"Hidden File Detected: '{info.filename}'.")

                    entry_manifest.append({
                        "filename": info.filename,
                        "compressed_bytes": info.compress_size,
                        "uncompressed_bytes": info.file_size,
                        "is_dir": info.is_dir(),
                        "ratio": (info.file_size / info.compress_size) if info.compress_size > 0 else 0.0,
                    })

                if total_uncompressed > self.policy.max_total_size:
                    threats.append(
                        f"Total Size Limit Exceeded: Uncompressed output ({total_uncompressed / (1024*1024):.2f} MB) "
                        f"exceeds total allowed threshold ({self.policy.max_total_size / (1024*1024):.0f} MB)."
                    )

                overall_ratio = (total_uncompressed / total_compressed) if total_compressed > 0 else 0.0
                if overall_ratio > self.policy.max_ratio and total_uncompressed > 1_000_000:
                    threats.append(
                        f"Zip Bomb Detection: Overall compression ratio is {overall_ratio:.1f}:1 "
                        f"(Threshold: {self.policy.max_ratio:.1f}:1)."
                    )

        except zipfile.BadZipFile as e:
            raise InvalidArchiveError(f"File is not a valid zip archive: {e}")
        except Exception as e:
            raise ArchiveGuardError(f"An unexpected error occurred while processing archive: {e}")

        is_safe = len(threats) == 0

        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "archive_path": str(self.file_path),
            "archive_size_bytes": self.file_path.stat().st_size,
            "sha256": self.compute_file_hash("sha256"),
            "file_count": len(entry_manifest),
            "total_compressed_bytes": total_compressed,
            "total_uncompressed_bytes": total_uncompressed,
            "overall_compression_ratio": overall_ratio if total_compressed > 0 else 0.0,
            "is_safe": is_safe,
            "threats": threats,
            "warnings": warnings,
            "policy": self.policy.to_dict(),
            "manifest": entry_manifest,
        }

        self.logger.info(f"Inspection complete. Safe: {is_safe}. Threats: {len(threats)}, Warnings: {len(warnings)}.")
        return report


class SafeExtractor:
    def __init__(self, inspector: ArchiveInspector, logger: Optional[logging.Logger] = None):
        self.inspector = inspector
        self.logger = logger or logging.getLogger("ArchiveGuard")

    def extract(self, destination: str, force: bool = False) -> List[str]:
        report = self.inspector.inspect()

        if not report["is_safe"] and not force:
            raise SecurityViolationError(
                "Extraction blocked due to security threats:\n" + "\n".join(report["threats"])
            )

        dest_path = Path(destination).resolve()
        dest_path.mkdir(parents=True, exist_ok=True)

        extracted_files: List[str] = []

        self.logger.info(f"Extracting contents to destination: {dest_path}")

        with zipfile.ZipFile(self.inspector.file_path, "r") as zf:
            for member in zf.infolist():
                target_file_path = (dest_path / member.filename).resolve()

                if not str(target_file_path).startswith(str(dest_path)):
                    raise SecurityViolationError(f"Zip Slip attack blocked during extraction: {member.filename}")

                if member.is_dir():
                    target_file_path.mkdir(parents=True, exist_ok=True)
                else:
                    target_file_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as source, open(target_file_path, "wb") as target:
                        while chunk := source.read(65536):
                            target.write(chunk)

                    extracted_files.append(str(target_file_path))

        self.logger.info(f"Successfully extracted {len(extracted_files)} files.")
        return extracted_files


if GUI_AVAILABLE:
    class ArchiveGuardGUI:
        def __init__(self, root: tk.Tk):
            self.root = root
            self.root.title("ArchiveGuard - Zip Threat Analysis & Security Tool")
            self.root.geometry("750x550")
            self.root.minsize(650, 450)

            self.current_file: Optional[str] = None
            self.current_report: Optional[Dict[str, Any]] = None

            self._create_menu()
            self._build_widgets()

        def _create_menu(self):
            menubar = tk.Menu(self.root)
            file_menu = tk.Menu(menubar, tearoff=0)
            file_menu.add_command(label="Open Archive...", command=self.open_archive)
            file_menu.add_command(label="Export Audit Report (JSON)...", command=self.export_report)
            file_menu.add_separator()
            file_menu.add_command(label="Exit", command=self.root.quit)
            menubar.add_cascade(label="File", menu=file_menu)

            help_menu = tk.Menu(menubar, tearoff=0)
            help_menu.add_command(label="About", command=self.show_about)
            menubar.add_cascade(label="Help", menu=help_menu)

            self.root.config(menu=menubar)

        def _build_widgets(self):
            top_frame = ttk.Frame(self.root, padding=10)
            top_frame.pack(fill=tk.X)

            btn_open = ttk.Button(top_frame, text="Select Zip File", command=self.open_archive)
            btn_open.pack(side=tk.LEFT, padx=(0, 10))

            self.btn_extract = ttk.Button(top_frame, text="Safely Extract", command=self.extract_archive, state=tk.DISABLED)
            self.btn_extract.pack(side=tk.LEFT, padx=(0, 10))

            self.lbl_file = ttk.Label(top_frame, text="No archive file loaded.", font=("Helvetica", 10, "italic"))
            self.lbl_file.pack(side=tk.LEFT, fill=tk.X, expand=True)

            self.status_frame = ttk.LabelFrame(self.root, text=" Archive Security Status ", padding=10)
            self.status_frame.pack(fill=tk.X, padx=10, pady=5)

            self.lbl_status = ttk.Label(self.status_frame, text="Awaiting inspection...", font=("Helvetica", 11, "bold"))
            self.lbl_status.pack(anchor="w")

            notebook = ttk.Notebook(self.root)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            tab_log = ttk.Frame(notebook)
            notebook.add(tab_log, text="Inspection Log")

            self.txt_log = tk.Text(tab_log, wrap=tk.WORD, font=("Consolas", 9))
            scrollbar = ttk.Scrollbar(tab_log, command=self.txt_log.yview)
            self.txt_log.configure(yscrollcommand=scrollbar.set)
            self.txt_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            tab_tree = ttk.Frame(notebook)
            notebook.add(tab_tree, text="Archive Manifest")

            self.tree = ttk.Treeview(tab_tree, columns=("Size", "Compressed", "Ratio"), show="tree headings")
            self.tree.heading("#0", text="Filename")
            self.tree.heading("Size", text="Uncompressed Size")
            self.tree.heading("Compressed", text="Compressed Size")
            self.tree.heading("Ratio", text="Ratio")
            self.tree.pack(fill=tk.BOTH, expand=True)

        def log(self, text: str):
            self.txt_log.config(state=tk.NORMAL)
            self.txt_log.insert(tk.END, text + "\n")
            self.txt_log.see(tk.END)
            self.txt_log.config(state=tk.DISABLED)

        def clear_log(self):
            self.txt_log.config(state=tk.NORMAL)
            self.txt_log.delete("1.0", tk.END)
            self.txt_log.config(state=tk.DISABLED)

        def open_archive(self):
            file_path = filedialog.askopenfilename(filetypes=[("Zip Archives", "*.zip"), ("All Files", "*.*")])
            if not file_path:
                return

            self.current_file = file_path
            self.lbl_file.config(text=Path(file_path).name, font=("Helvetica", 10, "normal"))
            self.clear_log()
            self.tree.delete(*self.tree.get_children())

            try:
                inspector = ArchiveInspector(file_path)
                report = inspector.inspect()
                self.current_report = report

                self.log("=" * 60)
                self.log(f"ARCHIVE AUDIT REPORT: {report['archive_path']}")
                self.log(f"SHA-256 Checksum: {report['sha256']}")
                self.log(f"File Count: {report['file_count']}")
                self.log(f"Total Size: {report['total_uncompressed_bytes'] / (1024*1024):.2f} MB")
                self.log(f"Compression Ratio: {report['overall_compression_ratio']:.2f}:1")
                self.log("=" * 60)

                for entry in report["manifest"]:
                    self.tree.insert(
                        "",
                        tk.END,
                        text=entry["filename"],
                        values=(
                            f"{entry['uncompressed_bytes']} B",
                            f"{entry['compressed_bytes']} B",
                            f"{entry['ratio']:.1f}:1"
                        )
                    )

                if report["is_safe"]:
                    self.lbl_status.config(text="STATUS: SAFE (No severe threats detected)", foreground="green")
                    self.btn_extract.config(state=tk.NORMAL)
                    self.log("\n[SAFE] Archive passed all security policy verification checks.")
                else:
                    self.lbl_status.config(text="STATUS: UNSAFE / THREAT DETECTED", foreground="red")
                    self.btn_extract.config(state=tk.DISABLED)
                    self.log("\n[THREATS DETECTED]:")
                    for threat in report["threats"]:
                        self.log(f" - {threat}")

                if report["warnings"]:
                    self.log("\n[WARNINGS]:")
                    for warn in report["warnings"]:
                        self.log(f" - {warn}")

            except Exception as e:
                messagebox.showerror("Inspection Error", str(e))
                self.lbl_status.config(text="STATUS: ERROR", foreground="red")

        def extract_archive(self):
            if not self.current_file:
                return

            dest_dir = filedialog.askdirectory(title="Select Destination Directory")
            if not dest_dir:
                return

            try:
                inspector = ArchiveInspector(self.current_file)
                extractor = SafeExtractor(inspector)
                extracted = extractor.extract(dest_dir)
                messagebox.showinfo("Success", f"Extracted {len(extracted)} files successfully to:\n{dest_dir}")
                self.log(f"\n[EXTRACTED] {len(extracted)} files saved to '{dest_dir}'.")
            except Exception as e:
                messagebox.showerror("Extraction Failed", str(e))

        def export_report(self):
            if not self.current_report:
                messagebox.showwarning("Warning", "No audit report available to export.")
                return

            save_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json")],
                title="Save Audit Report"
            )
            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(self.current_report, f, indent=4)
                messagebox.showinfo("Export Complete", f"Report saved to:\n{save_path}")

        def show_about(self):
            messagebox.showinfo(
                "About ArchiveGuard",
                "ArchiveGuard Security Utility\nVersion 2.0.0\n\n"
                "Protects against Zip Slip, Zip Bombs, and Malicious Archives."
            )


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ArchiveGuard: Inspect and safely extract `.zip` files with security controls."
    )
    parser.add_argument("archive", nargs="?", help="Path to target zip archive")
    parser.add_argument("-x", "--extract", metavar="DEST", help="Extract archive safely to destination directory")
    parser.add_argument("-j", "--json", metavar="FILE", help="Export inspection report to JSON file")
    parser.add_argument("--max-ratio", type=float, default=DEFAULT_MAX_RATIO, help="Max compression ratio allowed")
    parser.add_argument("--max-size", type=int, default=500, help="Max uncompressed size in MB")
    parser.add_argument("--gui", action="store_true", help="Launch Graphical User Interface")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--log-file", help="Path to output log file")
    return parser


def main():
    parser = build_cli_parser()
    args = parser.parse_args()

    logger = setup_logger(args.verbose, args.log_file)

    if args.gui or len(sys.argv) == 1:
        if not GUI_AVAILABLE:
            print("Error: Tkinter GUI environment is not installed or available.", file=sys.stderr)
            sys.exit(1)
        root = tk.Tk()
        app = ArchiveGuardGUI(root)
        root.mainloop()
        return

    if not args.archive:
        parser.print_help()
        sys.exit(1)

    policy = GuardPolicy(
        max_ratio=args.max_ratio,
        max_total_size=args.max_size * 1024 * 1024,
    )

    try:
        inspector = ArchiveInspector(args.archive, policy=policy, logger=logger)
        report = inspector.inspect()

        print("\n" + "=" * 60)
        print(f" ARCHIVEGUARD INSPECTION REPORT")
        print("=" * 60)
        print(f" Archive Name    : {Path(report['archive_path']).name}")
        print(f" SHA-256 Checksum: {report['sha256']}")
        print(f" Files Included  : {report['file_count']}")
        print(f" Compressed Size : {report['total_compressed_bytes'] / 1024:.2f} KB")
        print(f" Uncompressed    : {report['total_uncompressed_bytes'] / 1024:.2f} KB")
        print(f" Overall Ratio   : {report['overall_compression_ratio']:.2f}:1")
        print(f" Safety Status   : {'[SAFE]' if report['is_safe'] else '[HAZARDOUS / UNSAFE]'}")
        print("=" * 60)

        if report["threats"]:
            print("\n[!] THREATS DETECTED:")
            for threat in report["threats"]:
                print(f"  - {threat}")

        if report["warnings"]:
            print("\n[*] WARNINGS:")
            for warn in report["warnings"]:
                print(f"  - {warn}")

        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4)
            print(f"\n[+] Audit report exported to JSON: {args.json}")

        if args.extract:
            extractor = SafeExtractor(inspector, logger=logger)
            extracted = extractor.extract(args.extract)
            print(f"\n[+] Extraction successfully completed: {len(extracted)} files -> '{args.extract}'")

    except Exception as err:
        logger.error(f"Execution failed: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()

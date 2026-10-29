# ArchiveGuard

**ArchiveGuard** is a Python utility designed to inspect standard `.zip` archives and protect against common archive-based security exploits, including Zip Slip (path traversal), Zip Bombs, and hazardous file extension execution.

## Features

- **Zip Slip Prevention**: Blocks extraction paths that attempt to write outside the intended target directory (`../`).
- **Zip Bomb Defense**: Audits compression ratios and sets uncompressed file size ceilings.
- **Extension Inspection**: Warns users about hidden files and dangerous executable/script extensions.
- **Dual Interface**: Supports both a Command Line Interface (CLI) and a desktop Graphical User Interface (GUI via Tkinter).
- **JSON Security Reporting**: Generates exportable security audit logs for integration with automated workflows.

## Quick Start

### Requirements
- Python 3.8+ (Uses Python standard library)

### Usage

#### 1. Launch GUI Mode
```bash
python archiveguard.py --gui
```

#### 2. Inspect Archive via CLI
```bash
python archiveguard.py path/to/archive.zip
```

#### 3. Inspect and Safely Extract
```bash
python archiveguard.py path/to/archive.zip -x /path/to/destination/
```

#### 4. Export Audit Log to JSON
```bash
python archiveguard.py path/to/archive.zip -j report.json
```

## Security Policy Defaults
- **Maximum Compression Ratio**: `100:1`
- **Maximum Uncompressed Output Limit**: `500 MB`
- **Maximum Single File Size**: `100 MB`
- **Maximum File Count**: `10,000 files`

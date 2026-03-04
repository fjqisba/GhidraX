# Ghidra Decompiler Plugin for IDA 9.0

## Overview
This plugin integrates the PyGhidra decompilation engine into IDA Pro 9.0, providing an alternative decompiler accessible via **Alt+F1**. It creates a pseudocode viewer window similar to Hex-Rays.

## Installation

### Option 1: Plugin (Recommended)
Copy `ghidra_decompiler.py` to your IDA `plugins/` directory:
```
%IDADIR%\plugins\ghidra_decompiler.py
```

### Option 2: Script
Load via `File -> Script file...` and select `ghidra_decompiler.py`.

## Configuration
Edit the following paths at the top of `ghidra_decompiler.py`:

```python
PYGHIDRA_PATH = r"d:\BIGAI\pyghidra\python"  # Path to PyGhidra Python modules
SLA_PATH = r"d:\BIGAI\XGhidra\native\specs\x86.sla"  # Path to SLEIGH spec
```

## Usage
1. Open a binary in IDA Pro 9.0
2. Navigate to any function
3. Press **Alt+F1**
4. A new viewer window opens with the Ghidra-decompiled pseudocode

### Keyboard Shortcuts in Viewer
- **G** — Jump to address
- **ESC** — Close viewer

## Requirements
- IDA Pro 9.0+ with IDAPython
- Python 3.14+ (matching IDA's bundled Python)
- `sleigh_native.pyd` built for your Python version
- x86.sla specification file

## Architecture Support
Currently supports:
- x86-32 (addrsize=1, opsize=1)
- x86-64 (longMode=1, addrsize=2, opsize=2)

## How It Works
1. Extracts function bytes from the IDA database
2. Lifts to P-code via `sleigh_native.pyd` (C++ SLEIGH engine)
3. Builds `Funcdata` with Varnodes and PcodeOps
4. Runs the full decompilation pipeline (136 rules, 62 actions, Heritage SSA)
5. Emits structured C code via PrintC (RPN stack architecture)
6. Displays in a syntax-highlighted custom viewer

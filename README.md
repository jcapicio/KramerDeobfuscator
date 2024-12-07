# KramerDeobfuscator
A deobfuscator designed for [Kramer](https://github.com/billythegoat356/Kramer).

This script utilizes `pycdas.exe` from [pycdc](https://github.com/zrax/pycdc) to extract the byte-code disassembly of a Python file. 

It attempts to automatically retrieve the decryption key and the obfuscated data directly from the byte-code disassembly.

## Usage
```bash
python .\kramer_deobfuscator.py -h
```
## CommandLine Arguments
```text
usage: kramer_deobfuscator.py [-h] -f INPUT_FILE

Deobfuscate Kramer.

options:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --input_file INPUT_FILE
                        Path to the input file for pycdas.
```
## Example
```bash
python .\kramer_deobfuscator.py -f kramer_obf.py
```

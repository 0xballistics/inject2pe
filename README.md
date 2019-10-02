# inject2pe
inject or convert shellcode to PE.

Requires [pefile](https://github.com/erocarrera/pefile) to work. (pip install pefile)

Based on the work at [this post](https://axcheron.github.io/code-injection-with-python/)

A better [shellcode2exe](https://www.aldeid.com/wiki/Shellcode2exe) 

## Usage
python3 inject2pe.py --help


* Convert shellcode to Portable Executable directly:

```bash
python3 inject2pe.py s2e --shellcode <SHELLCODE_BIN_PATH> --output <OUTPUT_EXE_PATH>
```

* Inject shellcode into an existing Portable Executable:
```bash
python3 inject2pe.py i2e --shellcode <SHELLCODE_BIN_PATH> --exe <INPUT_EXE_PATH> --offset <HEX_ENTRY_POINT_OF_SC>--output <OUTPUT_EXE_PATH>
```
! This was particularly useful in a few situations in which shellcode uses modules loaded by the caller malware 

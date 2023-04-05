# Keystone testing for RISC-V

## Prerequisites:

- Installed and added to path `as` and `objdump` tools from [riscv-gnu-toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain) (tested with the Installation (Linux)).
- python packages:
  - capstone >= 5.0.0
  - keystone >= 0.9.3 (install from source, as it is a PR in the main repo, but can also be installed from [null-cell/keystone](https://github.com/null-cell/keystone))
  - qiling (install from [null-cell/qiling](https://github.com/null-cell/qiling) since the Keystone PR hasn't been accepted yet and thus is not supported in qiling)


## Usage:

Copy the contents of the instruction object (MatchTable0 of type MatchEntry) from RISCVGenAsmMatcher.inc to an input file (a sample input file is included in this repo - input_inst.txt)

Then run:
```python
python all_inst_test.py <input file>
```


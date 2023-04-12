# Keystone testing for RISC-V

This is a test script that takes a list of RISCV instructions, their descriptions and parameter requirements as input. Then the following steps are executed:
- parse each line into an Instruction object according to the mnemonic and operand restrictions,
- sort each Instruction depending on the required extensions string (res),
- create an `assembly_tests` folder per res and generate a valid RISCV assembly file for each Instruction in their respective folder,
- assemble every assembly file with RISC-V gcc into the respective object file (keeping the structure of res folders in `object_tests`),
- objdump each object file and save the output into the respective file with the .objdump suffix (again keeping the structure of res folders in objdump_tests),
- iterate the Instruction list of each res again and compare the output of Keystone with that of the objdump,
- keep track of what the differences are and notable gcc/objdump failures, namely:
    - empty objdump:
        - failure of gcc on assembling, one can also see this when running the test
    - objdump contains more than one disassembled instructions:
        - this means that objdump did not successfully combine the two or more instructions back into a single pseudo instruction
        - try to assemble the instructions from objdump with Keystone and compare the resulting machine code with that from objdump (assembled with gcc)
        - save this kind of results separately
    - objdump instruction line is only "...":
        - this is notation for only 0 bytes and is a failed assembler job
    - getting the same mnemonic but different machine (hex) code:
        -  from reading the results, this is usually because objdump references symbols as line numbers, while llvm or Keystone does not recognize a number as a valid symbol and just treats it as an immediate, resulting in a difference in machine code. An example of this is:
```
0000000000000000 <.text>:
0:	00041463          	bne	s0,zero,8 <.text+0x8>
4:	0000006f          	jal	zero,4 <.text+0x4>

Where the test output for assembling `jal zero, 4` in Keystone is `0040006f`. So we can see that Keystone treats the 4 as an immediate while GCC+Objdump treats it as the current line symbol. By changing this to any other symbol name, we can confirm this hypothesis. For example assembling the following in Keystone `sym: jal zero, sym` gets assembled the same as with gcc+objdump - `0000006f`,  while assembling `4: jal zero, 4` produces the Invalid Label error in Keystone. 
```


## Prerequisites:

- Installed and added to path `as` and `objdump` tools from [riscv-gnu-toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain) (tested with the Installation (Linux)).
- python packages:
  - capstone >= 5.0.0
  - keystone >= 0.9.3 (install from [PR](https://github.com/keystone-engine/keystone/pull/549) in the main repo or from [null-cell/keystone](https://github.com/null-cell/keystone))
  - qiling (install from [null-cell/qiling](https://github.com/null-cell/qiling) since the Keystone PR hasn't been accepted yet and thus is not supported in qiling)

## Usage:
Copy the contents of the instruction object (MatchTable0 of type MatchEntry) from RISCVGenAsmMatcher.inc to an input file (a sample input file is included in this repo - input_inst.txt)

Then run:
```python
python all_inst_test.py <input file>
```


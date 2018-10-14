# capstone-d 

A simple header of [capstone](https://www.capstone-engine.org) library. Converted with dstep.

## How to user

in your dub.json

```json
"capstone-d": "master"
```


## Usage

Example program at [documentation](https://www.capstone-engine.org/lang\_c.html).

```d
import std.stdio;
import std.string;
import capstone.capstone;

void main()
{
  const string code = "\x55\x48\x8b\x05\xb8\x13\x00\x00";
  csh handle;
  cs_insn *insn;

  if (cs_open(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64, &handle) != cs_err.CS_ERR_OK) {
    return;
  }
  auto count = cs_disasm(handle, cast(ubyte*)code.ptr, code.length, 0x1000, 0, &insn);
  if (count > 0) {
    foreach (j; 0..count) {
      writefln("0x%x\t%s\t\t%s", insn[j].address, insn[j].mnemonic, insn[j].op_str);
    }
    cs_free(insn, count);
  }
  else {
    throw new Exception("Failed to disassemble given code!");
  }

  cs_close(&handle);
}
```

output is 

```
0x1000	push		rbp
0x1001	mov		rax, qword ptr [rip + 0x13b8]
```

## LISENCE

MIT

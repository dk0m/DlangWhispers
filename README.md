# DlangWhispers

Implementation Of SysWhispers Direct System Call Technique In D.

## Usage
```
$ python gen.py --type direct --functions NtAllocateVirtualMemory,NtProtectVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx --output syscalls.d
```

## Acknowledgement

Thanks to [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) for alot of ideas for this, SysWhispers2's inline assembly has been used in this project.
[KlezVirus](https://github.com/klezVirus/) for the function prototypes JSON file and [SysWhispers3](https://github.com/klezVirus/SysWhispers3/) project.


## Problems With Generator
Due to the nature of C and D structs and them being different, Their conversion can be really tedious, Hence why I only made the generator output function definitions.

# debogus
Deobfuscate OLLVM Bogus Control Flow with angr
## Usage
```
python debogus.py [-h] [-f FILE] [-s START]
```

### Arguments
- `-h, --help`                Show this help message and exit
- `-f FILE, --file FILE`      File to deobfuscate
- `-s START, --start START`   Starting address of target function (Optional, address of `main` function by default)

### Examples
See [test.bat](test.bat) or [test.sh](test.sh)

## Implementation
1. Start symbolic execution from the specified address
2. Iterate through each active state of simulation manager
3. Step the current active state forward to get the successors
4. If there are both sat successors and unsat successors, patch jx/jnx to jmp
5. Step the simulation manager forward and go to step 2
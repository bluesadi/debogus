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
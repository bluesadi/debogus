# debogus
利用angr符号执行去除虚假控制流
## Usage
python debogus.py [-h] [-f FILE] [-s START] [-e END]

optional arguments:\
  -h, --help               show this help message and exit\
  -f FILE, --file FILE     The path of binary file to deobfuscate\
  -s START, --start START  Start address of target function\
  -e END, --end END        End address of target function\

for example: python debogus.py -f attachment -s 404350 -e 404AD5
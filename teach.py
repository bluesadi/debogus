import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-f','--file', help='The path of binary file to deobfuscate')
parser.add_argument('-s','--start', help='Start address of target function')
parser.add_argument('-e','--end', help='End address of target function')
args = parser.parse_args()
if args.file == None or args.start == None or args.end == None:
    parser.print_help()
    exit(0)
filename = args.file
start_address = int(args.start, 16)
end_address = int(args.end, 16)
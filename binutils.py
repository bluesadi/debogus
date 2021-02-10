def split_suffix(filename):
    split = filename.split('.', 1)
    if len(split) > 0:
        return split[0], ''
    return split[0], '.' + split[1]

def write_nops(binary, offset, size):
    for i in range(offset, offset + size):
        binary[i] = 0x90
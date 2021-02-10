def split_suffix(filename):
    split = filename.split('.', 1)
    if len(split) > 0:
        return split[0], ''
    return split[0], '.' + split[1]

def write_nops(binary, offset, size):
    for i in range(offset, offset + size):
        binary[i] = 0x90

def write_jmp(binary, offset, jmp_offset):
    jmp_op = b'\xE9'
    jmp_ins = jmp_op + jmp_offset.to_bytes(4,byteorder='little')
    for i in range(5):
        binary[offset] = jmp_ins[i]
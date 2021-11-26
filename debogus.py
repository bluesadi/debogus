import angr
import argparse
import logging

def patch_jmp(block, jmp_addr):
    insn = block.capstone.insns[-1]
    offset = insn.address - proj.loader.main_object.mapped_base
    # Nop original jx/jnx instruction
    binfile[offset : offset + insn.size] = b'\x90' * insn.size     
    # Patch jmp instruction that jumps to the real successor
    binfile[offset : offset + 5] = b'\xE9' + (jmp_addr - (insn.address + 5)).to_bytes(4, 'little', signed=True)
    print('Patch [%s\t%s] at %#x' % (insn.mnemonic, insn.op_str, insn.address))

def deobfu_func(func_addr):
    # Symbolic execution
    state = proj.factory.blank_state(addr=func_addr)
    simgr = proj.factory.simgr(state)
    while len(simgr.active):
        for active in simgr.active:
            # hook call instructions
            block = proj.factory.block(active.addr)
            for insn in block.capstone.insns:
                if insn.mnemonic == 'call':
                    next_func_addr = int(insn.op_str, 16)
                    proj.hook(next_func_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)
                    print('Hook [%s\t%s] at %#x' % (insn.mnemonic, insn.op_str, insn.address))
            succ = active.step()
            sat = succ.successors
            unsat = succ.unsat_successors
            if len(sat) == 1 and len(unsat) > 0:
                sat_addr = sat[0].addr
                patch_jmp(block, sat_addr)
        simgr.step()

if __name__ == '__main__':
    # Disable warning
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('angr').setLevel(logging.ERROR)
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='File to deobfuscate')
    parser.add_argument('-s', '--start', type=lambda x : int(x, 0), help='Starting address of target function')
    args = parser.parse_args()
    # Load binary file ${file} into angr
    proj = angr.Project(args.file, load_options={"auto_load_libs": False})
    start = args.start
    if start == None:
        main = proj.loader.find_symbol('main')
        if main == None:
            parser.error('Can\'t find the main function, please provide argument -s/--start')
        start = main.rebased_addr
    # Load binary file ${file} into memory
    with open(args.file, 'rb') as file:
        binfile = bytearray(file.read())
    # Do deobfuscation on target function
    deobfu_func(func_addr=start)
    # Write the recovered binary file to ${file}_recovered
    with open(args.file + '_recovered', 'wb') as file:
        file.write(binfile)
    print('Deobfuscation success!')
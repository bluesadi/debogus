import angr
from angrmanagement.utils.graph import to_supergraph
import argparse
import logging
import os

# def patch_jmp(block, jmp_addr):
#     insn = block.capstone.insns[-1]
#     offset = insn.address - proj.loader.main_object.mapped_base
#     # Nop original jx/jnx instruction
#     binfile[offset : offset + insn.size] = b'\x90' * insn.size     
#     # Patch jmp instruction that jumps to the real successor
#     binfile[offset : offset + 5] = b'\xE9' + (jmp_addr - (insn.address + 5)).to_bytes(4, 'little', signed=True)
#     print('Patch [%s\t%s] at %#x' % (insn.mnemonic, insn.op_str, insn.address))
    
def patch_nops(block):
    offset = block.addr - proj.loader.main_object.mapped_base
    binfile[offset : offset + block.size] = b'\x90' * block.size
    print('Patch nop at block %#x' % block.addr)

def get_cfg(func_addr):
    cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function_cfg = cfg.functions.get(func_addr).transition_graph
    super_cfg = to_supergraph(function_cfg)
    return super_cfg

def deobfu_func(func_addr):
    blocks = set()
    cfg = get_cfg(func_addr)
    for node in cfg.nodes:
        blocks.add(node.addr)
    print([hex(b) for b in blocks])
    # Symbolic execution
    state = proj.factory.blank_state(addr=func_addr)
    simgr = proj.factory.simgr(state)
    while len(simgr.active):
        for active in simgr.active:
            blocks.discard(active.addr)
            # hook call instructions
            block = proj.factory.block(active.addr)
            for insn in block.capstone.insns:
                if insn.mnemonic == 'call':
                    next_func_addr = int(insn.op_str, 16)
                    proj.hook(next_func_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)
                    print('Hook [%s\t%s] at %#x' % (insn.mnemonic, insn.op_str, insn.address))
        simgr.step()
    for block_addr in blocks:
        patch_nops(proj.factory.block(block_addr))

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
    fname, ext = os.path.splitext(args.file)
    with open(fname + '_recovered' + ext, 'wb') as file:
        file.write(binfile)
    print('Deobfuscation success!')
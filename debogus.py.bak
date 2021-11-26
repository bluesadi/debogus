import angr
import argparse
from binutils import *

class Deboguser:
    
    def __init__(self, filename, start_address, end_address):
        self.proj = angr.Project(filename, load_options={'auto_load_libs': False})
        self.filename = filename
        self.start_address = start_address
        self.end_address = end_address
        self.target_blocks = set()
        self.control_flow = set()

    def in_function(self,addr):
        return addr >= self.start_address and addr <= self.end_address

    def load_target_blocks(self):
        '''
        加载目标函数的所有代码块到 self.target_blocks
        '''
        cfg = self.proj.analyses.CFGFast()
        self.cfg = cfg.functions.get(self.start_address).transition_graph
        for node in self.cfg.nodes():
            if node.addr >= self.start_address and node.addr <= self.end_address:
                self.target_blocks.add(node)

    def hook(self):
        function_size = self.end_address - self.start_address + 1
        target_block = self.proj.factory.block(self.start_address,function_size)
        for ins in target_block.capstone.insns:
            if ins.mnemonic == 'call':
                self.proj.hook(int(ins.op_str, 16), angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)

    def symbolic_execute(self):
        state = self.proj.factory.blank_state(addr=self.start_address, remove_options={angr.sim_options.LAZY_SOLVES})
        simgr = self.proj.factory.simulation_manager(state)
        self.control_flow.add(state.addr)
        while len(simgr.active) > 0:
            for active in simgr.active:
                self.control_flow.add(active.addr)
            simgr.step()

    def patch_unreachable_blocks(self, data):
        handled_blocks = set()
        patched_addrs = []
        base_address = self.proj.loader.main_object.mapped_base
        for block in self.target_blocks:
            if block.addr in handled_blocks:
                continue
            handled_blocks.add(block.addr)
            if block.addr in self.control_flow:
                for child in self.cfg.successors(block):
                    if child.addr < self.start_address or child.addr > self.end_address:
                        continue
                    if child.addr not in self.control_flow:
                        handled_blocks.add(child.addr)
                        patched_addrs.append(hex(child.addr))
                        write_nops(data, child.addr - base_address, child.size)
            else:
                write_nops(data, block.addr - base_address, block.size)
        print(f'Patched {len(patched_addrs)} unreachable blocks: {patched_addrs}')

    def patch_jump(self, data):
        handled_blocks = set()
        patched_addrs = []
        base_address = self.proj.loader.main_object.mapped_base
        for block in self.target_blocks:
            if block.addr in handled_blocks:
                continue
            handled_blocks.add(block.addr)
            suc = list(self.cfg.successors(block))
            if block.addr in self.control_flow and len(suc) == 2:
                if self.in_function(suc[0].addr) and self.in_function(suc[1].addr):
                    jmp_ins_addr = block.addr + block.size - 6
                    if suc[0].addr in self.control_flow and suc[1].addr not in self.control_flow:
                        write_nops(data, jmp_ins_addr - base_address, 6)
                        write_jmp(data, jmp_ins_addr - base_address, suc[0].addr - jmp_ins_addr - 6)
                        patched_addrs.append(hex(jmp_ins_addr))
                    elif suc[1].addr in self.control_flow and suc[0].addr not in self.control_flow:
                        write_nops(data, jmp_ins_addr - base_address, 6)
                        write_jmp(data, jmp_ins_addr - base_address, suc[0].addr - jmp_ins_addr - 6)
                        patched_addrs.append(hex(jmp_ins_addr))
        print(f'Patched {len(patched_addrs)} jump instructions: {patched_addrs}')


    def patch_binary(self):
        with open(self.filename, 'rb') as inp:
            data = bytearray(inp.read())
        self.patch_unreachable_blocks(data)
        self.patch_jump(data)
        name, suffix = split_suffix(self.filename)
        outpath = name + '_recovered' + suffix
        with open(outpath,'wb') as out:
            out.write(data)
        print(f'Recovered file is saved to: {outpath}')

    def deobfu(self):
        self.load_target_blocks()
        self.hook()
        self.symbolic_execute()
        self.patch_binary()

if __name__ == '__main__':
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

    deboguser = Deboguser(filename=filename,start_address=start_address,end_address=end_address)
    deboguser.deobfu()
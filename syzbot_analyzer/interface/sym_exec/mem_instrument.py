import logging
import math
import archinfo

from angr import SimProcedure
from .symTracing import PropagationHandler
from .stateManager import StateManager
from capstone.x86_const import X86_REG_GS, X86_REG_CS, X86_REG_SS, X86_REG_DS, X86_REG_ES, X86_REG_FS, X86_OP_MEM

class MemInstrument(StateManager):
    USER_PAGE_START = 0x40000000
    USER_PAGE_END = 0x50000000
    PAGE_SIZE = 0x1000
    CTR_ADDR = 0x40000000

    def __init__(self, logger=None):
        StateManager.__init__(self)
        self.ppg_handler = PropagationHandler()
        self.cur_cond_jmp = 0
        self.sections = None
        if logger == None:
            self.logger = logging
        else:
            self.logger = logger
        self._segment_regs = {}
    
    def setup_sections(self, name=None):
        self.sections = {}
        if type(name) == str:
            self.sections[name] = self._get_one_section(name)
        if type(name) == list:
            for each in name:
                self.sections[each] = self._get_one_section(each)
        self.sections = self._get_sections()

    def setup_segment_base(self):
        segment_regs = ['es', 'cs', 'ss', 'ds', 'fs', 'gs', 'ldt', 'tr']
        for reg in segment_regs:
            if self.vm == None:
                return
            val = self.vm.read_reg(reg)
            self._segment_regs[reg] = val
    
    def get_segment_base(self, reg):
        if reg not in self._segment_regs:
            self.logger.warning("{} is not a valid segment registers".format(reg))
        return self._segment_regs[reg]
    
    def is_section(self, addr):
        if self.sections == None:
            self.logger.info("No sections available")
            return False
        for each in self.sections:
            if addr >= self.sections[each]['start'] and addr <= self.sections[each]['end']:
                return True
        return False
    
    def instrument_cond_jump(self, state):
        self.cur_cond_jmp = state.scratch.ins_addr
    
    def exit_point(self, state):
        if state in self.simgr.active:
            self.simgr.active.remove(state)

    def track_mem_read(self, state):
        size = state.inspect.mem_read_length
        self._instrument_mem_read(state, state.inspect.mem_read_address, size)
    
    def track_mem_write(self, state):
        bv_addr = state.inspect.mem_write_address
        bv_expr = state.inspect.mem_write_expr
        addr = state.solver.eval(bv_addr)
        size = state.solver.eval(state.inspect.mem_write_length)
        addr = self._write_to_seg_regs(state, addr)
        if type(bv_addr) != int and bv_addr.symbolic:
            self.logger.warning("Arbitrary write found")
        if self.ppg_handler.is_kasan_write(addr):
            print("Write from vuln mem found")
            if ((type(bv_addr) != int and not bv_addr.symbolic) or type(bv_addr) == int):
                if bv_expr.symbolic:
                    self.ppg_handler.log_symbolic_propagation()
        #b = math.ceil(size/8)
        #n = size - b * 8
        for i in range(0, size):
            self.update_states_globals(addr+i, 0, StateManager.G_MEM)
        #self.dump_state(state)
    
    def track_mem_write_after(self, state):
        bv_addr = state.inspect.mem_write_address
        bv_expr = state.inspect.mem_write_expr
        addr = state.solver.eval(bv_addr)
        size = state.solver.eval(state.inspect.mem_write_length)
        addr = self._write_to_seg_regs(state, addr)
        t = state.memory.load(addr, 1, endness=archinfo.Endness.LE, inspect=False)
        if t.uninitialized:
            print("still uninitialized after writing")
    
    def track_call(self, state):
        if state.regs.rip.symbolic:
            self.logger.warning("Control flow hijack")
            return
        addr = state.solver.eval(state.inspect.function_address)
        #print("call func ",hex(addr))

    def track_instruction(self, state):
        self.logger.warning("trace_instruction")
        self.dump_state(state)
    
    def track_symbolic_variable(self, state):
        self.logger.warning("A new symbolic data: {} size: {} bit".format(state.inspect.symbolic_name, state.inspect.symbolic_size))
    
    def track_irsb(self, state):
        n = 0
        addr = state.scratch.ins_addr
        insns = self.proj.factory.block(addr).capstone.insns
        for each_inst in insns:
            mem_inst = False
            for op in each_inst.operands:
                if op.mem.base == 0 and op.mem.disp == 0 and op.mem.index == 0 and op.mem.scale == 0:
                    continue
                mem_inst = True
            if mem_inst:
                n += 1
        self.update_states_globals(addr, n, StateManager.G_IRSB)

    def dump_state(self, state):
        self.logger.info("rax: is_symbolic: {} {}".format(state.regs.rax.symbolic, hex(state.solver.eval(state.regs.rax))))
        self.logger.info("rbx: is_symbolic: {} {}".format(state.regs.rbx.symbolic, hex(state.solver.eval(state.regs.rbx))))
        self.logger.info("rcx: is_symbolic: {} {}".format(state.regs.rcx.symbolic, hex(state.solver.eval(state.regs.rcx))))
        self.logger.info("rdx: is_symbolic: {} {}".format(state.regs.rdx.symbolic, hex(state.solver.eval(state.regs.rdx))))
        self.logger.info("rsi: is_symbolic: {} {}".format(state.regs.rsi.symbolic, hex(state.solver.eval(state.regs.rsi))))
        self.logger.info("rdi: is_symbolic: {} {}".format(state.regs.rdi.symbolic, hex(state.solver.eval(state.regs.rdi))))
        self.logger.info("rsp: is_symbolic: {} {}".format(state.regs.rsp.symbolic, hex(state.solver.eval(state.regs.rsp))))
        self.logger.info("rbp: is_symbolic: {} {}".format(state.regs.rbp.symbolic, hex(state.solver.eval(state.regs.rbp))))
        self.logger.info("r8: is_symbolic: {} {}".format(state.regs.r8.symbolic, hex(state.solver.eval(state.regs.r8))))
        self.logger.info("r9: is_symbolic: {} {}".format(state.regs.r9.symbolic, hex(state.solver.eval(state.regs.r9))))
        self.logger.info("r10: is_symbolic: {} {}".format(state.regs.r10.symbolic, hex(state.solver.eval(state.regs.r10))))
        self.logger.info("r11: is_symbolic: {} {}".format(state.regs.r11.symbolic, hex(state.solver.eval(state.regs.r11))))
        self.logger.info("r12: is_symbolic: {} {}".format(state.regs.r12.symbolic, hex(state.solver.eval(state.regs.r12))))
        self.logger.info("r13: is_symbolic: {} {}".format(state.regs.r13.symbolic, hex(state.solver.eval(state.regs.r13))))
        self.logger.info("r14: is_symbolic: {} {}".format(state.regs.r14.symbolic, hex(state.solver.eval(state.regs.r14))))
        self.logger.info("r15: is_symbolic: {} {}".format(state.regs.r15.symbolic, hex(state.solver.eval(state.regs.r15))))
        self.logger.info("rip: is_symbolic: {} {}".format(state.regs.rip.symbolic, hex(state.solver.eval(state.regs.rip))))
        self.logger.info("gs: is_symbolic: {} {}".format(state.regs.gs.symbolic, hex(state.solver.eval(state.regs.gs))))
        cap = self.proj.factory.block(state.scratch.ins_addr).capstone
        cap.pp()
    
    def dump_stack(self, state):
        stack = state.solver.eval(state.regs.rsp)
        frame = state.solver.eval(state.regs.rbp)
        

    def hook_noisy_func(self, extra):    
        noisy_func = ["queue_delayed_work_on", "mutex_lock", "mutex_unlock", "__sanitizer_cov_trace_pc", "__sanitizer_cov_trace_switch", \
            "__sanitizer_cov_trace_const_cmp1", "__sanitizer_cov_trace_const_cmp2", "__sanitizer_cov_trace_const_cmp4", "__sanitizer_cov_trace_const_cmp8", \
            "__sanitizer_cov_trace_cmp1", "__sanitizer_cov_trace_cmp2", "__sanitizer_cov_trace_cmp4", "__sanitizer_cov_trace_cmp8", \
            "printk"]
        if type(extra) == list:
            noisy_func.extend(extra)
        if type(extra) == str:
            noisy_func.append(extra)
        for each in noisy_func:
            self.proj.hook_symbol(each, HookInst())
        
        stack_addr = self.vm.stack_addr
        
        kasan = KasanAccess(stack_addr, self)

        if self.proj.loader.find_symbol("kasan_report", True) != None:
            kasan_func_name = "kasan_report"
            self.proj.hook_symbol(kasan_func_name, kasan)
        if self.proj.loader.find_symbol("__kasan_report", True) != None:
            kasan_func_name = "__kasan_report"
            self.proj.hook_symbol(kasan_func_name, kasan)
        
        
        kasan_1_r = KasanRead(size=1, stack_addr=stack_addr, mem_handler=self)
        kasan_2_r = KasanRead(size=2, stack_addr=stack_addr, mem_handler=self)
        kasan_4_r = KasanRead(size=4, stack_addr=stack_addr, mem_handler=self)
        kasan_8_r = KasanRead(size=8, stack_addr=stack_addr, mem_handler=self)
        kasan_16_r = KasanRead(size=16, stack_addr=stack_addr, mem_handler=self)
        kasan_N_r = KasanRead(size=None, stack_addr=stack_addr, mem_handler=self)
        kasan_1_w = KasanWrite(size=1, stack_addr=stack_addr, mem_handler=self)
        kasan_2_w = KasanWrite(size=2, stack_addr=stack_addr, mem_handler=self)
        kasan_4_w = KasanWrite(size=4, stack_addr=stack_addr, mem_handler=self)
        kasan_8_w = KasanWrite(size=8, stack_addr=stack_addr, mem_handler=self)
        kasan_16_w = KasanWrite(size=16, stack_addr=stack_addr, mem_handler=self)
        kasan_N_w = KasanWrite(size=None, stack_addr=stack_addr, mem_handler=self)

        self.proj.hook_symbol("__asan_store1", kasan_1_w)
        self.proj.hook_symbol("__asan_load1", kasan_1_r)
        self.proj.hook_symbol("__asan_store2", kasan_2_w)
        self.proj.hook_symbol("__asan_load2", kasan_2_r)
        self.proj.hook_symbol("__asan_store4", kasan_4_w)
        self.proj.hook_symbol("__asan_load4", kasan_4_r)
        self.proj.hook_symbol("__asan_store8", kasan_8_w)
        self.proj.hook_symbol("__asan_load8", kasan_8_r)
        self.proj.hook_symbol("__asan_store16", kasan_16_w)
        self.proj.hook_symbol("__asan_load16", kasan_16_r)
        self.proj.hook_symbol("__asan_storeN", kasan_N_w)
        self.proj.hook_symbol("__asan_loadN", kasan_N_r)
        
    
    def make_symbolic(self, state, addr, size, name=None):
        if (size <= 8):
            if name == None:
                name = "s_{}".format(hex(addr))
            sym = state.solver.BVS(name, size * 8)
            state.memory.store(addr, sym)
        else:
            index = 0
            while index < size:
                if name == None:
                    name = "s_{}".format(hex(addr+index))
                else:
                    name = "{}_{}".format(name, math.ceil(index / 8))
                if index + 8 > size:
                    size -= index
                sym = state.solver.BVS(name, size * 8)
                state.memory.store(addr, sym)
                index += 8
    
    def transfer_state_globals(self, state, successors):
        if len(successors) == 1:
            successors[0].globals = state.globals
        if len(successors) == 2:
            successors[0].globals = state.globals
            successors[1].globals = state.globals
    
    def _instrument_mem_read(self, state, bv_addr, size):
        uninitialized = False
        addr = state.solver.eval(bv_addr)
        addr = self._read_from_seg_regs(state, addr)
        if type(bv_addr) !=int and bv_addr.symbolic and not self._is_ctr_addr(addr) and self.add_constraints:
            if self._is_ctr_addr(addr):
                return
            try:
                state.solver.add(bv_addr == MemInstrument.CTR_ADDR)
                if state.satisfiable():
                    addr = state.solver.eval(bv_addr)
                    self._updateCtrAddr()
                else:
                    state.se.constraints.pop()
                    state.se.reload_solver()
            except:
                return

        #if self.is_section(addr):
        #    return
        i = 0
        for i in range(0, size):
            if self.get_states_globals(addr+i, StateManager.G_MEM) == None:
                uninitialized = True
                break
        if uninitialized:
            """
            if i != 0:
                self.logger.info("i: {} addr {} -> {}".format(i, hex(addr), hex(addr + i)))
            addr += i
            size -= i
            for j in range(0, size):
                self.update_states_globals(addr+j, 0, StateManager.G_MEM)
            """
            if self._is_ctr_addr(addr):
                self.make_symbolic(state, addr, size)
                self.logger.info("Make symbolic at {}".format(hex(state.scratch.ins_addr)))
                self.update_states_globals(addr, size, StateManager.G_SYM)
            else:
                val = self.vm.read_mem(addr, size)
                #self.logger.info('Store at', hex(addr), ' with value ', val)
                if len(val) > 0:
                    state.memory.store(addr, state.solver.BVV(int(val[0], 16), size*8), endness=archinfo.Endness.LE)
                    #self.dump_state(state)
                elif not self._is_ctr_addr(addr):
                    print("Dump last site")
                    self.dump_state(state)

                    self.logger.warning("page fault occur when access {}".format(hex(addr)))
                    self.purge_current_state()
                    #bv = state.memory.load(addr, size, inspect=False, endness=archinfo.Endness.LE)
                    #self.logger.info(hex(state.solver.eval(bv)))
    
    def _read_from_seg_regs(self, state, addr):
        if self.vm == None:
            return False
        seg_regs = [X86_REG_GS, X86_REG_CS, X86_REG_DS, X86_REG_ES, X86_REG_FS, X86_REG_SS]
        ins_addr = state.scratch.ins_addr
        insns = self.proj.factory.block(ins_addr).capstone.insns
        inst = insns[0]
        if len(inst.operands) == 0:
            return addr
        operands = inst.operands
        if len(inst.operands) > 1:
            operands = inst.operands[1:]
            if len(inst.operands) == 3:
                print("3 operands found")
        for op in operands:
            if op.type == X86_OP_MEM:
                if op.value.reg in seg_regs:
                    base = 0
                    offset = 0
                    reg = inst.reg_name(op.value.reg)
                    if reg != None:
                        base += self.get_segment_base(reg)
                    reg = inst.reg_name(op.mem.base)
                    if  reg != None:
                        bv = getattr(state.regs, reg)
                        val = state.solver.eval(bv)
                        if val != None:
                            offset += val
                            if reg == 'rip' or reg == 'eip':
                                offset += inst.size
                    reg = inst.reg_name(op.mem.index)
                    if  reg != None:
                        bv = getattr(state.regs, reg)
                        val = state.solver.eval(bv)
                        if val != None:
                            offset += val
                            if reg == 'rip' or reg == 'eip':
                                offset += inst.size
                    offset += op.mem.disp
                    addr = base + (offset % (0xffffffffffffffff + 1))
                    
        return addr
    
    def _write_to_seg_regs(self, state, addr):
        if self.vm == None:
            return False
        seg_regs = [X86_REG_GS, X86_REG_CS, X86_REG_DS, X86_REG_ES, X86_REG_FS, X86_REG_SS]
        ins_addr = state.scratch.ins_addr
        insns = self.proj.factory.block(ins_addr).capstone.insns
        if len(insns) == 0:
            return addr
        inst = insns[0]
        if len(inst.operands) == 0:
            return addr
        op = inst.operands[0]
        if op.type == X86_OP_MEM:
            if op.value.reg in seg_regs:
                base = 0
                offset = 0
                reg = inst.reg_name(op.value.reg)
                if reg != None:
                    base += self.get_segment_base(reg)
                reg = inst.reg_name(op.mem.base)
                if  reg != None:
                    bv = getattr(state.regs, reg)
                    val = state.solver.eval(bv)
                    if val != None:
                        offset += val
                        if reg == 'rip' or reg == 'eip':
                            offset += inst.size
                reg = inst.reg_name(op.mem.index)
                if  reg != None:
                    bv = getattr(state.regs, reg)
                    val = state.solver.eval(bv)
                    if val != None:
                        offset += val
                        if reg == 'rip' or reg == 'eip':
                            offset += inst.size
                offset += op.mem.disp
                addr = base + (offset % (0xffffffffffffffff + 1))
                
        return addr

    def _is_ctr_addr(self, addr):
        return addr >= MemInstrument.USER_PAGE_START and addr <= MemInstrument.USER_PAGE_END

    def _updateCtrAddr(self):
        MemInstrument.CTR_ADDR += MemInstrument.PAGE_SIZE
    
    def _get_sections(self):
        if self.vm == None:
            return
        sections = self.vm.read_section()
        return sections
    
    def _get_one_section(self, name):
        if self.vm == None:
            return
        section = self.vm.read_section(name)
        return section
    
    def is_on_stack(self, addr):
        if self.vm == None:
            return
        return self.vm.is_on_stack(addr)

class HookInst(SimProcedure):

    def __init__(self):
        SimProcedure.__init__(self)

    def run(self):
        pass

class KasanAccess(HookInst):
    READ = 0
    WRITE = 1

    def __init__(self, stack_addr :list, mem_handler, size=None, is_write=None):
        self.stack_addr = stack_addr
        self.mem = mem_handler
        self.size = size
        self.is_write = is_write
        HookInst.__init__(self)
    
    def run(self, addr, size, is_write):
        if self.size == None:
            self.size = self.state.solver.eval(size)
        if self.is_write == None:
            self.is_write = self.state.solver.eval(is_write)
        self.kasan_access(addr)
    
    def is_on_stack(self, addr):
        if self.stack_addr[0] == 0 and self.stack_addr[1] == 0:
            self.logger.info("Stack range is unclear")
            return False
        return addr >= self.stack_addr[0] and addr <= self.stack_addr[1]

    def kasan_access(self, addr):
        self.mem.add_constraints = True
        if self.is_write:
            if type(addr) != int and not addr.symbolic and not self.is_on_stack(self.state.solver.eval(addr)) \
                or type(addr) == int and not self.is_on_stack(addr):
                if type(addr) != int:
                    addr = self.state.solver.eval(addr)
                self.mem.ppg_handler.log_kasan_write(addr)
        #self._instrument_mem_read(addr, self.size)
            #print("kasan write inspect {} with {} bytes".format(hex(self.state.solver.eval(addr)), size))
        else:
            #self.mem._instrument_mem_read(self.state, addr, self.size)
            #if type(addr) != int:
            #    addr = self.state.solver.eval(addr)
            print("kasan read inspect {} with {} bytes".format(hex(self.state.solver.eval(addr)), self.size))
        self.mem.add_constraints = False

class KasanRead(KasanAccess):
    def __init__(self, size, stack_addr :list, mem_handler):
        KasanAccess.__init__(self, stack_addr, mem_handler, size, False)

class KasanWrite(KasanAccess):
    def __init__(self, size, stack_addr :list, mem_handler):
        KasanAccess.__init__(self, stack_addr, mem_handler, size, True)
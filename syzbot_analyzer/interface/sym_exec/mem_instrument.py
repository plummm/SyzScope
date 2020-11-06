import math
import archinfo

from angr import SimProcedure
from .symTracing import PropagationHandler
from .stateManager import StateManager

class MemInstrument(StateManager):
    USER_PAGE_START = 0x40000000
    USER_PAGE_END = 0x50000000
    PAGE_SIZE = 0x1000
    CTR_ADDR = 0x40000000

    def __init__(self):
        StateManager.__init__(self)
        self.ppg_handler = PropagationHandler()
        self.cur_cond_jmp = 0
        self.sections = None
    
    def setup_sections(self, name=None):
        self.sections = {}
        if type(name) == str:
            self.sections[name] = self._get_one_section(name)
        if type(name) == list:
            for each in name:
                self.sections[each] = self._get_one_section(each)
        self.sections = self._get_sections()
    
    def is_section(self, addr):
        if self.sections == None:
            print("No sections available")
            return False
        for each in self.sections:
            if addr >= self.sections[each]['start'] and addr <= self.sections[each]['end']:
                return True
        return False
    
    def instrument_cond_jump(self, state):
        self.cur_cond_jmp = state.addr
    
    def exit_point(self, state):
        print(self.ppg_handler.get_symbolic_propagation())
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
        if type(bv_addr) != int and bv_addr.symbolic:
            print("Arbitrary write found")
        if bv_expr.symbolic:
            print("Check here")
        if self.ppg_handler.is_kasan_write(addr) \
            and ((type(bv_addr) != int and not bv_addr.symbolic) or type(bv_addr) == int):
            if bv_expr.symbolic:
                self.ppg_handler.log_symbolic_propagation()
        #b = math.ceil(size/8)
        #n = size - b * 8
        for i in range(0, size):
            self.update_states_globals(addr+i, 0, StateManager.G_MEM)
        #self.dump_state(state)
    
    def trace_call(self, state):
        if state.regs.rip.symbolic:
            print("Control flow hijack")
            return
        addr = state.solver.eval(state.inspect.function_address)
        #print("call func ",hex(addr))

    def trace_instruction(self, state):
        print("trace_instruction")
        self.dump_state(state)
    
    def trace_symbolic_variable(self, state):
        print("A new symbolic data: {} size: {} bit".format(state.inspect.symbolic_name, state.inspect.symbolic_size), state.inspect.symbolic_expr)
        
    def dump_state(self, state):
        print("rax: is_symbolic: {} {}".format(state.regs.rax.symbolic, hex(state.solver.eval(state.regs.rax))))
        print("rbx: is_symbolic: {} {}".format(state.regs.rbx.symbolic, hex(state.solver.eval(state.regs.rbx))))
        print("rcx: is_symbolic: {} {}".format(state.regs.rcx.symbolic, hex(state.solver.eval(state.regs.rcx))))
        print("rdx: is_symbolic: {} {}".format(state.regs.rdx.symbolic, hex(state.solver.eval(state.regs.rdx))))
        print("rsi: is_symbolic: {} {}".format(state.regs.rsi.symbolic, hex(state.solver.eval(state.regs.rsi))))
        print("rdi: is_symbolic: {} {}".format(state.regs.rdi.symbolic, hex(state.solver.eval(state.regs.rdi))))
        print("rsp: is_symbolic: {} {}".format(state.regs.rsp.symbolic, hex(state.solver.eval(state.regs.rsp))))
        print("rbp: is_symbolic: {} {}".format(state.regs.rbp.symbolic, hex(state.solver.eval(state.regs.rbp))))
        print("r8: is_symbolic: {} {}".format(state.regs.r8.symbolic, hex(state.solver.eval(state.regs.r8))))
        print("r9: is_symbolic: {} {}".format(state.regs.r9.symbolic, hex(state.solver.eval(state.regs.r9))))
        print("r10: is_symbolic: {} {}".format(state.regs.r10.symbolic, hex(state.solver.eval(state.regs.r10))))
        print("r11: is_symbolic: {} {}".format(state.regs.r11.symbolic, hex(state.solver.eval(state.regs.r11))))
        print("r12: is_symbolic: {} {}".format(state.regs.r12.symbolic, hex(state.solver.eval(state.regs.r12))))
        print("r13: is_symbolic: {} {}".format(state.regs.r13.symbolic, hex(state.solver.eval(state.regs.r13))))
        print("r14: is_symbolic: {} {}".format(state.regs.r14.symbolic, hex(state.solver.eval(state.regs.r14))))
        print("r15: is_symbolic: {} {}".format(state.regs.r15.symbolic, hex(state.solver.eval(state.regs.r15))))
        print("rip: is_symbolic: {} {}".format(state.regs.rip.symbolic, hex(state.solver.eval(state.regs.rip))))
        print("gs: is_symbolic: {} {}".format(state.regs.gs.symbolic, hex(state.solver.eval(state.regs.gs))))
        cap = self.proj.factory.block(state.addr).capstone
        cap.pp()
    
    def dump_stack(self, state):
        stack = state.solver.eval(state.regs.rsp)
        frame = state.solver.eval(state.regs.rbp)
        

    def hook_noisy_func(self, extra):
        noisy_func = ["check_memory_region", "__kasan_check_read", "__kasan_check_write"]
        if type(extra) == list:
            noisy_func.extend(extra)
        if type(extra) == str:
            noisy_func.append(extra)
        for each in noisy_func:
            self.proj.hook_symbol(each, SkipInst())
        
        stack_addr = self.vm.stack_addr
        kasan_1_r = KasanAccess(1, KasanAccess.READ, stack_addr, self.ppg_handler)
        kasan_2_r = KasanAccess(2, KasanAccess.READ, stack_addr, self.ppg_handler)
        kasan_4_r = KasanAccess(4, KasanAccess.READ, stack_addr, self.ppg_handler)
        kasan_8_r = KasanAccess(8, KasanAccess.READ, stack_addr, self.ppg_handler)
        kasan_16_r = KasanAccess(16, KasanAccess.READ, stack_addr, self.ppg_handler)
        kasan_1_w = KasanAccess(1, KasanAccess.WRITE, stack_addr, self.ppg_handler)
        kasan_2_w = KasanAccess(2, KasanAccess.WRITE, stack_addr, self.ppg_handler)
        kasan_4_w = KasanAccess(4, KasanAccess.WRITE, stack_addr, self.ppg_handler)
        kasan_8_w = KasanAccess(8, KasanAccess.WRITE, stack_addr, self.ppg_handler)
        kasan_16_w = KasanAccess(16, KasanAccess.WRITE, stack_addr, self.ppg_handler)

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
        addr = state.solver.eval(bv_addr)
        if type(bv_addr) !=int and bv_addr.symbolic and not self._is_ctr_addr(addr):
            if self._is_ctr_addr(addr):
                return
            try:
                state.solver.add(bv_addr == MemInstrument.CTR_ADDR)
                if state.satisfiable():
                    addr = state.solver.eval(bv_addr)
            except:
                return
            self._updateCtrAddr()

        if self.is_section(addr):
            return
        i = 0
        try:
            for i in range(0, size):
                self.get_states_globals(addr+i, StateManager.G_MEM)
        except KeyError:
            """
            if i != 0:
                print("i: {} addr {} -> {}".format(i, hex(addr), hex(addr + i)))
            addr += i
            size -= i
            for j in range(0, size):
                self.update_states_globals(addr+j, 0, StateManager.G_MEM)
            """
            if self._is_ctr_addr(addr):
                self.make_symbolic(state, addr, size)
                print("Make symbolic at {}".format(hex(state.addr)))
                self.update_states_globals(addr, size, StateManager.G_SYM)
            else:
                val = self.vm.read_mem(addr, size)
                #print('Store at', hex(addr), ' with value ', val)
                if len(val) > 0:
                    state.memory.store(addr, state.solver.BVV(int(val[0], 16), size*8), endness=archinfo.Endness.LE)
                elif not self._is_ctr_addr(addr):
                    print("page fault occur")
                    self.purge_current_state()
                    #bv = state.memory.load(addr, size, inspect=False, endness=archinfo.Endness.LE)
                    #print(hex(state.solver.eval(bv)))
    
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

class SkipInst(SimProcedure):
    def __init__(self):
        SimProcedure.__init__(self)

    def run(self, addr):
        self.kasan_access(addr)
        return 0
    
    def kasan_access(self, addr):
        pass

class KasanAccess(SkipInst):
    READ = 0
    WRITE = 1

    def __init__(self, size: int, action: int, stack_addr :list, handler):
        self.size = size
        self.action = action
        self.stack_addr = stack_addr
        self.handler = handler
        SkipInst.__init__(self)
    
    def is_on_stack(self, addr):
        if self.stack_addr[0] == 0 and self.stack_addr[1] == 0:
            print("Stack range is unclear")
            return False
        return addr >= self.stack_addr[0] and addr <= self.stack_addr[1]

    def kasan_access(self, addr):
        if self.action == KasanAccess.WRITE:
            if type(addr) != int and not addr.symbolic and not self.is_on_stack(self.state.solver.eval(addr)) \
                or type(addr) == int and not self.is_on_stack(addr):
                if type(addr) != int:
                    addr = self.state.solver.eval(addr)
                print("kasan inspect {} with {} bytes".format(hex(addr), self.size))
                self.handler.log_kasan_write(addr)
        #self._instrument_mem_read(addr, self.size)
        #print("kasan inspect {} with {} bytes".format(hex(self.state.solver.eval(addr)), self.size))
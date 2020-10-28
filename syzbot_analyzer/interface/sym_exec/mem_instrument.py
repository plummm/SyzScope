import math

from angr import SimProcedure

class MemInstrument:
    USER_PAGE_START = 0x40000000
    USER_PAGE_END = 0x50000000
    PAGE_SIZE = 0x1000
    CTR_ADDR = 0x40000000

    def __init__(self):
        self.cur_cond_jmp = 0
        self.sections = None
    
    def setup_sections(self, vm, name=None):
        self.sections = {}
        if type(name) == str:
            self.sections[name] = self._get_one_section(vm, name)
        if type(name) == list:
            for each in name:
                self.sections[each] = self._get_one_section(vm, each)
        self.sections = self._get_sections(vm)
    
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
        if state in self.simgr.active:
            self.simgr.active.remove(state)

    def track_mem_read(self, state):
        size = state.inspect.mem_read_length
        self._instrument_mem_read(state, state.inspect.mem_read_address, size)
    
    def track_mem_write(self, state):
        bv_addr = state.inspect.mem_write_address
        addr = state.solver.eval(bv_addr)
        size = state.solver.eval(state.inspect.mem_write_length)
        if type(bv_addr) != int and bv_addr.symbolic:
            print("Arbitrary write found")
        #print("write to {} with {} bytes, pc = {}".format(hex(addr), size, hex(state.addr)))
        #b = math.ceil(size/8)
        #n = size - b * 8
        if 'mem' not in self.current_state.globals:
            self.current_state.globals['mem'] = {}
        for i in range(0, size):
            self.current_state.globals['mem'][addr+i] = 0
    
    def trace_call(self, state):
        if state.regs.rip.symbolic:
            print("Control flow hijack")
            return
        addr = state.solver.eval(state.inspect.function_address)
        #print("call func ",hex(addr))

    def trace_instruction(self, state):
        print("trace_instruction")
        self.debug_state(state)
    
    def trace_symbolic_variable(self, state):
        print("A new symbolic data: {} size: {} bit".format(state.inspect.symbolic_name, state.inspect.symbolic_size), state.inspect.symbolic_expr)
        
    def debug_state(self, state):
        print("rax: is_symbolic: {} {}".format(state.regs.rax.symbolic, state.solver.eval(state.regs.rax)))
        print("rbx: is_symbolic: {} {}".format(state.regs.rbx.symbolic, state.solver.eval(state.regs.rbx)))
        print("rcx: is_symbolic: {} {}".format(state.regs.rcx.symbolic, state.solver.eval(state.regs.rcx)))
        print("rdx: is_symbolic: {} {}".format(state.regs.rdx.symbolic, state.solver.eval(state.regs.rdx)))
        print("rsi: is_symbolic: {} {}".format(state.regs.rsi.symbolic, state.solver.eval(state.regs.rsi)))
        print("rdi: is_symbolic: {} {}".format(state.regs.rdi.symbolic, state.solver.eval(state.regs.rdi)))
        print("rsp: is_symbolic: {} {}".format(state.regs.rsp.symbolic, state.solver.eval(state.regs.rsp)))
        print("rbp: is_symbolic: {} {}".format(state.regs.rbp.symbolic, state.solver.eval(state.regs.rbp)))
        print("r8: is_symbolic: {} {}".format(state.regs.r8.symbolic, state.solver.eval(state.regs.r8)))
        print("r9: is_symbolic: {} {}".format(state.regs.r9.symbolic, state.solver.eval(state.regs.r9)))
        print("r10: is_symbolic: {} {}".format(state.regs.r10.symbolic, state.solver.eval(state.regs.r10)))
        print("r11: is_symbolic: {} {}".format(state.regs.r11.symbolic, state.solver.eval(state.regs.r11)))
        print("r12: is_symbolic: {} {}".format(state.regs.r12.symbolic, state.solver.eval(state.regs.r12)))
        print("r13: is_symbolic: {} {}".format(state.regs.r13.symbolic, state.solver.eval(state.regs.r13)))
        print("r14: is_symbolic: {} {}".format(state.regs.r14.symbolic, state.solver.eval(state.regs.r14)))
        print("r15: is_symbolic: {} {}".format(state.regs.r15.symbolic, state.solver.eval(state.regs.r15)))
        print("rip: is_symbolic: {} {}".format(state.regs.rip.symbolic, state.solver.eval(state.regs.rip)))
        print("gs: is_symbolic: {} {}".format(state.regs.gs.symbolic, state.solver.eval(state.regs.gs)))
        cap = self.proj.factory.block(state.addr).capstone
        cap.pp()
    
    def hook_noisy_func(self, extra):
        skipInst = SkipInst()
        noisy_func = ["check_memory_region", "check_memory_region", "__kasan_check_write"]
        if type(extra) == list:
            noisy_func.extend(extra)
        if type(extra) == str:
            noisy_func.append(extra)
        for each in noisy_func:
            self.proj.hook_symbol(each, skipInst)
        
        kasan_1 = KasanAccess(1)
        kasan_2 = KasanAccess(2)
        kasan_4 = KasanAccess(4)
        kasan_8 = KasanAccess(8)
        kasan_16 = KasanAccess(16)

        self.proj.hook_symbol("__asan_store1", kasan_1)
        self.proj.hook_symbol("__asan_load1", kasan_1)
        self.proj.hook_symbol("__asan_store2", kasan_2)
        self.proj.hook_symbol("__asan_load2", kasan_2)
        self.proj.hook_symbol("__asan_store4", kasan_4)
        self.proj.hook_symbol("__asan_load4", kasan_4)
        self.proj.hook_symbol("__asan_store8", kasan_8)
        self.proj.hook_symbol("__asan_load8", kasan_8)
        self.proj.hook_symbol("__asan_store16", kasan_16)
        self.proj.hook_symbol("__asan_load16", kasan_16)
        self.proj.hook_symbol("check_memory_region", SkipInst())
        self.proj.hook_symbol("__kasan_check_read", SkipInst())
        self.proj.hook_symbol("__kasan_check_write", SkipInst())
    
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
    
    def update_state_globals(self, state, successors):
        if len(successors) == 1:
            successors[0].globals = state.globals
        if len(successors) == 2:
            successors[0].globals = state.globals
            successors[1].globals = state.globals
    
    def _instrument_mem_read(self, state, bv_addr, size):
        uninitialized_flag = False
        addr = state.solver.eval(bv_addr)
        if bv_addr.symbolic and not self._is_ctr_addr(addr):
            if self._is_ctr_addr(addr):
                return
            try:
                state.solver.add(bv_addr == MemInstrument.CTR_ADDR)
                if state.satisfiable():
                    addr = state.solver.eval(bv_addr)
            except:
                return
            self._updateCtrAddr()
        #t = state.memory.load(bv_addr,size=1,inspect=False)
        #if t.uninitialized:
        #    uninitialized_flag = True
        #if self.state.memory.is_uninitialized_data(addr):
        if (addr < 0x7fffffffffff and not self._is_ctr_addr(addr)) or (self.is_section(addr)):
            return
        i = 0
        try:
            for i in range(0, size):
                self.current_state.globals['mem'][addr+i]
        except KeyError:
            if i != 0:
                print("i: {} addr {} -> {}".format(i, hex(addr), hex(addr + i)))
            addr += i
            size -= i
            #if not uninitialized_flag:
            #    print("uninitialized unsync confirm {} {}, pc = {}".format(hex(addr), size, hex(state.addr)))
            if self._is_ctr_addr(addr):
                self.make_symbolic(state, addr, size)
                print("Make symbolic at {}".format(hex(state.addr)))
                if 'sym' not in self.current_state.globals:
                    self.current_state.globals['sym'] = {}
                self.current_state.globals['sym'][addr] = size
            else:
                val = self.vm.read_mem(addr, size)
                #print('Store at', hex(addr), ' with value ', val)
                if len(val) > 0:
                    state.memory.store(addr, state.solver.BVV(int(val[0], 16), size*8))
    
    def _is_ctr_addr(self, addr):
        return addr >= MemInstrument.USER_PAGE_START and addr <= MemInstrument.USER_PAGE_END

    def _updateCtrAddr(self):
        MemInstrument.CTR_ADDR += MemInstrument.PAGE_SIZE
    
    def _get_sections(self, vm):
        vm.waitfor_pwndbg()
        sections = vm.kernel.getSections()
        return sections
    
    def _get_one_section(self, vm, name):
        vm.waitfor_pwndbg()
        section = vm.kernel.getSection(name)
        return section

class SkipInst(SimProcedure):
    def __init__(self):
        SimProcedure.__init__(self)

    def run(self, addr):
        self.kasan_access(addr)
        return 0
    
    def kasan_access(self, addr):
        pass

class KasanAccess(SkipInst, MemInstrument):
    def __init__(self, size: int):
        self.size = size
        MemInstrument.__init__(self)
        SkipInst.__init__(self)

    def kasan_access(self, addr):
        pass
        #self._instrument_mem_read(addr, self.size)
        #print("kasan inspect {} with {} bytes".format(hex(self.state.solver.eval(addr)), self.size))
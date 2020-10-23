import math

from angr import SimProcedure

class MemInstrument:
    USER_PAGE_START = 0x40000000
    USER_PAGE_END = 0x50000000
    PAGE_SIZE = 0x1000
    CTR_ADDR = 0x40000000

    def __init__(self):
        self.ctr_addr = MemInstrument.USER_PAGE_START

    def instrumen_mem_read(self, bv_addr, size):
        addr = self.state.solver.eval(bv_addr)
        if bv_addr.symbolic:
            if self.is_ctr_addr(addr):
                return
            try:
                self.state.solver.add(bv_addr == MemInstrument.CTR_ADDR)
                addr = self.state.solver.eval(bv_addr)
            except:
                return
            self.updateCtrAddr()
        t = self.state.memory.load(bv_addr,size=1,inspect=False)
        if t.uninitialized:
            print('Read from', hex(addr), 'size', size)
            print('Call instruction at:', hex(self.state.addr))
            if self.is_ctr_addr(addr):
                self.make_symbolic(self.state, addr, size)
            else:
                val = self.vm.read_mem(addr, size)
                if len(val) > 0:
                    self.current_state.memory.store(addr, self.current_state.solver.BVV(int(val[0], 16), size*8))

    def track_mem_read(self, state):
        self.state = state
        size = state.inspect.mem_read_length
        self.instrumen_mem_read(state.inspect.mem_read_address, size)
    
    def trace_call(self, state):
        kasan_func = [0xffffffff815b4de0, 0xffffffff815b4ce0, 0xffffffff815b4be0, 0xffffffff815b4b40, 0xffffffff815b4f00, 
                      0xffffffff815b4b90, 0xffffffff815b4c60, 0xffffffff815b4d60, 0xffffffff815b4e70, 0xffffffff815b4f80]
        if state.regs.rip.symbolic:
            print("Control flow hijack")
            return
        addr = state.solver.eval(state.inspect.function_address)
        #rip = state.solver.eval(state.regs.rip)
        #if addr in kasan_func:
        #    self.proj.hook(rip, self.nothing, length=5)
        print("call func ",hex(addr))

    def trace_instruction(self, state):
        print("trace_instruction")
        t = state.memory.load(state.regs.rbx, size=1, inspect=False)
        print("symbolic {}".format(t.symbolic))
        self.debug_state(state)

    def trace_fork(self, state):
        print("trace_fork")
        self.debug_state(state)
    
    def trace_symbolic_variable(self, state):
        print("A new symbolic variable was created: name: {} size: {} bit".format(state.inspect.symbolic_name, state.inspect.symbolic_size), state.inspect.symbolic_expr)
        
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
    
    def is_ctr_addr(self, addr):
        return addr >= MemInstrument.USER_PAGE_START and addr <= MemInstrument.USER_PAGE_END

    def updateCtrAddr(self):
        MemInstrument.CTR_ADDR += MemInstrument.PAGE_SIZE
    
    def hook_kasan_access(self):
        """skipInst = SkipInst()
        kasan_func = ["__asan_store1", "__asan_store2", "__asan_store4", "__asan_store8", "__asan_store16",
                      "__asan_load1", "__asan_load2", "__asan_load4", "__asan_load8", "__asan_load16"]
        for each in kasan_func:
            self.proj.hook_symbol(each, skipInst)
        """
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
    
    def make_symbolic(self, state, addr, size, name=None):
        if (size <= 8):
            if name == None:
                name = "s_{}".format(hex(addr))
            sym = state.solver.BVS(name, size * 8)
            state.memory.store(addr, sym, inspect=False)
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
                state.memory.store(addr, sym, inspect=False)
                index += 8
    
    def nothing(self, state):
        print("do nothing")

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
        self.instrumen_mem_read(addr, self.size)
        #print("kasan inspect {} with {} bytes".format(hex(self.state.solver.eval(addr)), self.size))
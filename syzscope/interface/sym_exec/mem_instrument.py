from cgitb import Hook
import logging
import math
import archinfo

from angr import SimProcedure, SimValueError, SimUnsatError
from pwn import *
from .symTracing import PropagationHandler
from .stateManager import StateManager
from capstone.x86_const import X86_REG_GS, X86_REG_CS, X86_REG_SS, X86_REG_DS, X86_REG_ES, X86_REG_FS, X86_OP_MEM

class MemInstrument(StateManager):
    USER_PAGE_START = 0x20000000
    USER_PAGE_END = 0x80000000
    MAX_OBJ_SIZE = 0x2000
    CTR_ADDR = 0x30000000

    def __init__(self, index, workdir, logger=None):
        StateManager.__init__(self, index, workdir)
        self.ppg_handler = PropagationHandler()
        self.sections = None
        if logger == None:
            self.logger = logging
        else:
            self.logger = logger
        self._segment_regs = {}
        self.counter = 0
    
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
    
    def exit_point(self, state):
        self.kill_current_state = True

    def track_mem_read(self, state):
        size = state.inspect.mem_read_length
        self._instrument_mem_read(state, state.inspect.mem_read_address, size)
    
    def track_mem_write(self, state):
        bv_addr = state.inspect.mem_write_address
        bv_expr = state.inspect.mem_write_expr
        if self.is_symbolic(bv_addr) or self.is_symbolic(bv_expr):
            self.reset_state_bb()
        addr = state.solver.eval(bv_addr)
        if not state.solver.unique(bv_addr):
            state.solver.add(bv_addr == addr)
        size = len(bv_expr) // 8
        stack = state.solver.eval(state.regs.rsp)
        frame = state.solver.eval(state.regs.rbp)
        if addr > frame or addr < stack: 
            # Finite address write includes write to UAF/OOB memory(addr is concrete but addr point to UAF/OOB memory)
            # or write to an address that comes from UAF/OOB memory(addr is symbolic)
            if addr >= self.vul_mem_start and addr <= self.vul_mem_end and state.solver.unique(bv_addr):
                self.wrap_high_risk_state(state, StateManager.OOB_UAF_WRITE)
            if self.is_symbolic(bv_addr) and state.scratch.ins_addr not in self.exploitable_state:
                if self._is_arbitrary_value(bv_addr):
                    self.wrap_high_risk_state(state, StateManager.ARBITRARY_ADDR_WRITE, bv_addr)
                else:
                    self.wrap_high_risk_state(state, StateManager.FINITE_ADDR_WRITE, bv_addr)
            if self.is_symbolic(bv_expr) and state.scratch.ins_addr not in self.exploitable_state:
                if self._is_arbitrary_value(bv_expr):
                    self.wrap_high_risk_state(state, StateManager.ARBITRARY_VALUE_WRITE, bv_expr)
                else:
                    self.wrap_high_risk_state(state, StateManager.FINITE_VALUE_WRITE, bv_expr)
        if not self._validate_inst(state):
            return
        if self.symbolic_tracing and self.ppg_handler.is_kasan_write(addr):
            if self.is_symbolic(bv_expr) and not self.is_symbolic(bv_addr) and state.solver.eval(bv_addr) not in state.globals['sym']:
                self.dump_stack(state)
                #self.ppg_handler.log_symbolic_propagation(state, stack)
                    #self.dump_state(state)
        for i in range(0, size):
            self.update_states_globals(addr+i, 0, StateManager.G_MEM)
            if self.is_symbolic(bv_expr):
                self.update_states_globals(addr+i, 1, StateManager.G_SYM)
    
    def track_call(self, state):
        if state.regs.rip.symbolic and state.solver.unique(state.regs.rip) and state.scratch.ins_addr not in self.exploitable_state:
            self.wrap_high_risk_state(state, StateManager.CONTROL_FLOW_HIJACK)
            return

    def track_instruction(self, state):
        self.logger.warning("trace_instruction")
        self.counter+=1
        self.dump_state(state)
    
    def track_symbolic_variable(self, state):
        self.logger.warning("A new symbolic data: {} size: {} bit".format(state.inspect.symbolic_name, state.inspect.symbolic_size))
        self.dump_state(state)
        self.dump_stack(state)
        self.dump_trace(state)
        self.purge_current_state()
    
    def track_contraint(self, state):
        self.logger.warning("A new constraint {} added at {}".format(state.inspect.added_constraints, hex(state.addr)))

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
        #self.update_states_globals(addr, n, StateManager.G_IRSB)

    def hook_noisy_func(self, extra):    
        kcov_funcs = ["__sanitizer_cov_trace_pc", "__sanitizer_cov_trace_switch", \
            "__sanitizer_cov_trace_const_cmp1", "__sanitizer_cov_trace_const_cmp2", "__sanitizer_cov_trace_const_cmp4", "__sanitizer_cov_trace_const_cmp8", 
            "__sanitizer_cov_trace_cmp1", "__sanitizer_cov_trace_cmp2", "__sanitizer_cov_trace_cmp4", "__sanitizer_cov_trace_cmp8",\
            "write_comp_data", ] 
        noisy_func = ["__kasan_check_read", "__kasan_check_write", "kasan_report_double_free", "kasan_report_invalid_free", "kasan_report_error", "kasan_check_read", "kasan_check_write", \
            "kasan_unpoison_shadow", "kasan_slab_free", "queue_delayed_work_on", "pvclock_read_wallclock","mutex_lock", "__mutex_lock", "mutex_unlock", "__mutex_unlock", \
            "record_times", "update_rq_clock", "sched_clock_idle_sleep_event", "print_tainted", "might_sleep", "__might_sleep", "debug_lockdep_rcu_enabled",\
            "__warn_printk", "srm_printk", "snd_printk", "dbgp_printk", "ql4_printk", "printk", "vprintk", "__dump_page", "irq_stack_union", \
            "queued_spin_lock_slowpath", "__pv_queued_spin_lock_slowpath", "queued_read_lock_slowpath", "queued_write_lock_slowpath", \
            "preempt_schedule_common", "schedule_idle", "schedule", "preempt_schedule_irq", "preempt_schedule_notrace", \
            "lock_acquire", "lock_release", "dump_stack", "__pv_queued_spin_unlock_slowpath", "save_stack", "check_memory_region",\
            "set_next_entity", "__schedule", "native_write_msr", "prepare_to_wait_event", "synchronize_rcu"]
        noisy_func.extend(kcov_funcs)
        
        if type(extra) == list:
            noisy_func.extend(extra)
        if type(extra) == str:
            noisy_func.append(extra)
        for each in noisy_func:
            if self.proj.loader.find_symbol(each, True) != None:
                ret = self.proj.hook_symbol(each, HookInst())
                if ret != None:
                    self.logger.info("Hook {} at {}".format(each, hex(ret)))
        
        stack_addr = self.vm.stack_addr
        
        kasan = KasanAccess(stack_addr, self)
        memcpy = MemCopy(mem_handler=self)
        kfree = Kfree(mem_handler=self)

        self._hook_kernel_func("kasan_report", kasan)
        self._hook_kernel_func("__kasan_report", kasan)
        self._hook_kernel_func("memcpy", memcpy)
        self._hook_kernel_func("__memcpy", memcpy)
        self._hook_kernel_func("kfree", kfree)
        
        
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
    
    def skip_insn(self, addr, insn_len):
        def nothing(state):
            pass
        self.proj.hook(addr, nothing, length=insn_len)
    
    def make_symbolic(self, state, addr, size, name=None):
        if size <= 8:
            if name == None:
                name = "s_{}".format(hex(addr))
            sym = state.solver.BVS(name, size * 8, inspect=False)
            for i in range(0, size):
                self.update_states_globals(addr+i, 0, StateManager.G_MEM)
                self.update_states_globals(addr+i, 1, StateManager.G_SYM)
            state.memory.store(addr, sym, inspect=False, endness=archinfo.Endness.LE)
        else:
            index = 0
            while index < size:
                alignment = self.vm.addr_bytes
                if name == None:
                    name = "s_{}".format(hex(addr+index))
                else:
                    name = "{}_{}".format(name, math.ceil(index / 8))
                sym = state.solver.BVS(name, alignment * 8, inspect=False)
                for i in range(0, alignment):
                    self.update_states_globals(addr+index+i, 0, StateManager.G_MEM)
                    self.update_states_globals(addr+index+i, 1, StateManager.G_SYM)
                state.memory.store(addr+index, sym, inspect=False, endness=archinfo.Endness.LE)
                index += 8
    
    def transfer_state_globals(self, state, successors):
        for i in range(0, len(successors)):
            if 'sym' in state.globals:
                successors[i].globals['sym'] = state.globals['sym'].copy()
            if 'mem' in state.globals:
                successors[i].globals['mem'] = state.globals['mem'].copy()
            if 'ret' in state.globals:
                successors[i].globals['ret'] = state.globals['ret'].copy()
            if 'bb' in state.globals:
                successors[i].globals['bb'] = state.globals['bb'] + 1
            if 'out_loop' in state.globals:
                successors[i].globals['out_loop'] = state.globals['out_loop']
                if successors[i].globals['out_loop'] and successors[i] not in self.out_loop_states:
                    self.out_loop_states.append(successors[i])
    
    def _instrument_mem_read(self, state, bv_addr, size):
        addrs = []
        if self.is_symbolic(bv_addr):
            self.reset_state_bb()
        single_addr = state.solver.eval(bv_addr)
        if state.solver.unique(bv_addr):
            addrs.append(single_addr)
        else:
            if self.add_constraints:
                if self._is_ctr_addr(single_addr):
                    state.solver.add(bv_addr == single_addr)
                    addrs.append(single_addr)
                else:
                    if state.solver.solution(bv_addr, MemInstrument.CTR_ADDR):
                        state.solver.add(bv_addr == MemInstrument.CTR_ADDR)
                        addrs.append(MemInstrument.CTR_ADDR)
                        self._updateCtrAddr()
                    else:
                        state.solver.add(bv_addr == single_addr)
                        addrs.append(single_addr)
            else:
                propagate_addr = True
        
        for addr in addrs:
            i = 0
            uninitialized = False
            propagate_addr = False
            for i in range(0, size):
                if self.get_states_globals(addr+i, StateManager.G_MEM) == None:
                    uninitialized = True
                    break
            if uninitialized:
                if self._is_ctr_addr(addr):
                    self.make_symbolic(state, addr, size)
                    self.logger.info("Make symbolic at {}".format(hex(state.scratch.ins_addr)))
                else:
                    val = self.vm.read_mem(addr, size)
                    #self.logger.info('Store at', hex(addr), ' with value ', val)
                    if len(val) > 0:
                        if not propagate_addr:
                            for each in val:
                                group = len(val)
                                for i in range(0, size):
                                    self.update_states_globals(addr+i, 0, StateManager.G_MEM)
                                
                                state.memory.store(addr, state.solver.BVV(each, round(size/group)*8), inspect=False, endness=archinfo.Endness.LE)
                                self._current_state.memory.store(addr, state.solver.BVV(each, round(size/group)*8), inspect=False, endness=archinfo.Endness.LE)
                        else:
                            self.make_symbolic(state, addr, size)
                            bv = state.memory.load(addr, size, inspect=False, endness=archinfo.Endness.LE)
                            state.solver.add(bv == val[0])
                        #self.dump_state(state)
                    elif not self._is_ctr_addr(addr):
                        self.logger.warning("page fault occur when access {}".format(hex(addr)))
                        self.logger.warning("Dump last site: {}".format(state.addr))
                        if self.is_symbolic(bv_addr):
                            self.logger.info("read from a symbolic address")
                            #self.dump_state(state)
                            #self.dump_stack(state)
                            #self.dump_trace(state)
                        self.purge_current_state()
                        self.dump_state(state)
                        self.dump_stack(state)
                        # In case that unconstrained symbolic variable pop up
                        self.make_symbolic(state, addr, size)
        return
    
    def is_symbolic(self, bv):
        return type(bv) != int and bv.symbolic
    
    def _hook_kernel_func(self, func_name, hook_class):
        if self.proj.loader.find_symbol(func_name, True) != None:
            ret = self.proj.hook_symbol(func_name, hook_class)
            if ret != None:
                self.logger.info("Hook {} at {}".format(func_name, hex(ret)))
                return True
        return False

    def _validate_inst(self, state):
        ins_addr = state.scratch.ins_addr
        insns = self.proj.factory.block(ins_addr).capstone.insns
        inst = insns[0]
        if 'rep' in inst.mnemonic:
            return state.solver.eval(state.regs.rcx) != 0xffffffffffffffff
        return True

    def _access_seg_regs(self, state, addr, is_write):
        if self.vm == None:
            return False
        seg_regs = [X86_REG_GS, X86_REG_CS, X86_REG_DS, X86_REG_ES, X86_REG_FS, X86_REG_SS]
        ins_addr = state.scratch.ins_addr
        insns = self.proj.factory.block(ins_addr).capstone.insns
        inst = insns[0]
        if len(inst.operands) == 0:
            return addr
        operands = inst.operands
        if len(operands) > 1:
            operands = inst.operands[1:]
            if len(inst.operands) == 3:
                print("3 operands found")
        if is_write:
            operands = inst.operands[:1]
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
                            offset += val * op.mem.scale
                            if reg == 'rip' or reg == 'eip':
                                offset += inst.size
                    offset += op.mem.disp
                    addr = base + (offset % (0xffffffffffffffff + 1))
                    
        return addr

    def _is_ctr_addr(self, addr):
        return addr >= MemInstrument.USER_PAGE_START and addr <= MemInstrument.USER_PAGE_END

    def _updateCtrAddr(self):
        MemInstrument.CTR_ADDR += MemInstrument.MAX_OBJ_SIZE
    
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
        return

class Kfree(HookInst):
    def __init__(self, mem_handler):
        HookInst.__init__(self)
        self.mem = mem_handler
    
    def run(self, obj):
        addr = self.state.solver.eval(obj)
        if self.mem.is_symbolic(obj) or \
                addr >= self.mem.vul_mem_start and addr <= self.mem.vul_mem_end and self.state.solver.unique(obj):
            self.mem.wrap_high_risk_state(self.state, StateManager.INVALID_FREE)

class MemCopy(HookInst):
    def __init__(self, mem_handler):
        HookInst.__init__(self)
        self.mem = mem_handler
    
    def run(self, bv_des, bv_src, bv_size):
        des = self.state.solver.eval(bv_des)
        size = self.state.solver.eval(bv_size)
        if self.mem.is_symbolic(bv_src):
            if self.mem.is_symbolic(bv_size):
                prim_logger = self.mem.wrap_high_risk_state(self.state, StateManager.ARBITRARY_VALUE_WRITE)
                if prim_logger != None:
                    prim_logger.warning("Size of memcpy is controllable")
                slab = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 1024*2]
                base_size = 1024*2
                for each_slab in slab:
                    if self.state.solver.solution(bv_size, each_slab):
                        base_size = each_slab
                    elif base_size != 1024*2:
                        break
                self.mem.make_symbolic(self.state, des, base_size)
                #self.mem.purge_current_state()
            else:
                self.mem.make_symbolic(self.state, des, size)
            return
        src = self.state.solver.eval(bv_src)
        if type(src) == int and src in self.state.globals['sym']:
            if self.mem.is_symbolic(bv_size):
                prim_logger = self.mem.wrap_high_risk_state(self.state, StateManager.ARBITRARY_VALUE_WRITE)
                if prim_logger != None:
                    prim_logger.warning("Size of memcpy is controllable")
            # Is is possible that src is in the middle of a sym address?
            # globals['sym'] has unit as field, not byte
            index = 0
            alignment_size = self.mem.vm.addr_bytes
            while index < size:
                if src+index in self.state.globals['sym']:
                    sym_size = self.state.globals['sym'][src+index]
                    sym = self.state.memory.load(src+index, sym_size, inspect=False, endness=archinfo.Endness.LE)
                    for i in range(0, sym_size):
                        self.mem.update_states_globals(des+index+i, 0, StateManager.G_MEM)
                        self.mem.update_states_globals(des+index+i, i, StateManager.G_SYM)
                    self.state.memory.store(des+index, sym, inspect=False, endness=archinfo.Endness.LE)
                    index += sym_size
                else:
                    val = self.state.memory.load(src+index, alignment_size, endness=archinfo.Endness.LE)
                    if self.mem.is_symbolic(val):
                        print("Something wrong")
                    self.state.memory.store(des+index, val, endness=archinfo.Endness.LE)
                    index += alignment_size

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
        stack = self.state.solver.eval(self.state.regs.rsp)
        frame = self.state.solver.eval(self.state.regs.rbp)
        if self.mem.vm.addr_bytes == 4:
            stack = self.state.solver.eval(self.state.regs.esp)
            frame = self.state.solver.eval(self.state.regs.ebp)
        return addr >= stack-0x1000 and addr <= frame+0x1000

    def kasan_access(self, addr):
        #self.mem.add_constraints = True
        if self.is_write and self.mem.symbolic_tracing:
            if not self.mem.is_symbolic(addr) and not self.is_on_stack(self.state.solver.eval(addr)):
                if type(addr) != int:
                    addr = self.state.solver.eval(addr)
                self.mem.ppg_handler.log_kasan_write(addr)
        #self._instrument_mem_read(addr, self.size)
            #print("kasan write inspect {} with {} bytes".format(hex(self.state.solver.eval(addr)), size))
            #self.mem._instrument_mem_read(self.state, addr, self.size)
            #if type(addr) != int:
            #    addr = self.state.solver.eval(addr)
            #self.logger.info("kasan read inspect {} with {} bytes".format(hex(self.state.solver.eval(addr)), self.size))
        #self.mem.add_constraints = False

class KasanRead(KasanAccess):
    def __init__(self, size, stack_addr :list, mem_handler):
        KasanAccess.__init__(self, stack_addr, mem_handler, size, False)

class KasanWrite(KasanAccess):
    def __init__(self, size, stack_addr :list, mem_handler):
        KasanAccess.__init__(self, stack_addr, mem_handler, size, True)
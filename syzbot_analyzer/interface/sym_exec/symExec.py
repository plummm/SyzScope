import logging
from syzbot_analyzer.interface.sym_exec.stateManager import StateManager
import time
import angr
import math
import threading
import archinfo
import syzbot_analyzer.interface.utilities as utilities

from syzbot_analyzer.interface.vm import VM
from math import e
from syzbot_analyzer.interface.vm.error import QemuIsDead
from .mem_instrument import MemInstrument
from .error import VulnerabilityNotTrigger, ExecutionError, AbnormalGDBBehavior

class SymExec(MemInstrument):
    def __init__(self, index, sections=None, logger=None, debug=False):
        MemInstrument.__init__(self, index, logger)
        self.debug = debug
        self.vul_mem_offset = None
        self.vul_mem_size = None
        self.vul_mem_start = None
        self.vul_mem_end = None
        self.target_site = None
        self.path = None
        self.extra_noisy_func = None
        self.gdb_port = None
        self.mon_port = None
        self.vm = None
        self.proj = None
        self.simgr = None
        self._branch = None
        self._init_state = None
        self._timeout=None
        self.cus_sections = sections
        if logger == None:
            self.logger = logging
        else:
            self.logger = logger

    def setup_vm(self, linux, arch, port, image, gdb_port, mon_port, hash_tag, proj_path='/tmp/', mem="2G", cpu="2", key=None, opts=None, log_name="vm.log", log_suffix="", logger=None, timeout=None):
        self.gdb_port = gdb_port
        self.mon_port = mon_port
        if timeout != None:
            self._timeout = timeout
        self.vm = VM(linux=linux, arch=arch, port=port, image=image, proj_path=proj_path, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, mon_port=mon_port, opts=opts, log_name=log_name, log_suffix=log_suffix, hash_tag=hash_tag, debug=self.debug, timeout=timeout, logger=logger)
    
    def cleanup(self):
        if self.vm != None:
            self.vm.kill()

    def setup_bug_capture(self, offset, size, vuln_site=None, target_site=None, path = [], extra_noisy_func=None):
        self.vul_mem_offset = offset
        self.vul_mem_size = size
        self.vuln_site = vuln_site
        self.target_site = target_site
        self.path = path
        self.extra_noisy_func = extra_noisy_func

    def run_vm(self):
        if self.vm == None:
            self.logger.error("Call setup_vm() to initialize the vm first")
            return
        # launch qemu
        p = self.vm.run()
        # connect qemu with gdb, set breakpoint at kasan_report()
        self.logger.info("Loading kernel into angr")
        self.vm.gdb_connect(self.gdb_port)
        if not self.vm.set_checkpoint():
            self.logger.error("No kasan_report() found")
            return None
        self.proj = self.vm.kernel.proj
        self.logger.info("Waiting for qemu launching")
        while True:
            if self.vm.qemu_ready:
                break
            poll = p.poll()
            if poll != None:
                raise QemuIsDead
            time.sleep(1)
        self.vm.mon_connect(self.mon_port)
        """
        with p.stdout:
            for line in iter(p.stdout.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    continue
                self.logger.info(line)
                if utilities.regx_match('syzkaller', line):
                    break
        """
        return p

    def run_sym(self, raw_tracing=False, timeout=60*10):
        if timeout > self._timeout:
            self.logger.warning("Timeout of symbolic execution is longer than timeout of qemu")
        self._timeout = timeout
        if self.vm == None:
            self.logger.error("Call setup_vm() to initialize the vm first")
            raise VulnerabilityNotTrigger
        if self.vul_mem_offset == None:
            self.logger.error("Call setup_bug_capture() to initialize vulnerability information")
            raise VulnerabilityNotTrigger
        self.vm.lock_thread()
        vul_mem = self._read_vul_mem()
        if vul_mem == None:
            self.logger.error("vulnerable oject addr is incorrect: {}".format(vul_mem))
            raise VulnerabilityNotTrigger   
        self.vul_mem_start = vul_mem - self.vul_mem_offset
        self.vul_mem_end = self.vul_mem_start + self.vul_mem_size
        self.logger.info("Vuln mem: {} to {}".format(hex(self.vul_mem_start), hex(self.vul_mem_end)))
        # set a breakpoint at vulnerable site, resume the qemu
        # self.vm.reach_vul_site(self.vuln_site)
        self.vm.back_to_kasan_ret()
        return self.symbolic_execute(self.target_site, self.path, raw_tracing)
    
    def symbolic_execute(self, target_site, path, raw_tracing=False):
        extras = {angr.options.REVERSE_MEMORY_NAME_MAP,
                  angr.options.TRACK_ACTION_HISTORY,
                  #angr.options.CONSERVATIVE_READ_STRATEGY,
                  angr.options.KEEP_IP_SYMBOLIC,
                  angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                  angr.options.REGION_MAPPING,
                  angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        self._init_state = self.proj.factory.blank_state(addr=0, add_options=extras)
        self.setup_current_state(self._init_state)
        self._after_gdb_resume(300)
        self._prepare_context()
        self._restore_memory()
        self._restore_registers()
        self._symbolize_vuln_mem(raw_tracing)
        if len(self._init_state.globals['sym']) == 0:
            return None
        self._hookup_path(path)
        ret = self._explore(target_site, raw_tracing)
        return ret

    def _explore(self, target_site, raw_tracing):
        self.logger.info("Initial state explore at {}".format(hex(self._init_state.addr)))
        self.hook_noisy_func(self.extra_noisy_func)

        last_state = 0
        flag_stop = False
        self.get_current_state().inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_mem_read)
        self.get_current_state().inspect.b('mem_write', when=angr.BP_BEFORE, action=self.track_mem_write)
        #self.get_current_state().inspect.b('instruction', when=angr.BP_BEFORE, action=self.track_instruction, instruction=0xffffffff84179a80)
        self.get_current_state().inspect.b('symbolic_variable', when=angr.BP_AFTER, action=self.track_symbolic_variable)

        ok, err = self.init_simgr(raw_tracing)
        if not ok:
            self.logger.error(err)
            return self.state_privilege

        start_time = time.time()

        while True:
            if self._timeout != None:
                current_time = time.time()
                #self.logger.info("time left: {}".format(current_time - start_time))
                if current_time - start_time > self._timeout:
                    self.logger.info("Timeout, stop symbolic execution")
                    return self.state_privilege

            if len(self.simgr.active) == 1:
                cur_state = self.get_state_index(self.get_current_state())
                if last_state != cur_state:
                    self.logger.info("Switch state {} to state {}".format(last_state, cur_state))
                    last_state = cur_state

            #try:
                self.simgr.step(successor_func=self._my_successor_func)
            #except Exception as e:
             #   self.logger.info("Unexpected error occur: {}".format(str(e)))
              #  raise ExecutionError
            
            if self.debug and len(self.simgr.active) > 0:
                #self.logger.info("=======dump========")
                insns = self.proj.factory.block(self.simgr.active[0].addr).capstone.insns
                n = len(insns)
                self.vm.inspect_code(self.simgr.active[0].addr, n)
            
            if len(self.simgr.active) == 0:
                # No dfs no deferred
                if len(self.simgr.deferred) == 0:
                    self.logger.info("No active states")
                    return self.state_privilege

            if self.simgr.unconstrained:
                for each_state in self.simgr.unconstrained:
                    if each_state.regs.rip.symbolic and each_state.satisfiable():
                        self.state_privilege |= StateManager.CONTROL_FLOW_HIJACK
                        self.logger.warning("Control flow hijack found!")
                        for addr in each_state.globals['sym']:
                            size = each_state.globals['sym'][addr]
                            bv = each_state.memory.load(addr, size=size, inspect=False, endness=archinfo.Endness.LE)
                            self.logger.info("addr {} eval to {}".format(hex(addr), hex(each_state.solver.eval(bv))))
                        self.dump_state(each_state)
                        self.dump_stack(each_state)
                        flag_stop = True
            
            if flag_stop:
                return self.state_privilege
    
    def _collect_propogating_results(self):
        self.logger.info("Dump symbolic propagations")
        ret = self.ppg_handler.get_symbolic_propagation()
        for each in ret:
            if type(each) == dict:
                self.logger.info("index: {}  pc: {}  addr: {}".format(each['kasan_write_index'], hex(each['pc']), hex(each['write_to_mem'])))
                t = self.vm.inspect_code(each['pc'], 1)
                self.logger.info(t)
                self.logger.info("stack:")
                for s in each['stack']:
                    self.logger.info(s)
        return ret
    
    def _hookup_path(self, path):
        self._branch = {}
        hooked = []
        for each in path:
            cond = each['cond']
            correct_path = each['correct_path']
            wrong_path = each['wrong_path']
            self._branch[cond] = [correct_path, wrong_path]
            self._init_state.inspect.b('instruction', when=angr.BP_BEFORE, action=self.instrument_cond_jump, instruction=cond)
            if cond == 0 and correct_path == 0 and wrong_path != 0:
                self._init_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.exit_point, instruction=wrong_path)
            """if wrong_path not in hooked:
                self._init_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.instrument_wrong_path, instruction=wrong_path)
                hooked.append(wrong_path)
            if correct_path not in hooked:
                self._init_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.instrument_correct_path, instruction=correct_path)
                hooked.append(correct_path)"""

    def _symbolize_vuln_mem(self, raw_tracing):
        for i in range(0, self.vul_mem_size):
            val = self.vm.read_mem(self.vul_mem_start + i, 1)
            if len(val) == 1:
                self.make_symbolic(self._init_state, self.vul_mem_start + i, 1, "s_obj_{}".format(i))
                if raw_tracing:
                    bv = self._init_state.memory.load(self.vul_mem_start + i, size=1, inspect=False)
                    if not bv.symbolic:
                        self.logger.info("Vulnerable memory ({}) is not symbolic".format(hex(self.vul_mem_start + i)))
                        continue
                    self._init_state.solver.add(bv == val[0])
            else:
                self.logger.info("Vulnerable memory has strange data: {}".format(val))
                return
    
    def _restore_registers(self):
        regs = self.vm.read_regs()
        if self.vm.addr_bytes == 8:
            self._init_state.regs.gs = self._init_state.solver.BVV(self.get_segment_base('gs'), 64)
            #self._init_state.regs.cs = self._init_state.solver.BVV(regs['cs'], 32)
            #self._init_state.regs.ss = self._init_state.solver.BVV(regs['ss'], 32)
            #self._init_state.regs.ds = self._init_state.solver.BVV(regs['ds'], 32)
            self._init_state.regs.fs = self._init_state.solver.BVV(self.get_segment_base('fs'), 64)
            #self._init_state.regs.es = self._init_state.solver.BVV(regs['es'], 32)
            if 'eflags' in regs:
                self._init_state.regs.eflags = self._init_state.solver.BVV(regs['eflags'], 32)
            else:
                raise AbnormalGDBBehavior
            self._init_state.regs.cr0 = self._init_state.solver.BVV(self.vm.read_reg('cr0'), 32)
            self._init_state.regs.cr2 = self._init_state.solver.BVV(self.vm.read_reg('cr2'), 64)
            self._init_state.regs.cr3 = self._init_state.solver.BVV(self.vm.read_reg('cr3'), 64)
            self._init_state.regs.cr4 = self._init_state.solver.BVV(self.vm.read_reg('cr4'), 32)
            self._init_state.regs.cr8 = self._init_state.solver.BVV(self.vm.read_reg('cr8'), 64)
            if self.vm.addr_bytes == 8:
                self._init_state.regs.rax = self._init_state.solver.BVV(regs['rax'], 64)
                self._init_state.regs.rbx = self._init_state.solver.BVV(regs['rbx'], 64)
                self._init_state.regs.rcx = self._init_state.solver.BVV(regs['rcx'], 64)
                self._init_state.regs.rdx = self._init_state.solver.BVV(regs['rdx'], 64)
                self._init_state.regs.rsi = self._init_state.solver.BVV(regs['rsi'], 64)
                self._init_state.regs.rdi = self._init_state.solver.BVV(regs['rdi'], 64)
                self._init_state.regs.rsp = self._init_state.solver.BVV(regs['rsp'], 64)
                self._init_state.regs.rbp = self._init_state.solver.BVV(regs['rbp'], 64)
                self._init_state.regs.r8 = self._init_state.solver.BVV(regs['r8'], 64)
                self._init_state.regs.r9 = self._init_state.solver.BVV(regs['r9'], 64)
                self._init_state.regs.r10 = self._init_state.solver.BVV(regs['r10'], 64)
                self._init_state.regs.r11 = self._init_state.solver.BVV(regs['r11'], 64)
                self._init_state.regs.r12 = self._init_state.solver.BVV(regs['r12'], 64)
                self._init_state.regs.r13 = self._init_state.solver.BVV(regs['r13'], 64)
                self._init_state.regs.r14 = self._init_state.solver.BVV(regs['r14'], 64)
                self._init_state.regs.r15 = self._init_state.solver.BVV(regs['r15'], 64)
                self._init_state.regs.rip = self._init_state.solver.BVV(regs['rip'], 64)
                self._init_state.regs.xmm0 = self._init_state.solver.BVV(self.vm.read_reg('xmm00'), 128)
                self._init_state.regs.xmm1 = self._init_state.solver.BVV(self.vm.read_reg('xmm01'), 128)
                self._init_state.regs.xmm2 = self._init_state.solver.BVV(self.vm.read_reg('xmm02'), 128)
                self._init_state.regs.xmm3 = self._init_state.solver.BVV(self.vm.read_reg('xmm03'), 128)
                self._init_state.regs.xmm4 = self._init_state.solver.BVV(self.vm.read_reg('xmm04'), 128)
                self._init_state.regs.xmm5 = self._init_state.solver.BVV(self.vm.read_reg('xmm05'), 128)
                self._init_state.regs.xmm6 = self._init_state.solver.BVV(self.vm.read_reg('xmm06'), 128)
                self._init_state.regs.xmm7 = self._init_state.solver.BVV(self.vm.read_reg('xmm07'), 128)
                self._init_state.regs.xmm8 = self._init_state.solver.BVV(self.vm.read_reg('xmm08'), 128)
                self._init_state.regs.xmm9 = self._init_state.solver.BVV(self.vm.read_reg('xmm09'), 128)
                self._init_state.regs.xmm10 = self._init_state.solver.BVV(self.vm.read_reg('xmm10'), 128)
                self._init_state.regs.xmm11 = self._init_state.solver.BVV(self.vm.read_reg('xmm11'), 128)
                self._init_state.regs.xmm12 = self._init_state.solver.BVV(self.vm.read_reg('xmm12'), 128)
                self._init_state.regs.xmm13 = self._init_state.solver.BVV(self.vm.read_reg('xmm13'), 128)
                self._init_state.regs.xmm14 = self._init_state.solver.BVV(self.vm.read_reg('xmm14'), 128)
                self._init_state.regs.xmm15 = self._init_state.solver.BVV(self.vm.read_reg('xmm15'), 128)
            if self.vm.addr_bytes == 4:
                self._init_state.regs.eax = self._init_state.solver.BVV(regs['eax'], 64)
                self._init_state.regs.ebx = self._init_state.solver.BVV(regs['ebx'], 64)
                self._init_state.regs.ecx = self._init_state.solver.BVV(regs['ecx'], 64)
                self._init_state.regs.edx = self._init_state.solver.BVV(regs['edx'], 64)
                self._init_state.regs.esi = self._init_state.solver.BVV(regs['esi'], 64)
                self._init_state.regs.edi = self._init_state.solver.BVV(regs['edi'], 64)
                self._init_state.regs.esp = self._init_state.solver.BVV(regs['esp'], 64)
                self._init_state.regs.ebp = self._init_state.solver.BVV(regs['ebp'], 64)
                self._init_state.regs.eip = self._init_state.solver.BVV(regs['eip'], 64)

    def _prepare_context(self):
        pc = 0
        val = self.vm.gdb.get_register('rip')
        if val != None:
            pc = val
        if self.vm.addr_bytes == 4:
            val = self.vm.gdb.get_register('rip')
            if val != None:
                pc = val
        if pc == 0:
            return
        self.vm.prepare_context(pc)

    def _restore_memory(self):
        self.setup_sections(self.cus_sections)
        self.setup_segment_base()
        #self.vm.read_stack_range()
    
    def skip_unexpected_opcode(self, addr):
        error_opcode = ['ud2', 'rdtsc', 'in', 'out']
        insns = self.proj.factory.block(addr).capstone.insns
        if len(insns) == 0:
            return
        offset = 0
        for inst in insns:
            opcode = inst.mnemonic
            if opcode in error_opcode:
                if not self.proj.is_hooked(addr+offset):
                    self.skip_insn(addr+offset, inst.size)
            offset += inst.size

    def _is_vul_mem(self, addr):
        if addr >= self.vul_mem_start and addr <= self.vul_mem_end:
            return True
        return False
    
    def _my_successor_func(self, state):
        self.setup_current_state(state)
        self.skip_unexpected_opcode(state.addr)
        succ = state.step()
        if self.cur_state_dead():
            self.logger.warning("current state is dead")
            succ.flat_successors = []
            succ.all_successors = []
            return succ
        successors = succ.successors
        self.transfer_state_globals(state, successors)
        if len(succ.successors) == 1:
            self.update_states(successors[0], self.get_state_index(state))
        if len(succ.successors) == 2:
            self.update_states(successors[0], self.get_state_index(state))
            self.update_states(successors[1], None)  # sym will go this way first
            self.logger.info("state {}({}) fork state {}({}) at {} ".format(self.get_state_index(state), hex(successors[0].addr), self.state_counter, hex(successors[1].addr), hex(state.addr)))
            #cap = self.proj.factory.block(each.addr).capstone
            #cap.pp()

        if len(succ.successors) > 2:
            self.logger.error("WTF")

        for each in successors:
            if self.cur_cond_jmp != 0 and each.addr == self._branch[self.cur_cond_jmp][1]:
                self.logger.info("kill a wrong state: state {}".format(self.self.get_state_index(each)))
                succ.successors.remove(each)
                if each in succ.flat_successors:
                    succ.flat_successors.remove(each)
                if each in succ.all_successors :
                    succ.all_successors.remove(each)
        self.cur_cond_jmp = 0
        return succ
    
    def _after_gdb_resume(self, timeout):
        self.vm.gdb.waitfor("Continuing")
        self.vm.gdb.waitfor("pwndbg>", timeout=timeout)

    def _read_vul_mem(self):
        self._after_gdb_resume(300)
        self.vm.gdb.waitfor("pwndbg>")
        rdi_val = self.vm.gdb.get_register('rdi')
        return rdi_val
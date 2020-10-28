import logging
import time
import angr
import math
import syzbot_analyzer.interface.utilities as utilities

from syzbot_analyzer.interface.vm import VM
from .mem_instrument import MemInstrument

class SymExec(MemInstrument):
    def __init__(self, sections=None, debug=False):
        MemInstrument.__init__(self)
        self.debug = debug
        self._state_logger = {}
        self._state_counter = 0
        self.vul_mem_offset = None
        self.vul_mem_size = None
        self.vul_mem_start = None
        self.vul_mem_end = None
        self.target_site = None
        self.path = None
        self.extra_noisy_func = None
        self.gdb_port = None
        self.vm = None
        self.proj = None
        self.simgr = None
        self._branch = None
        self._init_state = None
        self.current_state = None
        self.cus_sections = sections

    def setup_vm(self, linux, port, image, gdb_port, proj_path='/tmp/', mem="2G", cpu="2", key=None, opts=None, log_name="vm.log"):
        self.gdb_port = gdb_port
        self.vm = VM(linux=linux, port=port, image=image, proj_path=proj_path, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, opts=opts, log_name=log_name, debug=self.debug)
    
    def setup_bug_capture(self, offset, size, vuln_site, target_site, path = [], extra_noisy_func=None):
        self.vul_mem_offset = offset
        self.vul_mem_size = size
        self.vuln_site = vuln_site
        self.target_site = target_site
        self.path = path
        self.extra_noisy_func = extra_noisy_func

    def run_vm(self):
        if self.vm == None:
            print("Call setup_vm() to initialize the vm first")
            return
        # launch qemu
        p = self.vm.run()
        # connect qemu with gdb, set breakpoint at kasan_report()
        self.vm.connect(self.gdb_port)
        self.proj = self.vm.kernel.proj
        while True:
            if self.vm.QEMU_READY:
                break
            time.sleep(1)
        """
        with p.stdout:
            for line in iter(p.stdout.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    continue
                print(line)
                if utilities.regx_match('syzkaller', line):
                    break
        """

    def run_sym(self):
        if self.vm == None:
            print("Call setup_vm() to initialize the vm first")
            return
        if self.vul_mem_offset == None:
            print("Call setup_bug_capture() to initialize vulnerability information")
            return
        self.setup_sections(self.vm, self.cus_sections)
        rdi_val = self.vm.read_reg('rdi')
        vul_mem = int(rdi_val, 16)
        self.vul_mem_start = vul_mem - self.vul_mem_offset
        self.vul_mem_end = self.vul_mem_start + self.vul_mem_size
        print("Vuln mem: {} to {}".format(hex(self.vul_mem_start), hex(self.vul_mem_end)))
        # set a breakpoint at vulnerable site, resume the qemu
        self.vm.reach_vul_site(self.vuln_site)
        print("Reach vuln site")
        self.symbolic_execute(self.vuln_site, self.target_site, self.path)
    
    def symbolic_execute(self, vuln_site, target_site, path):
        extras = {angr.options.REVERSE_MEMORY_NAME_MAP,
                  angr.options.TRACK_ACTION_HISTORY,
                  #angr.options.CONSERVATIVE_READ_STRATEGY,
                  angr.options.KEEP_IP_SYMBOLIC,
                  angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                  angr.options.REGION_MAPPING,
                  angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        self._init_state = self.proj.factory.blank_state(addr=vuln_site, add_options=extras)
        self._restore_registers()
        self._symbolize_vuln_mem()
        self._hookup_path(path)
        self._explore(target_site)
    
    def _explore(self, target_site):
        last_state = 0
        self.current_state = self._init_state
        #self.cfg = self.proj.analyses.CFGFast(normalize = True, function_starts=[self.vuln_site])
        self.current_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_mem_read)
        self.current_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=self.track_mem_write)
        #self.current_state.inspect.b('call', when=angr.BP_BEFORE, action=self.trace_call)
        self.current_state.inspect.b('instruction', when=angr.BP_BEFORE, action=self.trace_instruction, instruction=target_site)
        self.current_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.trace_instruction, instruction=0xffffffff821b7e49)
        self.current_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.trace_instruction, instruction=0xffffffff821b7e5d)
        #self.current_state.inspect.b('fork', when=angr.BP_BEFORE, action=self.trace_fork)
        self.current_state.inspect.b('symbolic_variable', when=angr.BP_AFTER, action=self.trace_symbolic_variable)
        self._state_logger[self.current_state] = self._state_counter

        self.hook_noisy_func(self.extra_noisy_func)
        self.simgr = self.proj.factory.simgr(self.current_state, save_unconstrained=True)
        #loop_seer = angr.exploration_techniques.LoopSeer(bound=5)
        legth_limiter = angr.exploration_techniques.LengthLimiter(max_length=700, drop=True)
        dfs = angr.exploration_techniques.DFS()
        #explorer = angr.exploration_techniques.Explorer(find=target_site)
        self.simgr.use_technique(dfs)
        self.simgr.use_technique(legth_limiter)
        #self.simgr.use_technique(loop_seer)
        #self.simgr.use_technique(explorer)
        while True:
            if len(self.simgr.active) == 1:
                cur_state = self._state_logger[self.current_state]
                if last_state != cur_state:
                    print("Switch state {} to state {}".format(last_state, cur_state))
                    last_state = cur_state
                #cap = self.proj.factory.block(self.simgr.active[0].addr).capstone
                #cap.pp()
            self.simgr.step(successor_func=self._my_successor_func)
            """
            try:
                self.simgr.step(successor_func=self.my_successor_func)
            except:
                print("Error occur")
                return
            """
            if len(self.simgr.active) == 0:
                print("No active states")
            if self.simgr.unconstrained:
                for each_state in self.simgr.unconstrained:
                    if each_state.regs.rip.symbolic and each_state.satisfiable():
                        print("Reach target site")
                        for addr in each_state.globals['sym']:
                            size = each_state.globals['sym'][addr]
                            bv = each_state.memory.load(addr, size=size, inspect=False)
                            print("addr {} eval to {}".format(hex(addr), hex(each_state.solver.eval(bv))))
        return
    
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
                self._init_state.inspect.b('instruction', when=angr.BP_BEFORE, action=self.exit_point, instruction=wrong_path)
            """if wrong_path not in hooked:
                self._init_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.instrument_wrong_path, instruction=wrong_path)
                hooked.append(wrong_path)
            if correct_path not in hooked:
                self._init_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.instrument_correct_path, instruction=correct_path)
                hooked.append(correct_path)"""

    def _symbolize_vuln_mem(self):
        self._init_state.globals['mem'] = {}
        self._init_state.globals['sym'] = {}
        for i in range(0, self.vul_mem_size):
            self._init_state.globals['mem'][self.vul_mem_start + i] = 0
            self._init_state.globals['sym'][self.vul_mem_start + i] = 1
            self.make_symbolic(self._init_state, self.vul_mem_start + i, 1, "s_obj_{}".format(i))
    
    def _restore_registers(self):
        regs = self.vm.read_regs()
        self._init_state.regs.rax = self._init_state.solver.BVV(int(regs['rax'], 16), 64)
        self._init_state.regs.rbx = self._init_state.solver.BVV(int(regs['rbx'], 16), 64)
        self._init_state.regs.rcx = self._init_state.solver.BVV(int(regs['rcx'], 16), 64)
        self._init_state.regs.rdx = self._init_state.solver.BVV(int(regs['rdx'], 16), 64)
        self._init_state.regs.rsi = self._init_state.solver.BVV(int(regs['rsi'], 16), 64)
        self._init_state.regs.rdi = self._init_state.solver.BVV(int(regs['rdi'], 16), 64)
        self._init_state.regs.rsp = self._init_state.solver.BVV(int(regs['rsp'], 16), 64)
        self._init_state.regs.rbp = self._init_state.solver.BVV(int(regs['rbp'], 16), 64)
        self._init_state.regs.r8 = self._init_state.solver.BVV(int(regs['r8'], 16), 64)
        self._init_state.regs.r9 = self._init_state.solver.BVV(int(regs['r9'], 16), 64)
        self._init_state.regs.r10 = self._init_state.solver.BVV(int(regs['r10'], 16), 64)
        self._init_state.regs.r11 = self._init_state.solver.BVV(int(regs['r11'], 16), 64)
        self._init_state.regs.r12 = self._init_state.solver.BVV(int(regs['r12'], 16), 64)
        self._init_state.regs.r13 = self._init_state.solver.BVV(int(regs['r13'], 16), 64)
        self._init_state.regs.r14 = self._init_state.solver.BVV(int(regs['r14'], 16), 64)
        self._init_state.regs.r15 = self._init_state.solver.BVV(int(regs['r15'], 16), 64)
        self._init_state.regs.rip = self._init_state.solver.BVV(int(regs['rip'], 16), 64)
        self._init_state.regs.gs = self._init_state.solver.BVV(int(regs['gs'], 16), 32)
        #self._init_state.regs.cs = self._init_state.solver.BVV(int(regs['cs'], 16), 32)
        #self._init_state.regs.ss = self._init_state.solver.BVV(int(regs['ss'], 16), 32)
        #self._init_state.regs.ds = self._init_state.solver.BVV(int(regs['ds'], 16), 32)
        self._init_state.regs.fs = self._init_state.solver.BVV(int(regs['fs'], 16), 32)
        #self._init_state.regs.es = self._init_state.solver.BVV(int(regs['es'], 16), 32)
        self._init_state.regs.eflags = self._init_state.solver.BVV(int(regs['eflags'], 16), 32)

    def _is_vul_mem(self, addr):
        if addr >= self.vul_mem_start and addr <= self.vul_mem_end:
            return True
        return False
    
    def _my_successor_func(self, state):
        self.current_state = state
        succ = state.step()
        successors = succ.successors
        self.update_state_globals(state, successors)
        if len(succ.successors) == 1:
            self._state_logger[successors[0]] = self._state_counter
        if len(succ.successors) == 2:
            self._state_logger[successors[1]] = self._state_counter
            self._state_counter += 1
            self._state_logger[successors[0]] = self._state_counter
            print("state {} fork state {}({}) at {} ".format(self._state_logger[state], self._state_counter, hex(successors[1].addr), hex(state.addr)))
            #cap = self.proj.factory.block(each.addr).capstone
            #cap.pp()

        if len(succ.successors) > 2:
            print("WTF")

        for each in successors:
            if self.cur_cond_jmp != 0 and each.addr == self._branch[self.cur_cond_jmp][1]:
                print("kill a wrong state: state {}".format(self._state_logger[each]))
                succ.successors.remove(each)
                if each in succ.flat_successors:
                    succ.flat_successors.remove(each)
                if each in succ.all_successors :
                    succ.all_successors .remove(each)
        self.cur_cond_jmp = 0
        return succ
import logging
import time
import angr
import math
import interface.utilities as utilities

from interface.vm import VM
from .mem_instrument import MemInstrument

class SymExec(MemInstrument):
    def __init__(self, debug=False):
        MemInstrument.__init__(self)
        self.debug = debug
        self.state_logger = {}
        self.state_counter = 0
        #self.gdb_port = None
        #self.vm = None
        #self.proj = None
        pass

    def setup_env(self, case_path, syz_repro, syz_commit, repro_type, c_repro, i386, fixed, compiler, command):
        self.case_path = case_path
        self.syz_repro = syz_repro
        self.syz_commit = syz_commit
        self.repro_type = repro_type
        self.c_repro = c_repro
        self.i386 = i386
        self.fixed = fixed
        self.compiler = compiler
        self.command = command

    def setup_vm(self, linux, port, image, gdb_port, proj_path='/tmp/', mem="2G", cpu="2", key=None, opts=None, log_name="vm.log"):
        self.gdb_port = gdb_port
        self.vm = VM(linux=linux, port=port, image=image, proj_path=proj_path, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, opts=opts, log_name=log_name, debug=self.debug)
    
    def setup_bug_capture(self, offset, size, vuln_site, target_site, path):
        self.vul_mem_offset = offset
        self.vul_mem_size = size
        self.vuln_site = vuln_site
        self.target_site = target_site
        self.path = path

    def run_vm(self):
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
        rdi_val = self.vm.read_reg('rdi')
        vul_mem = int(rdi_val, 16)
        self.vul_mem_start = vul_mem - self.vul_mem_offset
        self.vul_mem_end = self.vul_mem_start + self.vul_mem_size
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
        self.init_state = self.proj.factory.blank_state(addr=vuln_site, add_options=extras)
        self.restore_registers()
        self.symbolize_vuln_mem()
        self.hookup_path(path)
        self.explore(target_site)
    
    def explore(self, target_site):
        last_state = 0
        self.current_state = self.init_state
        #self.cfg = self.proj.analyses.CFGFast(normalize = True, function_starts=[self.vuln_site])
        self.current_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_mem_read)
        #self.current_state.inspect.b('call', when=angr.BP_BEFORE, action=self.trace_call)
        self.current_state.inspect.b('instruction', when=angr.BP_BEFORE, action=self.trace_instruction, instruction=target_site)
        self.current_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.trace_instruction, instruction=0xffffffff821b7e49)
        self.current_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.trace_instruction, instruction=0xffffffff821b7e5d)
        self.current_state.inspect.b('fork', when=angr.BP_BEFORE, action=self.trace_fork)
        self.current_state.inspect.b('symbolic_variable', when=angr.BP_AFTER, action=self.trace_symbolic_variable)
        self.state_logger[self.current_state] = self.state_counter

        self.hook_kasan_access()
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
                cur_state = self.state_logger[self.simgr.active[0]]
                if last_state != cur_state:
                    print("Switch state {} to state {}".format(last_state, cur_state))
                    last_state = cur_state
                cap = self.proj.factory.block(self.simgr.active[0].addr).capstone
                cap.pp()
            self.simgr.step(successor_func=self.my_successor_func)
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
                    if each_state.regs.rip.symbolic:
                        print("Reach the target address")
        return
    
    def hookup_path(self, path):
        self.branch = {}
        hooked = []
        for each in path:
            cond = each['cond']
            correct_path = each['correct_path']
            wrong_path = each['wrong_path']
            self.branch[cond] = [correct_path, wrong_path]
            self.init_state.inspect.b('instruction', when=angr.BP_BEFORE, action=self.instrument_cond_jump, instruction=cond)
            if cond == 0 and correct_path == 0 and wrong_path != 0:
                self.init_state.inspect.b('instruction', when=angr.BP_BEFORE, action=self.exit_point, instruction=wrong_path)
            """if wrong_path not in hooked:
                self.init_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.instrument_wrong_path, instruction=wrong_path)
                hooked.append(wrong_path)
            if correct_path not in hooked:
                self.init_state.inspect.b('instruction', when=angr.BP_AFTER, action=self.instrument_correct_path, instruction=correct_path)
                hooked.append(correct_path)"""

    def symbolize_vuln_mem(self):
        for i in range(0, self.vul_mem_size):
            self.make_symbolic(self.init_state, self.vul_mem_start + i, 1, "s_obj_{}".format(i))
    
    def restore_registers(self):
        regs = self.vm.read_regs()
        self.init_state.regs.rax = self.init_state.solver.BVV(int(regs['rax'], 16), 64)
        self.init_state.regs.rbx = self.init_state.solver.BVV(int(regs['rbx'], 16), 64)
        self.init_state.regs.rcx = self.init_state.solver.BVV(int(regs['rcx'], 16), 64)
        self.init_state.regs.rdx = self.init_state.solver.BVV(int(regs['rdx'], 16), 64)
        self.init_state.regs.rsi = self.init_state.solver.BVV(int(regs['rsi'], 16), 64)
        self.init_state.regs.rdi = self.init_state.solver.BVV(int(regs['rdi'], 16), 64)
        self.init_state.regs.rsp = self.init_state.solver.BVV(int(regs['rsp'], 16), 64)
        self.init_state.regs.rbp = self.init_state.solver.BVV(int(regs['rbp'], 16), 64)
        self.init_state.regs.r8 = self.init_state.solver.BVV(int(regs['r8'], 16), 64)
        self.init_state.regs.r9 = self.init_state.solver.BVV(int(regs['r9'], 16), 64)
        self.init_state.regs.r10 = self.init_state.solver.BVV(int(regs['r10'], 16), 64)
        self.init_state.regs.r11 = self.init_state.solver.BVV(int(regs['r11'], 16), 64)
        self.init_state.regs.r12 = self.init_state.solver.BVV(int(regs['r12'], 16), 64)
        self.init_state.regs.r13 = self.init_state.solver.BVV(int(regs['r13'], 16), 64)
        self.init_state.regs.r14 = self.init_state.solver.BVV(int(regs['r14'], 16), 64)
        self.init_state.regs.r15 = self.init_state.solver.BVV(int(regs['r15'], 16), 64)
        self.init_state.regs.rip = self.init_state.solver.BVV(int(regs['rip'], 16), 64)
        self.init_state.regs.gs = self.init_state.solver.BVV(int(regs['gs'], 16), 32)
        #self.init_state.regs.cs = self.init_state.solver.BVV(int(regs['cs'], 16), 32)
        #self.init_state.regs.ss = self.init_state.solver.BVV(int(regs['ss'], 16), 32)
        #self.init_state.regs.ds = self.init_state.solver.BVV(int(regs['ds'], 16), 32)
        self.init_state.regs.fs = self.init_state.solver.BVV(int(regs['fs'], 16), 32)
        #self.init_state.regs.es = self.init_state.solver.BVV(int(regs['es'], 16), 32)
        self.init_state.regs.eflags = self.init_state.solver.BVV(int(regs['eflags'], 16), 32)

    def is_vul_mem(self, addr):
        if addr >= self.vul_mem_start and addr <= self.vul_mem_end:
            return True
        return False

    def trigger_kasan(self):
        self.vm.upload_exp(case_path=self.case_path, syz_repro=self.syz_repro, syz_commit=self.syz_commit,
                            repro_type=self.repro_type, c_repro=self.c_repro, i386=self.i386, fixed=self.fixed,
                            compiler=self.compiler, command=self.command)
        self.vm.command("chmod +x run.sh && ./run.sh")
        
    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)

    def wrong_path_detector(self, state):
        if self.cur_cond_jmp == 0:
            return False
        if state.addr == self.branch[self.cur_cond_jmp][1]:
            return True
        return False
    
    def my_successor_func(self, state):
        succ = state.step()
        successors = succ.successors
        #self.update_mem_initialized_map(state, successors)
        if len(succ.successors) == 1:
            self.state_logger[successors[0]] = self.state_counter
        if len(succ.successors) == 2:
            self.state_logger[successors[1]] = self.state_counter
            self.state_counter += 1
            self.state_logger[successors[0]] = self.state_counter
            print("state {} fork state {} at {} ".format(self.state_logger[state], self.state_counter, hex(state.addr)))
            print("     state {} start at {}".format(self.state_counter, hex(successors[1].addr)))
            #cap = self.proj.factory.block(each.addr).capstone
            #cap.pp()

        if len(succ.successors) > 2:
            print("WTF")

        for each in successors:
            if self.cur_cond_jmp != 0 and each.addr == self.branch[self.cur_cond_jmp][1]:
                print("kill a wrong state: state {}".format(self.state_logger[each]))
                succ.successors.remove(each)
                if each in succ.flat_successors:
                    succ.flat_successors.remove(each)
                if each in succ.all_successors :
                    succ.all_successors .remove(each)
        self.cur_cond_jmp = 0
        return succ
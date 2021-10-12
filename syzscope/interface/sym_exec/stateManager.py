import angr
import logging
import os
import archinfo
import datetime
import time
from angr import SimUnsatError
class StateManager:
    G_MEM = 0
    G_SYM = 1
    G_RET = 2
    G_BB = 3
    G_LOOP = 4
    MAX_BB_WITHOUT_SYM = 10000
    MAX_FORK_LOOP = 10
    NO_ADDITIONAL_USE = 0
    ARBITRARY_VALUE_WRITE = 1 << 0
    FINITE_VALUE_WRITE = 1 << 1
    ARBITRARY_ADDR_WRITE = 1 << 2
    FINITE_ADDR_WRITE = 1 << 3
    CONTROL_FLOW_HIJACK = 1 << 4
    OOB_UAF_WRITE = 1 << 5
    INVALID_FREE = 1 << 6

    def __init__(self, index, workdir):
        self.index = index
        self.workdir = workdir
        self._current_state = None
        self.simgr = None
        self.state_logger = None
        self.fork_countor = None
        self.state_privilege = None
        self.state_counter = None
        self.add_constraints = False
        self.symbolic_tracing = False
        self.out_of_scope = False
        self.dfs = True
        self.guided= False
        self.proj_path = None
        self.stop_execution = False
        self.kill_current_state = False
        self.exploitable_state = {}
    
    def init_StateManager(self):
        self.state_logger = {}
        self.fork_countor = {}
        self.state_privilege = 0
        self.state_counter = 0
    
    def init_primitive_logger(self, name):
        primitive_path = os.path.join(self.workdir, "primitives")
        if not os.path.exists(primitive_path):
            os.mkdir(primitive_path)
        if self.proj_path != None:
            handler = logging.FileHandler("{}/{}".format(primitive_path, name))
            logger = logging.getLogger(name)
            if len(logger.handlers) == 0:
                logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
            if self.debug:
                logger.propagate = True
                logger.setLevel(logging.DEBUG)
        else:
            return None


        #now = datetime.datetime.now()
        #current_time = now.strftime("%m/%d/%y %H:%M:%S")
        logger.info("Primitive found at {} seconds".format(time.time() - self.start_time))
        return logger
    
    def setup_current_state(self, init_state):
        self._current_state = init_state

    def init_simgr(self, symbolic_tracing, dfs):
        self.dfs = dfs
        self.symbolic_tracing = symbolic_tracing
        if self._current_state == None:
            err = "setup current state before initializing simgr"
            return False, err
        self.update_states(self._current_state, None)
        self.simgr = self.proj.factory.simgr(self._current_state, save_unconstrained=True)
        if not symbolic_tracing:
            self.add_constraints = True
            #if dfs:
            #    legth_limiter = angr.exploration_techniques.LengthLimiter(max_length=20000, drop=True)
            #    self.simgr.use_technique(legth_limiter)
        if dfs:
            dfs = angr.exploration_techniques.DFS()
            self.simgr.use_technique(dfs)
        return True, None
    
    def get_current_state(self):
        return self._current_state
    
    def wrap_high_risk_state(self, state, impact_type, bv=None):
        prim_logger = None
        func_name = self.vm.get_func_name(state.scratch.ins_addr)
        if func_name == None:
            self.logger.info("{} does not have a valid function name".format(hex(state.scratch.ins_addr)))
            func_name = 'UNKOWN_FUNC'
            #self.dump_state(state)
            #self.dump_stack(state)
            #self.dump_trace(state)
            self.purge_current_state()
            return None
        target_sign = ""
        file, line = self.vm.get_dbg_info(state.scratch.ins_addr)
        key = "{}:{}".format(file, line)
        if key in self.target_site and self.target_site[key] == StateManager.NO_ADDITIONAL_USE:
            target_sign = "-Target"
        if key not in self.target_site:
            self.target_site[key] = StateManager.NO_ADDITIONAL_USE
        self.target_site[key] |= impact_type
        #if self.all_targets_covered():
        #    self.stop_execution = True
        if (state.scratch.ins_addr in self.exploitable_state) and (self.exploitable_state[state.scratch.ins_addr] & impact_type):
            return None
        self.exploitable_state[state.scratch.ins_addr] = impact_type
        index = len(self.exploitable_state)
        if impact_type == StateManager.FINITE_ADDR_WRITE:
            self.state_privilege |= impact_type
            prim_name = "{}-{}-{}".format("CAW", func_name, hex(state.scratch.ins_addr)) + target_sign + "-" + str(index)
            prim_logger = self.init_primitive_logger(prim_name)
            prim_logger.warning("Finite address write found")
        if impact_type == StateManager.ARBITRARY_ADDR_WRITE:
            self.state_privilege |= impact_type
            prim_name = "{}-{}-{}".format("AAW", func_name, hex(state.scratch.ins_addr)) + target_sign + "-" + str(index)
            prim_logger = self.init_primitive_logger(prim_name)
            prim_logger.warning("Arbitrary address write found")
        if impact_type == StateManager.FINITE_VALUE_WRITE:
            self.state_privilege |= impact_type
            prim_name = "{}-{}-{}".format("CVW", func_name, hex(state.scratch.ins_addr)) + target_sign + "-" + str(index)
            prim_logger = self.init_primitive_logger(prim_name)
            prim_logger.warning("Finite value write found")
        if impact_type == StateManager.ARBITRARY_VALUE_WRITE:
            self.state_privilege |= impact_type
            prim_name = "{}-{}-{}".format("AVW", func_name, hex(state.scratch.ins_addr)) + target_sign + "-" + str(index)
            prim_logger = self.init_primitive_logger(prim_name)
            prim_logger.warning("Arbitrary value write found")
        if impact_type == StateManager.CONTROL_FLOW_HIJACK:
            self.state_privilege |= impact_type
            prim_name = "{}-{}-{}".format("FPD", func_name, hex(state.scratch.ins_addr)) + target_sign + "-" + str(index)
            prim_logger = self.init_primitive_logger(prim_name)
            prim_logger.warning("Control flow hijack found!")
        if impact_type == StateManager.OOB_UAF_WRITE:
            self.state_privilege |= impact_type
            prim_name = "{}-{}-{}".format("OUW", func_name, hex(state.scratch.ins_addr)) + target_sign + "-" + str(index)
            prim_logger = self.init_primitive_logger(prim_name)
            prim_logger.warning("OOB UAF write found!")
        if impact_type == StateManager.INVALID_FREE:
            self.state_privilege |= impact_type
            prim_name = "{}-{}-{}".format("IF", func_name, hex(state.scratch.ins_addr)) + target_sign + "-" + str(index)
            prim_logger = self.init_primitive_logger(prim_name)
            prim_logger.warning("Invalid free found!")
            """
            for addr in state.globals['sym']:
                size = state.globals['sym'][addr]
                bv = state.memory.load(addr, size=size, inspect=False, endness=archinfo.Endness.LE)
                val = state.solver.eval(bv)
                prim_logger.info("addr {} eval to {} with {} bytes".format(hex(addr), hex(val), size))
            """
        if bv != None:
            prim_logger.info('constraint begin')
            prim_logger.info(bv)
            prim_logger.info('constraint end')
        self.dump_state(state, prim_logger)
        self.dump_stack(state, prim_logger)
        self.dump_trace(state, prim_logger)
        return prim_logger
    
    def update_states(self, state, index):
        if index == None:
            self.state_counter += 1
            self.state_logger[state] = self.state_counter
        else:
            self.state_logger[state] = index

    def update_states_globals(self, addr, val, key, state=None):
        n = 0
        if state == None:
            state = self._current_state
        if key == StateManager.G_MEM:
            if 'mem' not in state.globals:
                state.globals['mem'] = {}
            state.globals['mem'][addr] = val
            n = len(state.globals['mem'])
        if key == StateManager.G_SYM:
            if 'sym' not in state.globals:
                state.globals['sym'] = {}
            state.globals['sym'][addr] = val
            n = len(state.globals['sym'])
            if 'mem' not in state.globals:
                state.globals['mem'] = {}
            state.globals['mem'][addr] = val
        if key == StateManager.G_RET:
            if 'ret' not in state.globals:
                state.globals['ret'] = []
            state.globals['ret'].append(val)
            n = len(state.globals['ret'])
        if key == StateManager.G_BB:
            if 'bb' not in state.globals:
                state.globals['bb'] = 0
            state.globals['bb'] += 1
            n = 0
        if key == StateManager.G_LOOP:
            if 'out_loop' not in state.globals:
                state.globals['out_loop'] = False
            state.globals['out_loop'] = val
        return n
    
    def get_states_globals(self, addr, key):
        val = None
        if key == StateManager.G_MEM:
            try:
                val = self._current_state.globals['mem'][addr]
            except KeyError:
                val = None
        if key == StateManager.G_SYM:
            try:
                val = self._current_state.globals['sym'][addr]
            except KeyError:
                val = None
        if key == StateManager.G_RET:
            try:
                val = self._current_state.globals['ret'][addr]
            except KeyError:
                val = None
        if key == StateManager.G_BB:
            try:
                val = self._current_state.globals['bb']
            except KeyError:
                val = None
        return val
        
    def get_state_index(self, state):
        try:
            ret = self.state_logger[state]
        except:
            ret = -1
        return ret
    
    def _arg_be_zero(self, bv):
        for arg in bv.args:
            if self._current_state.solver.solution(arg, 0):
                return True
        return False
    
    def _is_arbitrary_value(self, bv):
        range_limit_op = ['__le__', 'SLE', '__lt__', 'SLT', 'UGT', 'UGE'\
            '__gt__', '__ge__', 'SGT', 'SGE', 'ULT', 'ULE', '__eq__', '__ne__', 'Concat']
        ret = None
        if type(bv) == int or bv.op == 'BVV':
            return False
        if bv.op == 'BVS':
            return True
        if bv.args == None:
            return True
        for each_arg in bv.args:
            if ret == None:
                ret = self._is_arbitrary_value(each_arg)
            else:
                if bv.op in range_limit_op:
                    ret &= self._is_arbitrary_value(each_arg)
                else:
                    if bv.op == '__mul__' and self._arg_be_zero(bv):
                        return False
                    else:
                        ret |= self._is_arbitrary_value(each_arg)
        return ret
        

    def is_under_constrained(self, bv):
        # '0x100000000000000'
        print(bv)
        for e in bv.leaf_asts():
            print(e)
        if bv.depth > 10:
            # Too many depth (8^10) make the recursive a blackhole
            return not (self._current_state.solver.solution(bv, 0) and \
                self._current_state.solver.solution(bv, 0x100000000000000))
        sym_value_4_state = []
        sym_value_4_bv = []
        constraints = self._current_state.solver.constraints
        for each_con in constraints:
            sym_value_4_state.extend(self.iterate_constraints(each_con))
        sym_value_4_bv.extend(self.iterate_constraints(bv))
        try:
            for each in sym_value_4_bv:
                if each in sym_value_4_state:
                    return True
        except Exception as e:
            print(e)
        return False
    
    def iterate_constraints(self, bv):
        ret = []
        try:
            if bv.depth == 1 or bv.args == None:
                return ret
        except AttributeError:
            return ret
        for each_arg in bv.args:
            ret.append(id(each_arg))
            ret.extend(self.iterate_constraints(each_arg))
        return ret
    
    def reset_state_bb(self):
        self._current_state.globals['bb'] = 0
        self.out_of_scope = False

    def purge_current_state(self):
        self.kill_current_state = True
    
    def cur_state_dead(self):
        return not self._current_state in self.simgr.active
    
    def all_targets_covered(self):
        if not self.guided:
            return False
        for key in self.target_site:
            if self.target_site[key] == StateManager.NO_ADDITIONAL_USE:
                return False
        return True

    def dump_state(self, state, logger=None):
        if logger == None:
            logger = self.logger
        logger.info("rax: is_symbolic: {} {}".format(state.regs.rax.symbolic, hex(state.solver.eval(state.regs.rax))))
        logger.info("rbx: is_symbolic: {} {}".format(state.regs.rbx.symbolic, hex(state.solver.eval(state.regs.rbx))))
        logger.info("rcx: is_symbolic: {} {}".format(state.regs.rcx.symbolic, hex(state.solver.eval(state.regs.rcx))))
        logger.info("rdx: is_symbolic: {} {}".format(state.regs.rdx.symbolic, hex(state.solver.eval(state.regs.rdx))))
        logger.info("rsi: is_symbolic: {} {}".format(state.regs.rsi.symbolic, hex(state.solver.eval(state.regs.rsi))))
        logger.info("rdi: is_symbolic: {} {}".format(state.regs.rdi.symbolic, hex(state.solver.eval(state.regs.rdi))))
        logger.info("rsp: is_symbolic: {} {}".format(state.regs.rsp.symbolic, hex(state.solver.eval(state.regs.rsp))))
        logger.info("rbp: is_symbolic: {} {}".format(state.regs.rbp.symbolic, hex(state.solver.eval(state.regs.rbp))))
        logger.info("r8: is_symbolic: {} {}".format(state.regs.r8.symbolic, hex(state.solver.eval(state.regs.r8))))
        logger.info("r9: is_symbolic: {} {}".format(state.regs.r9.symbolic, hex(state.solver.eval(state.regs.r9))))
        logger.info("r10: is_symbolic: {} {}".format(state.regs.r10.symbolic, hex(state.solver.eval(state.regs.r10))))
        logger.info("r11: is_symbolic: {} {}".format(state.regs.r11.symbolic, hex(state.solver.eval(state.regs.r11))))
        logger.info("r12: is_symbolic: {} {}".format(state.regs.r12.symbolic, hex(state.solver.eval(state.regs.r12))))
        logger.info("r13: is_symbolic: {} {}".format(state.regs.r13.symbolic, hex(state.solver.eval(state.regs.r13))))
        logger.info("r14: is_symbolic: {} {}".format(state.regs.r14.symbolic, hex(state.solver.eval(state.regs.r14))))
        logger.info("r15: is_symbolic: {} {}".format(state.regs.r15.symbolic, hex(state.solver.eval(state.regs.r15))))
        logger.info("rip: is_symbolic: {} {}".format(state.regs.rip.symbolic, hex(state.solver.eval(state.regs.rip))))
        logger.info("gs: is_symbolic: {} {}".format(state.regs.gs.symbolic, hex(state.solver.eval(state.regs.gs))))
        logger.info("================Thread-{} dump_state====================".format(self.index))
        logger.info("The value of each register may not reflect the latest state. It only represent the value at the beginning of current basic block")
        insns = self.proj.factory.block(state.scratch.ins_addr).capstone.insns
        n = len(insns)
        t = self.vm.inspect_code(state.scratch.ins_addr, n)
        logger.info(t)
        #cap = self.proj.factory.block(state.scratch.ins_addr).capstone
        #cap.pp()
    
    def dump_stack(self, state, logger=None):
        if logger == None:
            logger = self.logger
        calltrace = '\n'
        ret = []
        if 'ret' in state.globals:
            for i in range(0, len(state.globals['ret'])):
                calltrace += '  '*(len(state.globals['ret'])-i-1) + '|' + state.globals['ret'][i] + '\n'
        callstack = state.callstack
        while True:
            if callstack.next == None:
                break
            func_addr = callstack.current_function_address
            call_site = callstack.call_site_addr
            func_name = self.vm.get_func_name(func_addr)
            file, line = self.vm.get_dbg_info(call_site)
            ret.append("{} {}:{}".format(func_name, file, line))
            callstack = callstack.next
        for i in range(0, len(ret)):
            calltrace += '  '*i + '|' + ret[::-1][i] + '\n'
        if not state.regs.rip.symbolic:
            func_name = self.vm.get_func_name(state.scratch.ins_addr)
            file, line = self.vm.get_dbg_info(state.scratch.ins_addr)
            calltrace += '  '*(len(ret)-1) + '|' + "{} {}:{}".format(func_name, file, line) + "\n"
        logger.info(calltrace)
        return
    
    def dump_trace(self, state, logger=None):
        if logger == None:
            logger = self.logger
        n = 0
        intra_proc_n = 0
        depth = 0
        in_call_n = [0]
        for addr in state.history.bbl_addrs: 
            n += 1
            intra_proc_n += 1
            in_call_n[depth] += 1
            insns = self.proj.factory.block(addr).capstone.insns
            length = len(insns)
            func_name = self.vm.get_func_name(addr)
            file, line = self.vm.get_dbg_info(addr)
            if func_name == None or file == None or line == None:
                continue
            if 'kasan' not in file and 'kcov' not in file:
                logger.info(hex(addr))
                logger.info("{} {}:{}".format(func_name, file, line))
                logger.info("--------------------------------------")
            if length != 0:
                    if insns[length-1].mnemonic == 'call':
                        depth += 1
                        if len(in_call_n) > depth:
                            in_call_n[depth] = 0
                        else:
                            in_call_n.append(0)
                    if insns[length-1].mnemonic == 'ret' or \
                        'kasan' in file or 'kcov' in file:
                        if depth > 0:
                            intra_proc_n -= in_call_n[depth]
                            depth -= 1
        logger.info("Total {} intraprocedural basic block".format(intra_proc_n))
        logger.info("Total {} basic block".format(n))
import angr

class StateManager:
    G_MEM = 0
    G_SYM = 1
    G_IRSB = 2
    NO_ADDITIONAL_USE = 0
    ARBITRARY_VALUE_WRITE = 1 << 0
    FINITE_VALUE_WRITE = 1 << 1
    ARBITRARY_ADDR_WRITE = 1 << 2
    FINITE_ADDR_WRITE = 1 << 3
    CONTROL_FLOW_HIJACK = 1 << 4

    def __init__(self, index):
        self.index = index
        self._current_state = None
        self.simgr = None
        self.state_logger = {}
        self.state_privilege = 0
        self.state_counter = 0
        self.add_constraints = False
        self.symbolic_tracing = False
    
    def setup_current_state(self, init_state):
        self._current_state = init_state

    def init_simgr(self, symbolic_tracing):
        self.symbolic_tracing = symbolic_tracing
        if self._current_state == None:
            err = "setup current state before initializing simgr"
            return False, err
        self.update_states(self._current_state, None)
        self.simgr = self.proj.factory.simgr(self._current_state, save_unconstrained=True)
        if not symbolic_tracing:
            self.add_constraints = True
            legth_limiter = angr.exploration_techniques.LengthLimiter(max_length=10000, drop=True)
            self.simgr.use_technique(legth_limiter)
        dfs = angr.exploration_techniques.DFS()
        self.simgr.use_technique(dfs)
        return True, None
    
    def get_current_state(self):
        return self._current_state
    
    def update_states(self, state, index):
        if index == None:
            self.state_counter += 1
            self.state_logger[state] = self.state_counter
        else:
            self.state_logger[state] = index
    
    def update_states_globals(self, addr, val, key):
        if key == StateManager.G_MEM:
            if 'mem' not in self._current_state.globals:
                self._current_state.globals['mem'] = {}
            self._current_state.globals['mem'][addr] = val
        if key == StateManager.G_SYM:
            if 'sym' not in self._current_state.globals:
                self._current_state.globals['sym'] = {}
            self._current_state.globals['sym'][addr] = val
            if 'mem' not in self._current_state.globals:
                self._current_state.globals['mem'] = {}
            self._current_state.globals['mem'][addr] = val
        if key == StateManager.G_IRSB:
            if 'irsb' not in self._current_state.globals:
                self._current_state.globals['irsb'] = {}
            self._current_state.globals['irsb'][addr] = val
    
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
        return val
        
    def get_state_index(self, state):
        try:
            ret = self.state_logger[state]
        except:
            ret = -1
        return ret
    
    def is_under_constrained(self, bv):
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

    def purge_current_state(self):
        if self._current_state in self.simgr.active:
            self.simgr.active.remove(self._current_state)
            self.simgr.deadended.append(self._current_state)
    
    def cur_state_dead(self):
        return not self._current_state in self.simgr.active
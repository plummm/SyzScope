import angr

class StateManager:
    G_MEM = 0
    G_SYM = 1
    G_IRSB = 2

    def __init__(self):
        self._current_state = None
        self.simgr = None
        self.state_logger = {}
        self.state_counter = 0
        self.add_constraints = False
    
    def setup_current_state(self, init_state):
        self._current_state = init_state

    def init_simgr(self, symbolic_tracing):
        if self._current_state == None:
            err = "setup current state before initializing simgr"
            return False, err
        self.update_states(self._current_state, False)
        self.simgr = self.proj.factory.simgr(self._current_state, save_unconstrained=True)
        if not symbolic_tracing:
            #self.add_constraints = True
            pass
        legth_limiter = angr.exploration_techniques.LengthLimiter(max_length=1000, drop=True)
        self.simgr.use_technique(legth_limiter)
        dfs = angr.exploration_techniques.DFS()
        self.simgr.use_technique(dfs)
        return True, None
    
    def get_current_state(self):
        return self._current_state
    
    def update_states(self, state, new_state: bool):
        self.state_logger[state] = self.state_counter
        if new_state:
            self.state_counter += 1
    
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
        return self.state_logger[state]

    def purge_current_state(self):
        if self._current_state in self.simgr.active:
            self.simgr.active.remove(self._current_state)
            self.simgr.deadended.append(self._current_state)
    
    def cur_state_dead(self):
        return not self._current_state in self.simgr.active
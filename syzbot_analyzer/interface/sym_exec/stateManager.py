import angr

class StateManager:
    G_MEM = 0
    G_SYM = 1

    def __init__(self):
        self._current_state = None
        self.simgr = None
        self.state_logger = {}
        self.state_counter = 0
    
    def setup_current_state(self, init_state):
        self._current_state = init_state

    def init_simgr(self):
        if self._current_state == None:
            print("setup current state before initializing simgr")
            return
        self.update_states(self._current_state, False)
        self.simgr = self.proj.factory.simgr(self._current_state, save_unconstrained=True)
        legth_limiter = angr.exploration_techniques.LengthLimiter(max_length=700, drop=True)
        dfs = angr.exploration_techniques.DFS()
        self.simgr.use_technique(dfs)
        self.simgr.use_technique(legth_limiter)
    
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
    
    def get_states_globals(self, addr, key):
        if key == StateManager.G_MEM:
            return self._current_state.globals['mem'][addr]
        if key == StateManager.G_SYM:
            return self._current_state.globals['sym'][addr]
        
    def get_state_index(self, state):
        return self.state_logger[state]

    def purge_current_state(self):
        for each_state in self.simgr.active:
            if each_state == self._current_state:
                self.simgr.active.remove(each_state)
        
        self.simgr.deadended.append(self._current_state)


class PropagationHandler:
    def __init__(self):
        self._last_write = 0
        self._write_queue = []
        self._write_from_sym = []

    def is_kasan_write(self, addr):
        if self._last_write == addr:
            self._last_write = 0
            return True
        return False

    def log_kasan_write(self,addr):
        self._write_queue.append(addr)
        if self._last_write !=0:
            print("last_write = {} instead of 0".format(hex(self._last_write)))
        self._last_write = addr

    def log_symbolic_propagation(self, state, stack):
        propagation_info = {}
        propagation_info['kasan_write_index'] = len(self._write_queue)-1
        propagation_info['pc'] = state.scratch.ins_addr
        propagation_info['write_to_mem'] = self._write_queue[len(self._write_queue)-1]
        propagation_info['stack'] = stack
        self._write_from_sym.append(propagation_info)
    
    def get_symbolic_propagation(self):
        return self._write_from_sym
    
    def get_write_queue(self, index):
        if len(self._write_queue) > index:
            return self._write_queue[index]
        return None


class PropagationHandler:
    def __init__(self):
        self._write_queue = []
        self._write_from_sym = []

    def is_kasan_write(self, addr):
        length = len(self._write_queue)
        if length > 0:
            if self._write_queue[length-1] == addr:
                return True
        return False

    def log_kasan_write(self,addr):
        self._write_queue.append(addr)

    def log_symbolic_propagation(self):
        self._write_from_sym.append(len(self._write_queue)-1)
    
    def get_symbolic_propagation(self):
        if self._write_from_sym == []:
            self._write_from_sym.append(self._write_queue)
        return self._write_from_sym
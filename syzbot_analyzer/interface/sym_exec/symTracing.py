

class InvokeHandler:
    def __init__(self):
        self._write_queue = []
        self._queue_index = 0
        self._write_from_sym = []

    def is_kasan_write(self, addr):
        if len(self._write_queue) > self._queue_index:
            tmp = self._queue_index
            self._queue_index += 1
            return self._write_queue[tmp] == addr
        return False

    def log_kasan_write(self,addr):
        self._write_queue.append(addr)

    def log_symbolic_propagation(self):
        self._write_from_sym.append(self._queue_index)
    
    def get_symbolic_propagation(self):
        return self._write_from_sym
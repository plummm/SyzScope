from .instance import VMInstance
from .state import VMState

class VM(VMInstance, VMState):
    def __init__(self, linux, port, image, hash_tag, arch='amd64', proj_path='/tmp/', mem="2G", cpu="2", key=None, gdb_port=None, mon_port=None, opts=None, log_name='vm.log', log_suffix="", timeout=None, debug=False, logger=None):
        VMInstance.__init__(self, proj_path=proj_path, log_name=log_name, log_suffix=log_suffix, logger=logger, hash_tag=hash_tag, debug=debug)
        self.setup(port=port, image=image, linux=linux, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, mon_port=mon_port, opts=opts, timeout=timeout)
        if gdb_port != None:
            VMState.__init__(self, linux, gdb_port, arch, proj_path=proj_path, log_suffix=log_suffix, debug=debug)
    
    def kill(self):
        self.kill_vm()
        if self.gdb != None:
            self.gdb.close()
        if self.mon != None:
            self.mon.close()
        if self.kernel != None and self.kernel.proj != None:
            del self.kernel.proj
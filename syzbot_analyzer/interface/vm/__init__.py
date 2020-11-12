from .instance import VMInstance
from .state import VMState

class VM(VMInstance, VMState):
    def __init__(self, linux, port, image, arch='amd64', proj_path='/tmp/', mem="2G", cpu="2", key=None, gdb_port=None, mon_port=None, opts=None, log_name='vm.log', debug=False):
        VMInstance.__init__(self, proj_path=proj_path, log_name=log_name, debug=debug)
        self.setup(port=port, image=image, linux=linux, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, mon_port=mon_port, opts=opts)
        if gdb_port != None:
            VMState.__init__(self, linux, gdb_port, arch, debug=debug)
    
    def kill(self):
        self.kill_vm()
        self.gdb.close()
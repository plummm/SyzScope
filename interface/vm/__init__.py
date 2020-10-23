from .instance import VMInstance
from .state import VMState

class VM(VMInstance, VMState):
    def __init__(self, linux, port, image, proj_path='/tmp/', mem="2G", cpu="2", key=None, gdb_port=None, opts=None, log_name='vm.log', debug=False):
        VMInstance.__init__(self, proj_path=proj_path, log_name=log_name, debug=debug)
        self.setup(port=port, image=image, linux=linux, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, opts=opts)
        if gdb_port != None:
            VMState.__init__(self, linux, gdb_port)
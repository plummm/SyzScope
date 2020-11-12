import syzbot_analyzer.interface.utilities as utilities

from pwn import *

class Monitor:
    def __init__(self, port, debug=False):
        self._port = port
        self._debug = debug
    
    def connect(self):
        self.mon_inst = remote('127.0.0.1', self._port)
        self.waitfor("(qemu)")
    
    def get_register(self, reg):
        ret = 0
        segment_regs = ['es', 'cs', 'ss', 'ds', 'fs', 'gs', 'ldt', 'tr']
        cmd = 'info registers'
        raw = self.sendline(cmd)
        if reg in segment_regs:
            seg_regx = r'\w+( )?=[0-9a-f]+ ([0-9a-f]+)'
            for line in raw.split('\n'):
                line = line.strip('\n')
                tmp = line.split('=')
                if len(tmp) == 1:
                    continue
                name = tmp[0]
                last_ele = len(name)-1
                if name[last_ele] == ' ':
                    name = name[:last_ele]
                if name.lower() == reg:
                    val = utilities.regx_get(seg_regx, line, 1)
                    if val != None:
                        ret = int(val, 16)
        return ret
    
    def choose_cpu(self, pc):
        ret = 0
        cmd = 'info cpus'
        cpu_regx = r'CPU #(\d+): pc=(0x[a-f0-9]+)'
        raw = self.sendline(cmd)
        for line in raw.split('\n'):
            line = line.strip('\n')
            cpu_index = utilities.regx_get(cpu_regx, line, 0)
            cpu_pc = utilities.regx_get(cpu_regx, line, 1)
            if cpu_index == None or cpu_pc == None:
                continue
            if pc == int(cpu_pc, 16):
                ret = int(cpu_index)
                break
        return ret
    
    def set_cpu(self, index):
        cmd = 'cpu {}'.format(index)
        self.sendline(cmd)
    
    def sendline(self, cmd):
        self._sendline(cmd)
        raw = self.waitfor("(qemu)")
        return raw
    
    def waitfor(self, pattern):
        text = self.mon_inst.recvuntil(pattern)
        if self._debug:
            print(text.decode("utf-8"))
        return text.decode("utf-8")
    
    def _sendline(self, cmd):
        self.mon_inst.sendline(cmd)

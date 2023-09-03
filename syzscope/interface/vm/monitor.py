import syzscope.interface.utilities as utilities
import math
import logging

from pwn import *
from .error import QemuIsDead

class Monitor:
    def __init__(self, port, addr_bytes, log_path=None, log_suffix="", debug=False):
        self.mon_inst = None
        self.s_mem = 'g'
        self.s_group = 8
        if addr_bytes == 4:
            self.s_mem = 'w'
            self.s_group = 4
        self._log_suffix = log_suffix
        self._port = port
        self._debug = debug
        self.logger = self._init_logger(log_path)
    
    def _init_logger(self, log_path):
        logger = logging.getLogger(__name__+"-mon-{}".format(self._port))
        if len(logger.handlers) != 0:
            for each_handler in logger.handlers:
                logger.removeHandler(each_handler)
        handler = logging.FileHandler("{}/mon.log{}".format(log_path, self._log_suffix))
        format = logging.Formatter('%(asctime)s %(message)s')
        handler.setFormatter(format)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.propagate = False
        if self._debug:
            logger.setLevel(logging.DEBUG)
        return logger
    
    def connect(self):
        #context.log_level = 'error'
        try:
            self.mon_inst = remote('127.0.0.1', self._port)
        except:
            raise QemuIsDead
        self.waitfor("(qemu)")
    
    def get_registers(self):
        ret = {}
        cmd = 'info registers'
        raw = self.sendline(cmd)
        regs = ['es', 'cs', 'ss', 'ds', 'fs', 'gs', 'ldt', 'tr', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', \
            'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip']
        for each in regs:
            val = self.get_register(each, raw)
            if val != None:
                ret[each] = val
        return ret

    def get_register(self, reg, raw=None):
        ret = 0
        segment_regs = ['es', 'cs', 'ss', 'ds', 'fs', 'gs', 'ldt', 'tr']
        if raw==None:
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
                if name != None and name.lower() == reg:
                    val = utilities.regx_get(seg_regx, line, 1)
                    if val != None:
                        ret = int(val, 16)
        else:
            reg_regx = r'(\w+)=([0-9a-f]+)'
            for line in raw.split('\n'):
                line = line.strip('\n')
                t = line.split(' ')
                new = []
                str = ''
                for e in t:
                    reg_name = None
                    reg_val = None
                    if '=' in e and e[0] != '=':
                        reg_name = utilities.regx_get(reg_regx, e, 0)
                        reg_val = utilities.regx_get(reg_regx, e, 1)
                    else:
                        str += e
                        if '=' in str:
                            reg_name = utilities.regx_get(reg_regx, str, 0)
                            reg_val = utilities.regx_get(reg_regx, str, 1)
                            str = ''
                    if reg_name != None and reg_name.lower() == reg:
                        if reg_val != None:
                            ret = int(reg_val, 16)
                            break

        return ret
    
    def get_mem_content(self, addr, size):
        ret = []
        regx_mem_contect = r'[a-f0-9]+( <[A-Za-z0-9_.\+]+>)?:\W+(0x[a-f0-9]+)(\W+(0x[a-f0-9]+))?'
        group = math.ceil(size / self.s_group)
        cmd = 'x/{}{}x {}'.format(group, self.s_mem, hex(addr))
        raw = self.sendline(cmd)
        for line in raw.split('\n'):
            line = line.strip('\n')
            mem = utilities.regx_get(regx_mem_contect, line, 1)
            if mem == None:
               continue
            ret.append(int(mem, 16))
            mem = utilities.regx_get(regx_mem_contect, line, 3)
            if mem == None:
                continue
            ret.append(int(mem, 16))
        return ret

    
    def choose_cpu(self, pc):
        ret = -1
        n = 0
        cmd = 'info cpus'
        cpu_regx = r'CPU #(\d+): pc=(0x[a-f0-9]+)'
        raw = self.sendline(cmd)
        for line in raw.split('\n')[1:]:
            line = line.strip('\n')
            cpu_index = utilities.regx_get(cpu_regx, line, 0)
            cpu_pc = utilities.regx_get(cpu_regx, line, 1)
            if cpu_index == None or cpu_pc == None:
                self.set_cpu(n)
                cpu_pc = self.get_register('rip')
                if self.s_group == 4:
                    cpu_pc = self.get_register('eip')
                cpu_pc = hex(cpu_pc)
                cpu_index = n
            n += 1
            if pc == int(cpu_pc, 16):
                ret = int(cpu_index)
                break
        return ret
    
    def set_cpu(self, index):
        cmd = 'cpu {}'.format(index)
        self.sendline(cmd)
    
    def sendline(self, cmd):
        self._sendline(cmd)
        self.waitfor(cmd)
        raw = self.waitfor("(qemu)")
        return raw
    
    def waitfor(self, pattern):
        try:
            text = self.mon_inst.recvuntil(pattern.encode())
        except EOFError:
            raise QemuIsDead
        self.logger.info(text.decode("utf-8"))
        if self._debug:
            print(text.decode("utf-8"))
        return text.decode("utf-8")
    
    def close(self):
        self.mon_inst.close()

    def _sendline(self, cmd):
        self.mon_inst.sendline(cmd.encode())
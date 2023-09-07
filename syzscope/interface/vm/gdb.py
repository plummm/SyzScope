import logging
import time
import pexpect
import math, re
import syzscope.interface.utilities as utilities

from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
from pwn import *
from .error import QemuIsDead

class GDBHelper:
    def __init__(self, vmlinux, addr_bytes, log_path = None, debug=False, log_suffix=""):
        self._vmlinux = vmlinux
        self._prompt = "gdbbot"
        self.gdb_inst = None
        self.s_mem = 'g'
        self.s_group = 8
        self._log_suffix = log_suffix
        self._debug = debug
        if addr_bytes == 4:
            self.s_mem = 'w'
            self.s_group = 4
        #log.propagate = debug
        #context.log_level = 'error'
        self.gdb_inst = process(["gdb", self._vmlinux])
        self.logger = self._init_logger(log_path)
    
    def _init_logger(self, log_path):
        logger = logging.getLogger(__name__+"-{}".format(self._vmlinux))
        if len(logger.handlers) != 0:
            for each_handler in logger.handlers:
                logger.removeHandler(each_handler)
        handler = logging.FileHandler("{}/gdb.log{}".format(log_path, self._log_suffix))
        format = logging.Formatter('%(asctime)s %(message)s')
        handler.setFormatter(format)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.propagate = False
        if self._debug:
            logger.setLevel(logging.DEBUG)
        return logger
    
    def is_pwndbg(self):
        raw = self.sendline('version')
        for line in raw.split('\n'):
            line = line.strip('\n')
            line = line.strip()
            versions = line.split(':')
            if 'Pwndbg' in versions[0]:
                return True
        return False
    
    def connect(self, port):
        self.sendline('target remote :{}'.format(port), timeout=10)
    
    def set_breakpoint(self, addr):
        self.sendline('break *{}'.format(addr))
    
    def del_breakpoint(self, num=-1):
        if num == -1:
            self.sendline("d")
        else:
            self.sendline('d {}'.format(num))

    def resume(self):
        self._sendline('continue')
        #print("QEMU is running")
    
    def waitfor(self, pattern, timeout=5):
        try:
            text = self.gdb_inst.recvuntil(pattern.encode(), timeout=timeout)
        except EOFError:
            raise QemuIsDead
        self.logger.info(text.decode("utf-8"))
        if self._debug:
            print(text.decode("utf-8"))
        return text.decode("utf-8")
    
    def get_mem_content(self, addr, size):
        ret = []
        regx_mem_contect = r'0x[a-f0-9]+( <[A-Za-z0-9_.\+]+>)?:\W+(0x[a-f0-9]+)(\W+(0x[a-f0-9]+))?'
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
    
    def get_registers(self):
        ret = {}
        regx_regs = r'([0-9a-z]+)\W+(0x[0-9a-f]+)'
        cmd = 'info registers'
        raw = self.sendline(cmd)
        for line in raw.split('\n'):
            line = line.strip('\n')
            reg = utilities.regx_get(regx_regs, line, 0)
            val = utilities.regx_get(regx_regs, line, 1)
            if reg != None and val != None:
                ret[reg] = int(val, 16)
        return ret
    
    def get_register(self, reg):
        ret = None
        regx_regs = r'([0-9a-z]+)\W+(0x[0-9a-f]+)'
        cmd = 'info r {}'.format(reg)
        raw = self.sendline(cmd)
        for line in raw.split('\n'):
            line = line.strip('\n')
            val = utilities.regx_get(regx_regs, line, 1)
            if val != None:
                ret = int(val, 16)
        return ret
    
    def get_sections(self):
        ret = {}
        cmd = 'elfheader'
        regx_sections = r'(0x[0-9a-f]+) - (0x[0-9a-f]+)  (.*)'
        raw = self.sendline(cmd)
        for line in raw.split('\n'):
            line = line.strip('\n')
            s = utilities.regx_get(regx_sections, line, 0)
            e = utilities.regx_get(regx_sections, line, 1)
            name = utilities.regx_get(regx_sections, line, 2)
            if s != None and e != None and name != None:
                ret[name] = {}
                ret[name]['start'] = int(s, 16)
                ret[name]['end'] = int(e, 16)
        return ret
    
    def get_stack_range(self):
        ret = []
        cmd = 'vmmap'
        regx_stack = r'(0x[0-9a-f]+) (0x[0-9a-f]+) .*\[stack\]'
        raw = self.sendline(cmd)
        for line in raw.split('\n'):
            line = line.strip('\n')
            s = utilities.regx_get(regx_stack, line, 0)
            e = utilities.regx_get(regx_stack, line, 1)
            if s != None and e != None:
                ret.append(s)
                ret.append(e)
                break
        return ret
    
    def get_backtrace(self, n=None):
        ret = []
        cmd = 'bt'
        regx_bt = r'#\d+( )+([A-Za-z0-9_.]+)'
        raw = self.sendline(cmd)
        for line in raw.split('\n'):
            line = line.strip('\n')
            func_name = utilities.regx_get(regx_bt, line, 1)
            if func_name != None:
                ret.append(func_name)
            if len(ret) >= n:
                break
        return ret
    
    def set_scheduler_mode(self, mode):
        cmd = 'set scheduler-locking {}'.format(mode)
        self.sendline(cmd)
    
    def finish_cur_func(self):
        cmd = 'finish'
        self.sendline(cmd)
    
    def print_code(self, addr, n_line):
        cmd = 'x/{}i {}'.format(n_line, addr)
        raw = self.sendline(cmd)
        return raw
    
    def get_func_name(self, addr):
        func_name_regx = r'0x[a-f0-9]+ <([a-zA-Z0-9_\.]+)(\+\d+)?>:'
        raw = self.print_code(addr, 1)
        ret = None
        for line in raw.split('\n'):
            line = line.strip('\n')
            line = self._escape_ansi(line)
            name = utilities.regx_get(func_name_regx, line, 0)
            if name != None:
                ret = name
        # we dont need refresh again since it was done in print_code()
        return ret
    
    def get_dbg_info(self, addr):
        cmd = 'info line *{}'.format(addr)
        raw = self.sendline(cmd)
        #example input: 'Line 2852 of "net/core/skbuff.c" starts at address 0xffffffff83f0ad69 <skb_queue_purge+25> and ends at 0xffffffff83f0ad79 <skb_queue_purge+41>.\npwndbg>'
        dbg_info_regx = r'Line (\d+) of "(.+)" starts at address'
        ret = []
        for line in raw.split('\n'):
            line = line.strip('\n')
            dbg_file = utilities.regx_get(dbg_info_regx, line, 1)
            dbg_line = utilities.regx_get(dbg_info_regx, line, 0)
            if dbg_file != None and dbg_line != None:
                ret.append(dbg_file)
                ret.append(dbg_line)
        return ret
    
    def refresh(self):
        self._sendline('echo')

    def sendline(self, cmd, timeout=5):
        #print("send", cmd)
        self._sendline(cmd)
        raw = self.waitfor("pwndbg>", timeout)
        return self._escape_ansi(raw)
    
    def recv(self):
        return self.gdb_inst.recv()

    def close(self):
        self.gdb_inst.kill()

    def _sendline(self, cmd):
        self.gdb_inst.sendline(cmd.encode())
    
    def _escape_ansi(self, line):
        ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', line)

    def command(self, cmd):
        ret = list()
        try:
            init = [
                "gdb", self._vmlinux, "-ex",
                "set prompt %s" % self._prompt
            ]
            gdb = Popen(init, stdout=PIPE, stdin=PIPE, stderr=PIPE)
            outs, errs = gdb.communicate(cmd.encode(), timeout=20)
            start = False
            for line in outs.decode().split("\n"):
                # print(line)
                if line.startswith(self._prompt):
                    start = True
                if self._prompt + "quit" in line:
                    break
                if start:
                    if line.startswith(self._prompt):
                        line = line[len(self._prompt):]
                    ret.append(line)
            gdb.kill()
        except TimeoutExpired:
            self.gdb.kill()
        return ret

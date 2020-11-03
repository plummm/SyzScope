import os
import angr

from pwn import *
from .kernel import Kernel

class VMState:
    ADDRESS = 1
    INITIAL = 0

    def __init__(self, linux, gdb_port, arch):
        self.linux = os.path.join(linux, "vmlinux")
        self.gdb_port = gdb_port
        self.vm = None
        self._kasan_report = 0
        self._kasan_ret = 0
        self.kernel = None
        self.addr_len = 64
        if arch == 'i385':
            self.addr_len = 32
        VMState.INITIAL = 1

    def connect(self, port):
        if self.__check_initialization():
            return
        self.kernel = Kernel(self.linux, self.addr_len)
        self.gdb = self.kernel.gdbhelper
        kasan_report, kasan_ret = self.kernel.getKasanReport()
        self.waitfor_pwndbg()
        self.gdb.connect(port)
        self.gdb.set_breakpoint(kasan_report)
        self.gdb.resume()
    
    def reach_vul_site(self, addr):
        if self.__check_initialization():
            return
        self.waitfor_pwndbg()
        self.gdb.set_breakpoint(addr)
        self.gdb.resume()
    
    def read_mem(self, addr, size):
        if self.__check_initialization():
            return
        self.waitfor_pwndbg()
        mem = self.gdb.get_mem_content(addr, size)
        if len(mem) == 1 and size < 8:
            val = int(mem[0], 16)
            if size == 4:
                val = val - (val >> 32 << 32)
            if size == 2:
                val = val - (val >> 16 << 16)
            if size == 1:
                val = val - (val >> 8 << 8)
            mem = [hex(val)]

        return mem
    
    def read_regs(self):
        if self.__check_initialization():
            return
        self.waitfor_pwndbg()
        regs = self.gdb.get_registers()
        return regs
    
    def read_reg(self, reg):
        if self.__check_initialization():
            return
        self.waitfor_pwndbg()
        val = self.gdb.get_register(reg)
        return val

    def waitfor_pwndbg(self):
        self.gdb.waitfor("pwndbg>")

    def __check_initialization(self):
        return not VMState.INITIAL

    



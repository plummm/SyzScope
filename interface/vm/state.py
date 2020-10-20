import os
import angr

from pwn import *
from .kernel import Kernel

class VMState:
    ADDRESS = 1

    def __init__(self, linux, gdb_port = 1234):
        self.linux = os.path.join(linux, "vmlinux")
        self.gdb_port = gdb_port
        self.vm = None
        self._kasan_report = 0
        self._kasan_ret = 0
        self.kernel = Kernel(self.linux)
        self.gdb = self.kernel.gdbhelper

    def connect(self, port):
        kasan_report, kasan_ret = self.kernel.getKasanReport()
        self.waitfor_pwndbg()
        self.gdb.connect(port)
        self.gdb.set_breakpoint(kasan_report)
        self.gdb.resume()
    
    def reach_vul_site(self, addr):
        self.waitfor_pwndbg()
        self.gdb.set_breakpoint(addr)
        self.gdb.resume()
    
    def read_mem(self, addr, size):
        self.waitfor_pwndbg()
        mem = self.gdb.get_mem_content(addr, size)
        print(mem)

    def waitfor_pwndbg(self):
        self.gdb.waitfor("pwndbg>")

    



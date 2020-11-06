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
        self._sections = None
        self.stack_addr = [0,0]
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
    
    def read_section(self, name=None):
        if self.__check_initialization():
            return
        self.waitfor_pwndbg()
        if self._sections == None:
            self._sections = self.gdb.get_sections()
        if name in self._sections:
            return self._sections[name]
        return self._sections
    
    def read_stack_range(self):
        if self.__check_initialization():
            return
        self.waitfor_pwndbg()
        if self.stack_addr[0] == 0 and self.stack_addr[1] == 0:
            ret = self.gdb.get_stack_range()
            if len(ret) == 2:
                self.stack_addr[0] = int(ret[0], 16)
                self.stack_addr[1] = int(ret[1], 16)
                return self.stack_addr[0], self.stack_addr[1]
        return 0, 0
    
    # results are inaccurate due to the false postive from gdb, will be removed in future 
    def locate_vul_site(self):
        if self.__check_initialization():
            return
        self.waitfor_pwndbg()
        index = -1
        bt = self.gdb.get_backtrace()
        extra_check = False
        kasan_entries = ["__kasan_check_read", "__kasan_check_write", \
            "__asan_store1", "__asan_store2", "__asan_store4", "__asan_store8", "__asan_store16", \
            "__asan_load1", "__asan_load2", "__asan_load4", "__asan_load8", "__asan_load16"]
        for i in range(0, len(bt)):
            each = bt[i]
            if each == "check_memory_region":
                extra_check = True
                continue
            if each in kasan_entries:
                index = i+1
                break
            if extra_check:
                # check_memory_region can be both entry and callee of other entries
                index = i
                break
        return index
    
    def back_to_vul_site(self):
        if self.__check_initialization():
            return
        kasan_entries = ["__kasan_check_read", "__kasan_check_write", \
            "__asan_store1", "__asan_store2", "__asan_store4", "__asan_store8", "__asan_store16", \
            "__asan_load1", "__asan_load2", "__asan_load4", "__asan_load8", "__asan_load16"]
        cmd = 'finish'
        exit_flag = False
        extra_check = False
        while True:
            self.waitfor_pwndbg()
            self.gdb.sendline(cmd)
            bt = self.gdb.get_backtrace(1)
            if exit_flag:
                break
            if len(bt) > 0:
                if bt[0] == "check_memory_region":
                    extra_check = True
                    continue
                if bt[0] in kasan_entries:
                    exit_flag = True
                    continue
                if extra_check:
                    break
    
    def is_on_stack(self, addr):
        if self.stack_addr[0] == 0 and self.stack_addr[1] == 0:
            print("Stack range is unclear")
            return False
        return addr >= self.stack_addr[0] and addr <= self.stack_addr[1]
    
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
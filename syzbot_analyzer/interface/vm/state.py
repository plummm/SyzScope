import os
import angr

from pwn import *
from .kernel import Kernel
from .monitor import Monitor

class VMState:
    ADDRESS = 1
    INITIAL = 0

    def __init__(self, linux, gdb_port, arch, log_suffix="", proj_path=None, debug=False):
        self.linux = os.path.join(linux, "vmlinux")
        self.gdb_port = gdb_port
        self.vm = None
        self._kasan_report = 0
        self._kasan_ret = 0
        self._proj_path = proj_path
        self.kernel = None
        self.addr_bytes = 8
        self.log_suffix = log_suffix
        self.gdb = None
        self.mon = None
        self.debug = debug
        if arch == 'i386':
            self.addr_bytes = 4
        self._sections = None
        self.stack_addr = [0,0]
        self.kasan_addr = [0,[]]
        VMState.INITIAL = 1

    def gdb_connect(self, port):
        if self.__check_initialization():
            return
        if self.debug:
            print("Loading kernel, this process may take a while")
        self.kernel = Kernel(self.linux, self.addr_bytes, self._proj_path, self.log_suffix, self.debug)
        self.gdb = self.kernel.gdbhelper
        self.waitfor_pwndbg()
        self.gdb.connect(port)
    
    def mon_connect(self, port):
        if self.__check_initialization():
            return
        self.mon = Monitor(port, self.addr_bytes, self._proj_path, self.log_suffix, self.debug)
        self.mon.connect()
    
    def set_checkpoint(self):
        if self.__check_initialization():
            return
        kasan_report, kasan_ret = self.kernel.getKasanReport()
        if kasan_report == None:
            return False
        self.gdb.set_breakpoint(kasan_report)
        self.gdb.resume()
        self.kasan_addr[0] = kasan_report
        self.kasan_addr[1] = kasan_ret
        return True

    def lock_thread(self):
        if self.__check_initialization():
            return
        self.gdb.set_scheduler_mode('on')

    def unlock_thread(self):
        if self.__check_initialization():
            return
        self.gdb.set_scheduler_mode('off')
    
    def reach_target_site(self, addr):
        if self.__check_initialization():
            return
        self.gdb.set_breakpoint(addr)
        self.gdb.resume()
    
    def read_mem(self, addr, size):
        if self.__check_initialization():
            return
        mem = self.mon.get_mem_content(addr, size)
        if len(mem) == 1 and size < 8:
            val = mem[0]
            if size == 4 and self.addr_bytes == 8:
                val = val - (val >> 32 << 32)
            if size == 2:
                val = val - (val >> 16 << 16)
            if size == 1:
                val = val - (val >> 8 << 8)
            mem = [val]

        return mem
    
    def read_section(self, name=None):
        if self.__check_initialization():
            return
        if self._sections == None:
            self._sections = self.gdb.get_sections()
        if name in self._sections:
            return self._sections[name]
        return self._sections
    
    def read_stack_range(self):
        if self.__check_initialization():
            return
        if self.stack_addr[0] == 0 and self.stack_addr[1] == 0:
            ret = self.gdb.get_stack_range()
            if len(ret) == 2:
                self.stack_addr[0] = int(ret[0], 16)
                self.stack_addr[1] = int(ret[1], 16)
                return self.stack_addr[0], self.stack_addr[1]
        return 0, 0
    
    def back_to_kasan_ret(self):
        if self.__check_initialization():
            return
        if len(self.kasan_addr[1]) > 0:
            for each in self.kasan_addr[1]:
                self.gdb.set_breakpoint(each)
        self.gdb.resume()

    def back_to_caller(self):
        if self.__check_initialization():
            return
        self.gdb.finish_cur_func()

    def inspect_code(self, addr, n_line):
        if self.__check_initialization():
            return
        return self.gdb.print_code(addr, n_line)
    
    def read_backtrace(self, n):
        if self.__check_initialization():
            return
        bt = self.gdb.get_backtrace(n)
        return bt
    
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
        regs = self.mon.get_registers()
        if 'eflags' not in regs:
            val = self.gdb.get_register('eflags')
            if val != None:
                regs['eflags'] = val
        return regs
    
    def prepare_context(self, pc):
        index = self.mon.choose_cpu(pc)
        self.mon.set_cpu(index)
    
    def read_reg(self, reg, timeout=5):
        if self.__check_initialization():
            return
        val = self.mon.get_register(reg)
        return val
    
    def get_func_name(self, addr):
        if self.__check_initialization():
            return
        return self.gdb.get_func_name(addr)
    
    def get_dbg_info(self, addr):
        if self.__check_initialization():
            return
        file = None
        line = None
        ret = self.gdb.get_dbg_info(addr)
        if len(ret) == 2:
            file, line = ret[0], ret[1]
        return file, line

    def waitfor_pwndbg(self, timeout=5):
        self.gdb.waitfor("pwndbg>", timeout)

    def __check_initialization(self):
        return not VMState.INITIAL
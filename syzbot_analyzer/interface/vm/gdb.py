from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
from pwn import *

import time
import pexpect
import math
import syzbot_analyzer.interface.utilities as utilities


class GDBHelper:
    def __init__(self, vmlinux):
        self._vmlinux = vmlinux
        self._prompt = "gdbbot"
        self.gdb_inst = process(["gdb", self._vmlinux])
        context.log_level = 'info'
    
    def connect(self, port):
        self.sendline('target remote :{}'.format(port))
        self.waitfor("pwndbg>")
    
    def set_breakpoint(self, addr):
        self.sendline('break *{}'.format(addr))
        self.waitfor("pwndbg>")

    def resume(self):
        self.sendline('continue')
        print("QEMU is running")
    
    def waitfor(self, pattern):
        text = self.gdb_inst.recvuntil(pattern)
        #print(text.decode("utf-8"))
        return text.decode("utf-8")
    
    def get_mem_content(self, addr, size):
        ret = []
        regx_mem_contect = r'0x[a-f0-9]+:\W+(0x[a-f0-9]+)(\W+(0x[a-f0-9]+))?'
        group = math.ceil(size / 8)
        cmd = 'x/{}gx {}'.format(group, hex(addr))
        self.sendline(cmd)
        raw = self.waitfor("pwndbg>")
        for line in raw.split('\n'):
            line = line.strip('\n')
            mem = utilities.regx_get(regx_mem_contect, line, 0)
            if mem == None:
               break
            ret.append(mem)
            mem = utilities.regx_get(regx_mem_contect, line, 2)
            if mem == None:
                break
            ret.append(mem)
        self.refresh()
        return ret
    
    def get_registers(self):
        ret = {}
        regx_regs = r'([0-9a-z]+)\W+(0x[0-9a-f]+)'
        cmd = 'info registers'
        self.sendline(cmd)
        raw = self.waitfor("pwndbg>")
        for line in raw.split('\n'):
            line = line.strip('\n')
            reg = utilities.regx_get(regx_regs, line, 0)
            val = utilities.regx_get(regx_regs, line, 1)
            if reg != None and val != None:
                ret[reg] = val
        self.refresh()
        return ret
    
    def get_register(self, reg):
        ret = None
        regx_regs = r'([0-9a-z]+)\W+(0x[0-9a-f]+)'
        cmd = 'info r {}'.format(reg)
        self.sendline(cmd)
        raw = self.waitfor("pwndbg>")
        for line in raw.split('\n'):
            line = line.strip('\n')
            val = utilities.regx_get(regx_regs, line, 1)
            if val != None:
                ret = val
        self.refresh()
        return ret
    
    def get_sections(self):
        ret = {}
        cmd = 'elfheader'
        regx_sections = r'(0x[0-9a-f]+) - (0x[0-9a-f]+)  (.*)'
        self.sendline(cmd)
        raw = self.waitfor("pwndbg>")
        for line in raw.split('\n'):
            line = line.strip('\n')
            s = utilities.regx_get(regx_sections, line, 0)
            e = utilities.regx_get(regx_sections, line, 1)
            name = utilities.regx_get(regx_sections, line, 2)
            if s != None and e != None and name != None:
                ret[name] = {}
                ret[name]['start'] = int(s, 16)
                ret[name]['end'] = int(e, 16)
        self.refresh()
        return ret
    
    def refresh(self):
        self.sendline('echo')

    def sendline(self, cmd):
        #print("send", cmd)
        self.gdb_inst.sendline(cmd)
    
    def recv(self):
        return self.gdb_inst.recv()

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

    def commands(self, cmds):
        ret = list()
        try:
            init = [
                "gdb", self._vmlinux, "-ex",
                "\"set prompt %s\"" % self._prompt
            ]
            gdb = pexpect.spawn(' '.join(init))
            gdb.expect(self._prompt)
            for cmd in cmds:
                gdb.sendline(cmd)
                gdb.expect(self._prompt)
            outs = gdb.before
            gdb.close()
            for line in outs.decode().split("\n"):
                ret.append(line.strip())
        except pexpect.TIMEOUT:
            gdb.close()
        return ret

    def commandstr(self, cmd):
        ret = self.command(cmd)
        return ''.join(ret)


if __name__ == '__main__':
    gdb = GDBHelper(
        "/media/weiteng/ubuntu/Workspace/syzkaller/linux/linux-next/vmlinux")
    # out = gdb.command("p &((struct task_struct *)0)->xxxx")
    # out = gdb.commands(["b crypto/dh_helper.c:21", "info b"])
    out = gdb.commandstr(
        "python print([hex(x.pc) for x in gdb.decode_line(\"crypto/dh_helper.c:21\")[1]])"
    )
    print(out)

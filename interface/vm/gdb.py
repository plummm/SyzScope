from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
from pwn import *

import time
import pexpect
import math
import interface.utilities as utilities


class GDBHelper:
    def __init__(self, vmlinux):
        self._vmlinux = vmlinux
        self._prompt = "gdbbot"
        self.gdb_inst = process(["gdb", self._vmlinux])
        context.log_level = 'info'
    
    def connect(self, port):
        self.gdb_inst.sendline('target remote :{}'.format(port))
        self.waitfor("pwndbg>")
    
    def set_breakpoint(self, addr):
        self.gdb_inst.sendline('break *{}'.format(addr))
        self.waitfor("pwndbg>")

    def resume(self):
        self.gdb_inst.sendline('continue')
    
    def waitfor(self, pattern):
        text = self.gdb_inst.recvuntil(pattern)
        print(text.decode("utf-8"))
        return text.decode("utf-8")
    
    def get_mem_content(self, addr, size):
        ret = []
        regx_mem_contect = r'0x[a-f0-9]+:\W+(0x[a-f0-9]+)\W+(0x[a-f0-9]+)'
        group = math.ceil(size / 8)
        cmd = 'x/{}gx {}'.format(group, hex(addr))
        self.gdb_inst.sendline(cmd)
        raw = self.waitfor("pwndbg>")
        for line in raw.split('\n'):
            line = line.strip('\n')
            mem0 = utilities.regx_get(regx_mem_contect, line, 0)
            mem1 = utilities.regx_get(regx_mem_contect, line, 1)
            if mem0 != None and mem1 != None:
                ret.extend([mem0, mem1])
        return ret
    
    def sendline(self, cmd):
        self.gdb_inst.sendline(cmd)

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

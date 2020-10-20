import os
from subprocess import Popen, PIPE, STDOUT

class S2EInterface:
    def __init__(self, s2e_path, kernel_path, syzkaller_path):
        self.s2e_path = s2e_path
        self.kernel_path = kernel_path
        self.syzkaller_path = syzkaller_path

    def getAvoidingPC(self, func_list):
        avoid = {}
        func2addr = os.path.join(self.syzkaller_path, "bin/syz-fun2addr")
        for each_func in func_list:
            avoid[each_func] = []
            cmd = [func2addr, "-f", each_func, "-v", self.kernel_path]
            p = Popen(cmd,
                    stdout=PIPE,
                    stderr=STDOUT)
            with p.stdout:
                for line in iter(p.stdout.readline, b''):
                    line = line.decode("utf-8").strip('\n').strip('\r')
                    res = line.split(':')
                    if len(res) == 2:
                        if res[0] == 'Start':
                            addr = int(res[1], 16)
                            avoid[each_func].append(addr)
                        if res[0] == 'End':
                            addr = int(res[1], 16)
                            avoid[each_func].append(addr)
        return avoid

    def generateAvoidList(self, avoid, s2e_project_path):
        avoid_list_path = os.path.join(s2e_project_path, "avoid")
        f = open(avoid_list_path, 'w')
        for func in avoid:
            for i in range(0, len(avoid[func]), 2):
                start = avoid[func][i]
                end = avoid[func][i+1]
                text = "{} {}\n".format(hex(start), hex(end))
                f.write(text)
        f.close()


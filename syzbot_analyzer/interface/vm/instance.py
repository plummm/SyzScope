import threading
import logging
import os
import syzbot_analyzer.interface.utilities as utilities

from subprocess import Popen, PIPE, STDOUT, call


class VMInstance:
    QEMU_READY = 0

    def __init__(self, proj_path='/tmp/', log_name='vm.log', debug=False):
        self.proj_path = proj_path
        self.port = None
        self.image = None
        self.linux = None
        self.log = None
        self.cmd_launch = None
        self.debug = debug
        self.qemu_logger = None
        self.def_opts = ["kasan_multi_shot=1", "earlyprintk=serial", "oops=panic", "nmi_watchdog=panic", "panic=1", \
                        "ftrace_dump_on_oops=orig_cpu", "rodata=n", "vsyscall=native", "net.ifnames=0", \
                        "biosdevname=0", "kvm-intel.nested=1", \
                        "kvm-intel.unrestricted_guest=1", "kvm-intel.vmm_exclusive=1", \
                        "kvm-intel.fasteoi=1", "kvm-intel.ept=1", "kvm-intel.flexpriority=1", \
                        "kvm-intel.vpid=1", "kvm-intel.emulate_invalid_guest_state=1", \
                        "kvm-intel.eptad=1", "kvm-intel.enable_shadow_vmcs=1", "kvm-intel.pml=1", \
                        "kvm-intel.enable_apicv=1"]
        self.log = self.init_logger(os.path.join(proj_path, log_name))

    def init_logger(self, log_path):
        log = open(log_path, "a")
        return log

    def close_logger(self):
        if self.log != None:
            self.log.close()
        return

    def setup(self, port, image, linux, mem="2G", cpu="2", key=None, gdb_port=None, opts=None):
        cur_opts = ["root=/dev/sda", "console=ttyS0"]
        gdb_arg = ""
        self.port = port
        self.image = image
        self.linux = linux
        self.key = key
        self.cmd_launch = ["qemu-system-x86_64", "-m", mem, "-smp", cpu]
        if gdb_port != None:
            self.cmd_launch.extend(["-gdb", "tcp::{}".format(gdb_port)])
        if self.port != None:
            self.cmd_launch.extend(["-net", "nic,model=e1000", "-net", "user,host=10.0.2.10,hostfwd=tcp::{}-:22".format(self.port)])
        self.cmd_launch.extend(["-display", "none", "-serial", "stdio", "-no-reboot", "-enable-kvm", "-cpu", "host,migratable=off", 
                    "-hda", "{}/stretch.img".format(self.image), 
                    "-snapshot", "-kernel", "{}/arch/x86_64/boot/bzImage".format(self.linux),
                    "-append"])
        if opts == None:
            cur_opts.extend(self.def_opts)
        else:
            cur_opts.extend(opts)
        if type(cur_opts) == list:
            self.cmd_launch.append(" ".join(cur_opts))
        return
        
    def run(self):
        p = Popen(self.cmd_launch, stdout=PIPE, stderr=STDOUT)
        self.p = p
        x = threading.Thread(target=self.__log_qemu, args=(p.stdout,))
        x.start()
        return p

    def upload(self, stuff: list):
        cmd = ["scp", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
               "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-i", "".format(self.key), 
               "-P", "".format(self.port), " ".join(stuff), "root@localhost:/root"]
        Popen(cmd, stdout=PIPE, stderr=STDOUT)

    def command(self, cmds):
        cmd = ["ssh", "-p", str(self.port), "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
        "-o", "ConnectTimeout=10", "-i", "".format(self.key), 
        "-v", "root@localhost", "".format(cmds)]
        p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, self.log)
    
    def __log_qemu(self, pipe):
        for line in iter(pipe.readline, b''):
            line = line.decode("utf-8").strip('\n').strip('\r')
            if utilities.regx_match('syzkaller', line):
                VMInstance.QEMU_READY = 1
            if self.debug:
                print(line)
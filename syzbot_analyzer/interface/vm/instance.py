from inspect import formatannotation
import threading
import logging
import time
import os
import syzbot_analyzer.interface.utilities as utilities

from subprocess import Popen, PIPE, STDOUT, call


class VMInstance:

    def __init__(self, proj_path='/tmp/', log_name='vm.log', logger=None, debug=False):
        self.proj_path = proj_path
        self.port = None
        self.image = None
        self.linux = None
        self.cmd_launch = None
        self.timeout = None
        self.case_logger = None
        self.debug = debug
        self.qemu_logger = None
        self.qemu_ready = False
        self.kill_qemu = False
        self.def_opts = ["kasan_multi_shot=1", "earlyprintk=serial", "oops=panic", "nmi_watchdog=panic", "panic=1", \
                        "ftrace_dump_on_oops=orig_cpu", "rodata=n", "vsyscall=native", "net.ifnames=0", \
                        "biosdevname=0", "kvm-intel.nested=1", \
                        "kvm-intel.unrestricted_guest=1", "kvm-intel.vmm_exclusive=1", \
                        "kvm-intel.fasteoi=1", "kvm-intel.ept=1", "kvm-intel.flexpriority=1", \
                        "kvm-intel.vpid=1", "kvm-intel.emulate_invalid_guest_state=1", \
                        "kvm-intel.eptad=1", "kvm-intel.enable_shadow_vmcs=1", "kvm-intel.pml=1", \
                        "kvm-intel.enable_apicv=1"]
        self.qemu_logger = self.init_logger(os.path.join(proj_path, log_name))
        if logger != None:
            self.case_logger = logger
        self._qemu = None

    def init_logger(self, log_path):
        handler = logging.FileHandler(log_path)
        format = logging.Formatter('%(message)s')
        handler.setFormatter(format)
        logger = logging.getLogger(log_path)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if self.debug:
            logger.setLevel(logging.DEBUG)
        return logger

    def setup(self, port, image, linux, mem="2G", cpu="2", key=None, gdb_port=None, mon_port=None, opts=None, timeout=None):
        cur_opts = ["root=/dev/sda", "console=ttyS0"]
        gdb_arg = ""
        self.port = port
        self.image = image
        self.linux = linux
        self.key = key
        self.timeout = timeout
        self.cmd_launch = ["qemu-system-x86_64", "-m", mem, "-smp", cpu]
        if gdb_port != None:
            self.cmd_launch.extend(["-gdb", "tcp::{}".format(gdb_port)])
        if mon_port != None:
            self.cmd_launch.extend(["-monitor", "tcp::{},server,nowait,nodelay,reconnect=-1".format(mon_port)])
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
        self.write_cmd_to_script(self.cmd_launch, "launch_vm.sh")
        return
        
    def run(self):
        p = Popen(self.cmd_launch, stdout=PIPE, stderr=STDOUT)
        x1 = threading.Thread(target=self.__log_qemu, args=(p.stdout,))
        x1.start()

        if self.timeout != None:
            x2 = threading.Thread(target=self.monitor_execution, args=(p,))
            x2.start()
        self._qemu = p
        return p

    def kill_vm(self):
        self._qemu.kill()
    
    def write_cmd_to_script(self, cmd, name):
        path_name = os.path.join(self.proj_path, name)
        prefix = []
        with open(path_name, "w") as f:
            for i in range(0, len(cmd)):
                each = cmd[i]
                prefix.append(each)
                if each == '-append':
                    f.write(" ".join(prefix))
                    f.write(" \"")
                    f.write(" ".join(cmd[i+1:]))
                    f.write("\"")
            f.close()

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
    
    def monitor_execution(self, p):
        count = 0
        while (count <self.timeout/10):
            if self.kill_qemu:
                self.case_logger.info('Signal kill qemu received.')
                p.kill()
                return
            count += 1
            time.sleep(10)
            poll = p.poll()
            if poll != None:
                return
        self.case_logger.info('Time out, kill qemu')
        p.kill()
    
    def __log_qemu(self, pipe):
        try:
            for line in iter(pipe.readline, b''):
                line = line.decode("utf-8").strip('\n').strip('\r')
                if utilities.regx_match(r'Debian GNU\/Linux \d+ syzkaller ttyS\d+', line):
                    self.qemu_ready = True
                self.qemu_logger.info(line+'\n')
                if self.debug:
                    print(line)
        except:
            # Qemu may crash and makes pipe NULL
            return
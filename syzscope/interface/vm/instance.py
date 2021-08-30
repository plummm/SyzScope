from inspect import formatannotation
import threading
import logging
import time
import os
import syzscope.interface.utilities as utilities

from subprocess import Popen, PIPE, STDOUT, call

reboot_regx = r'reboot: machine restart'
port_error_regx = r'Could not set up host forwarding rule'

class VMInstance:

    def __init__(self, hash_tag, proj_path='/tmp/', log_name='vm.log', log_suffix="", logger=None, debug=False):
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
        self.hash_tag = hash_tag
        self.log_name = log_name
        self.output = []
        self.def_opts = ["kasan_multi_shot=1", "earlyprintk=serial", "oops=panic", "nmi_watchdog=panic", "panic=1", \
                        "ftrace_dump_on_oops=orig_cpu", "rodata=n", "vsyscall=native", "net.ifnames=0", \
                        "biosdevname=0", "kvm-intel.nested=1", \
                        "kvm-intel.unrestricted_guest=1", "kvm-intel.vmm_exclusive=1", \
                        "kvm-intel.fasteoi=1", "kvm-intel.ept=1", "kvm-intel.flexpriority=1", \
                        "kvm-intel.vpid=1", "kvm-intel.emulate_invalid_guest_state=1", \
                        "kvm-intel.eptad=1", "kvm-intel.enable_shadow_vmcs=1", "kvm-intel.pml=1", \
                        "kvm-intel.enable_apicv=1"]
        log_name += log_suffix
        self.qemu_logger = self.init_logger(os.path.join(proj_path, log_name))
        self.case_logger = self.qemu_logger
        if logger != None:
            self.case_logger = logger
        self._qemu = None

    def init_logger(self, log_path):
        handler = logging.FileHandler(log_path)
        format = logging.Formatter('%(message)s')
        handler.setFormatter(format)
        logger = logging.getLogger(log_path)
        for each_handler in logger.handlers:
            logger.removeHandler(each_handler)
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
            self.cmd_launch.extend(["-monitor", "tcp::{},server,nowait,nodelay".format(mon_port)])
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
        self._qemu = p
        if self.timeout != None:
            x = threading.Thread(target=self.monitor_execution, name="{} qemu killer".format(self.hash_tag))
            x.start()
        x1 = threading.Thread(target=self.__log_qemu, args=(p.stdout,), name="{} qemu logger".format(self.hash_tag))
        x1.start()

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
    
    def monitor_execution(self):
        count = 0
        while (count <self.timeout/10):
            if self.kill_qemu:
                self.case_logger.info('Signal kill qemu received.')
                self._qemu.kill()
                return
            count += 1
            time.sleep(10)
            poll = self._qemu.poll()
            if poll != None:
                return
        self.case_logger.info('Time out, kill qemu')
        self._qemu.kill()
    
    def __log_qemu(self, pipe):
        try:
            self.qemu_logger.info("\n".join(self.cmd_launch)+"\n")
            self.qemu_logger.info("pid: {}".format(self._qemu.pid))
            for line in iter(pipe.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    self.qemu_logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                if utilities.regx_match(reboot_regx, line) or utilities.regx_match(port_error_regx, line):
                    self.case_logger.error("Booting qemu-{} failed".format(self.log_name))
                if utilities.regx_match(r'Debian GNU\/Linux \d+ syzkaller ttyS\d+', line):
                    self.qemu_ready = True
                self.qemu_logger.info(line)
                if self.debug:
                    print(line)
                self.output.append(line)
        except EOFError:
            # Qemu may crash and makes pipe NULL
            pass
        except ValueError:
            # Traceback (most recent call last):                                                                       │
            # File "/usr/lib/python3.6/threading.py", line 916, in _bootstrap_inner                                  │
            # self.run()                                                                                           │
            # File "/usr/lib/python3.6/threading.py", line 864, in run                                               │
            # self._target(*self._args, **self._kwargs)                                                            │
            # File "/home/xzou017/projects/SyzbotAnalyzer/syzscope/interface/vm/instance.py", line 140, in __log_qemu                                                                                                  │
            # for line in iter(pipe.readline, b''):                                                                │
            # ValueError: PyMemoryView_FromBuffer(): info->buf must not be NULL
            pass
        self.qemu_ready = False
        return
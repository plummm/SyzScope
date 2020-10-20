from subprocess import Popen, PIPE, STDOUT


class VMInstance:
    def __init__(self, log_path=None):
        self.port = None
        self.image = None
        self.linux = None
        self.log = None
        self.cmd = None
        self.def_opts = ["kasan_multi_shot=1", " earlyprintk=serial", " oops=panic", " nmi_watchdog=panic", " panic=1", \
                        "ftrace_dump_on_oops=orig_cpu", " rodata=n", " vsyscall=native", " net.ifnames=0", \
                        "biosdevname=0", " kvm-intel.nested=1", \
                        "kvm-intel.unrestricted_guest=1", " kvm-intel.vmm_exclusive=1", \
                        "kvm-intel.fasteoi=1", " kvm-intel.ept=1", " kvm-intel.flexpriority=1", \
                        "kvm-intel.vpid=1", " kvm-intel.emulate_invalid_guest_state=1", \
                        "kvm-intel.eptad=1", " kvm-intel.enable_shadow_vmcs=1", " kvm-intel.pml=1", \
                        "kvm-intel.enable_apicv=1"]
        if log_path != None:
            self.log = self.init_logger(log_path)

    def init_logger(self, log_path):
        log = open(log_path, "a")
        return log

    def close_logger(self):
        if self.log != None:
            self.log.close()
        return

    def setup(self, port, image, linux, mem="2G", cpu="2", gdb_port=None, opts=None):
        cur_opts = None
        gdb_arg = ""
        self.port = port
        self.image = image
        self.linux = linux
        self.cmd = ["qemu-system-x86_64", "-m", mem, "-smp", cpu]
        if gdb_port != None:
            self.cmd.extend(["-gdb", "tcp::{}".format(gdb_port)])
        if self.port != None:
            self.cmd.extend(["-net", "nic,model=e1000", "-net", "user,host=10.0.2.10,hostfwd=tcp::{}-:22".format(self.port)])
        self.cmd.extend(["-display", "none", "-serial", "stdio", "-no-reboot", "-enable-kvm", "-cpu", "host,migratable=off", 
                    "-hda", "{}/stretch.img".format(self.image), 
                    "-snapshot", "-kernel", "{}/arch/x86_64/boot/bzImage".format(self.linux),
                    "-append", "root=/dev/sda console=ttyS0"])
        if opts == None:
            cur_opts = self.def_opts
        else:
            cur_opts = opts
        if type(cur_opts) == type(list):
            self.cmd.extend(cur_opts)
        return
        
    def run(self):
        p = Popen(self.cmd, stdout=PIPE, stderr=STDOUT)
        return p
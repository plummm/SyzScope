import datetime
import logging
import os, stat, sys

stamp_finish_fuzzing = "FINISH_FUZZING"
stamp_build_syzkaller = "BUILD_SYZKALLER"
stamp_build_kernel = "BUILD_KERNEL"
stamp_reproduce_ori_poc = "REPRO_ORI_POC"
stamp_symbolic_tracing = "FINISH_SYM_TRACING"
stamp_static_analysis = "FINISH_STATIC_ANALYSIS"

max_qemu_for_one_case = 4

class Case:
    def __init__(self, index, debug=False, force=False, port=53777, replay='incomplete', linux_index=-1, time=8, force_fuzz=False, alert=[], static_analysis=False, symbolic_tracing=True, gdb_port=1235, qemu_monitor_port=9700, max_compiling_kernel=-1):
        self.linux_folder = "linux"
        self.project_path = ""
        self.package_path = None
        self.syzkaller_path = ""
        self.image_path = ""
        self.current_case_path = ""
        self.kernel_path = ""
        self.index = index
        self.case_logger = None
        self.logger = None
        self.case_info_logger = None
        self.store_read = True
        self.force = force
        self.time_limit = time
        self.crash_checker = None
        self.image_switching_date = datetime.datetime(2020, 3, 15)
        self.arch = None
        self.compiler = None
        self.force_fuzz = force_fuzz
        self.alert = alert
        self.static_analysis = static_analysis
        self.symbolic_tracing = symbolic_tracing
        self.max_compiling_kernel = max_compiling_kernel
        self.max_qemu_for_one_case = max_qemu_for_one_case
        self.sa = None
        if replay == None:
            self.replay = False
            self.catalog = 'incomplete'
        else:
            self.replay = True
            self.catalog = replay
        self.ssh_port = port + max_qemu_for_one_case*index
        self.gdb_port = gdb_port + max_qemu_for_one_case*index
        self.qemu_monitor_port = qemu_monitor_port + max_qemu_for_one_case*index
        if linux_index != -1:
            self.index = linux_index
        self.debug = debug
        self.hash_val = None
        self.init_logger(debug)
    
    def init_logger(self, debug, hash_val=None):
        self.logger = logging.getLogger(__name__+str(self.index))
        for each in self.logger.handlers:
            self.logger.removeHandler(each)
        handler = logging.StreamHandler(sys.stdout)
        if hash_val != None:
            format = logging.Formatter('%(asctime)s Thread {}: {} %(message)s'.format(self.index, hash_val))
        else:
            format = logging.Formatter('%(asctime)s Thread {}: %(message)s'.format(self.index))
        handler.setFormatter(format)
        self.logger.addHandler(handler)
        if debug:
            self.logger.setLevel(logging.DEBUG)
            self.logger.propagate = True
        else:
            self.logger.setLevel(logging.INFO)
            self.logger.propagate = False
    
    def setup_hash(self, hash_val):
        self.hash_val = hash_val
        self.init_logger(self.debug, self.hash_val[:7])
        
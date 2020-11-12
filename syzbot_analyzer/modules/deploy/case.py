import datetime
import logging
import os, stat, sys

stamp_finish_fuzzing = "FINISH_FUZZING"
stamp_build_syzkaller = "BUILD_SYZKALLER"
stamp_build_kernel = "BUILD_KERNEL"
stamp_reproduce_ori_poc = "REPRO_ORI_POC"

class Case:
    def __init__(self, index, debug=False, force=False, port=53777, replay='incomplete', linux_index=-1, time=8, force_fuzz=False, alert=[], static_analysis=False, symbolic_tracing=True, gdb_port=1235, qemu_monitor_port=9700):
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
        self.sa = None
        if replay == None:
            self.replay = False
            self.catalog = 'incomplete'
        else:
            self.replay = True
            self.catalog = replay
        self.default_port = port
        self.gdb_port = gdb_port
        self.qemu_monitor_port = qemu_monitor_port
        if linux_index != -1:
            self.index = linux_index
        self.debug = debug
        self.hash_val = None
        self.init_logger(debug)
    
    def init_logger(self, debug):
        self.logger = logging.getLogger(__name__+str(self.index))
        handler = logging.StreamHandler(sys.stdout)
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
        
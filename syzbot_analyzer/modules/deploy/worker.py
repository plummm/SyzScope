import re
import os, stat, sys
from syzbot_analyzer.interface.sym_exec.stateManager import StateManager
import requests
import threading
import logging
import time
import syzbot_analyzer.interface.utilities as utilities

from syzbot_analyzer.modules.syzbotCrawler import syzbot_host_url, syzbot_bug_base_url
from syzbot_analyzer.interface import s2e, static_analysis, sym_exec
from subprocess import call, Popen, PIPE, STDOUT
from syzbot_analyzer.modules.crash import CrashChecker, kasan_regx, free_regx
from syzbot_analyzer.interface.utilities import chmodX
from dateutil import parser as time_parser
from .case import Case, stamp_build_kernel, stamp_build_syzkaller, stamp_finish_fuzzing, stamp_reproduce_ori_poc, stamp_symbolic_tracing, stamp_static_analysis
from syzbot_analyzer.interface.sym_exec.error import VulnerabilityNotTrigger, ExecutionError, AbnormalGDBBehavior
from syzbot_analyzer.interface.vm.monitor import QemuIsDead

class Workers(Case):
    def __init__(self, index, debug=False, force=False, port=53777, replay='incomplete', linux_index=-1, time=8, force_fuzz=False, alert=[], static_analysis=False, symbolic_tracing=True, gdb_port=1235, qemu_monitor_port=9700, max_compiling_kernel=-1):
        Case.__init__(self, index, debug, force, port, replay, linux_index, time, force_fuzz, alert, static_analysis, symbolic_tracing, gdb_port, qemu_monitor_port, max_compiling_kernel)

    def do_symbolic_tracing(self, case, i386, max_round=3, raw_tracing=False):
        self.logger.info("initial environ of symbolic execution")
        self.sa = static_analysis.StaticAnalysis(self.case_logger, self.project_path, self.index, self.current_case_path, self.linux_folder)
        self.init_crash_checker(self.ssh_port, False)
        r = utilities.request_get(case['report'])
        #_, _, _, offset, size = self.sa.KasanVulnChecker(r.text)
        offset = case["vul_offset"]
        size = case["obj_size"]
        if offset == None or size == None:
            self.logger.info("No valid offset or size")
            return

        linux_path = os.path.join(self.current_case_path, self.linux_folder)
        """target = os.path.join(self.package_path, "scripts/deploy_linux.sh")
        utilities.chmodX(target)
        p = Popen([target, self.compiler, "0", linux_path, self.package_path, case["commit"], case["config"],  "1"],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        if exitcode != 0:
            self.logger.error("Error occur when compiling kernel")
            return
        """
        arch = 'amd64'
        if i386:
            arch = 'i386'

        is_propagating_global = False
        exception_count = 0
        for i in range(0, max_round):
            sym_folder = os.path.join(self.current_case_path, "sym")
            if not os.path.isdir(sym_folder):
                os.mkdir(sym_folder)
            cur_sym_log = sym_folder + "/symbolic_tracing.log" + "-" + str(i)
            sym_logger = self.__init_logger(cur_sym_log)
            sym_logger.info("round {}: symbolic tracing".format(i))
            sym = sym_exec.SymExec(logger=sym_logger, index=self.index, debug=self.debug)
            sym.setup_vm(linux_path, arch, self.ssh_port, self.image_path, self.gdb_port, self.qemu_monitor_port, proj_path=self.current_case_path, cpu="2", logger=self.case_logger, hash_tag=self.hash_val[:7], log_name="sym/vm.log", log_suffix="-{}".format(i),  timeout=70*60)
            p = None
            try:
                p = sym.run_vm()
            except QemuIsDead:
                self.logger.error("Error occur when executing symbolic tracing: QemuIsDead")
            if p == None:
                self.logger.error("Fail to lauch qemu")
                self.cleanup(sym)
                continue
            exitcode = p.poll()
            if exitcode != None:
                err = 'Unknown reason'
                if exitcode == -9:
                    err = 'SIGKILL'
                self.logger.error('QEMU exit due to: {}'.format(err))
                self.cleanup(sym)
                continue
            sym_logger.info("Uploading poc and triggering the crash")
            ok, output = self.crash_checker.upload_exp(case["syz_repro"], self.ssh_port, case["syzkaller"], utilities.URL, case["c_repro"], i386, 0)
            for line in output:
                sym_logger.info(line)
            if ok == 0:
                self.logger.error("Error occur at upload exp")
                self.cleanup(sym)
                continue

            self.crash_checker.run_exp(case["syz_repro"], self.ssh_port, utilities.URL, ok, i386, 0)
            paths = []
            #paths.append({'cond': 0xffffffff8328c77d, 'correct_path': 0xffffffff8328c77f, 'wrong_path': 0xffffffff8328c79a})
            #paths.append({'cond': 0xffffffff83295764, 'correct_path': 0xffffffff83295766, 'wrong_path': 0xffffffff8329576b})
            #paths.append({'cond': 0xffffffff8329661f, 'correct_path': 0xffffffff8329667b, 'wrong_path': 0xffffffff83296621})
            #paths.append({'cond': 0xffffffff83296f63, 'correct_path': 0xffffffff83296f65, 'wrong_path': 0xffffffff83296fc2})
            #paths.append({'cond': 0xffffffff83296fc0, 'correct_path': 0xffffffff83296f65, 'wrong_path': 0xffffffff83296fc2})
            #paths.append({'cond': 0, 'correct_path': 0, 'wrong_path': 0xffffffff8328c7ad})
            sym.setup_bug_capture(offset, size)
            try:
                ret = sym.run_sym(raw_tracing, timeout=60*60)
                if ret == None:
                    self.cleanup(sym)
                    continue
                if ret & StateManager.CONTROL_FLOW_HIJACK:
                    self.logger.warning("Control flow hijack found")
                if ret & StateManager.ARBITRARY_VALUE_WRITE:
                    self.logger.warning("Arbitrary value write found")
                if ret & StateManager.FINITE_VALUE_WRITE:
                    self.logger.warning("Finite value write found")
                if ret & StateManager.ARBITRARY_ADDR_WRITE:
                    self.logger.warning("Arbitrary address write found")
                if ret & StateManager.FINITE_ADDR_WRITE:
                    self.logger.warning("Finite address write found")
                if ret == 0:
                    self.logger.warning("No additional use")
                self.cleanup(sym)
                break
                #if ret != None and len(ret) > 0:
                #    is_propagating_global = True
            except VulnerabilityNotTrigger:
                exception_count += 1
            except ExecutionError:
                sym_logger.warning("Execution Error")
            except AbnormalGDBBehavior:
                sym_logger.warning("Abnormal GDB behavior occured")
            except QemuIsDead:
                self.logger.error("Error occur when executing symbolic tracing: QemuIsDead")
            #except Exception as e:
            #    sym_logger.error("Unknown exception occur during symboulic execution: {}".format(e))
            self.cleanup(sym)
            time.sleep(1)
        if max_round == exception_count:
            self.logger.warning("Can not trigger vulnerability. Abaondoned")
            return
        """if is_propagating_global:
            if raw_tracing:
                self.logger.warning("{} access to global/local variables on symbolic tracing".format(self.hash_val))
            #self.__create_stamp(stamp_symbolic_tracing)
        elif exception_count < max_round:
            if raw_tracing:
                self.logger.warning("{} has no access to variables".format(self.hash_val))
            #self.__create_stamp(stamp_symbolic_tracing)
        else:
            self.logger.warning("Can not trigger vulnerability. Abaondoned")"""
        self.__create_stamp(stamp_symbolic_tracing)
        return

    def do_static_analysis(self, case):
        self.sa = static_analysis.StaticAnalysis(self.case_logger, self.project_path, self.index, self.current_case_path, self.linux_folder)
        res = utilities.request_get(case['report'])
        offset = case['vul_offset']
        size = case['obj_size']
        if offset == None:
            self.logger.info("No valid offset of vulnerable object for static analysis")
            return
        vul_site, func_site, func = self.sa.KasanVulnChecker(res.text)
        if vul_site == None or func_site == None or func == None:
            self.logger.error("No valid Calltrace for static analysis")
            return
        r = self.sa.prepare_static_analysis(case, vul_site, func_site)
        if r == 1:
            if self.sa.compile_bc_extra() != 0:
                self.logger.error("Error occur in deploy-bc.sh")
                return
        elif r != 0:
            self.logger.error("Error occur in deploy-bc.sh")
            return
        # Before save the Calltrace, we need to checkout to a right commit
        report_list = res.text.split('\n')
        trace = utilities.extrace_call_trace(report_list)
        self.sa.saveCallTrace2File(trace, vul_site)
        r = self.sa.run_static_analysis(vul_site, func_site, func, offset, size)
        if r != 0:
            self.logger.error("Error occur when getting pointer in IR")
        self.__create_stamp(stamp_static_analysis)
    
    def do_reproducing_ori_poc(self, case, hash_val, i386, store_read):
        self.logger.info("Try to triger the OOB/UAF by running original poc")
        self.case_info_logger.info("compiler: "+self.compiler)
        self.init_crash_checker(self.ssh_port, store_read)
        report, trigger = self.crash_checker.read_crash(case["syz_repro"], case["syzkaller"], None, 0, case["c_repro"], i386)
        hunted_type_without_mutating, title = self.KasanChecker(store_read, report, hash_val)
        self.__create_stamp(stamp_reproduce_ori_poc)
        return hunted_type_without_mutating, title
    
    def KasanChecker(self, read_check, report, hash_val):
        title = None
        ret = False
        if report != []:
            for each in report:
                for line in each:
                    if utilities.regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line):
                    #utilities.regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        #m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        #if m != None and len(m.groups()) > 0:
                        #    title = m.groups()[0]
                    if utilities.regx_match(utilities.kasan_write_addr_regx, line):
                            ret = True
                            self.crash_checker.logger.info("OOB/UAF Write without mutating")
                            self.logger.info("Write to confirmed success")
                            self.__write_to_sucess(hash_val)
                            self.__write_to_confirmed_sucess(hash_val)
                            break
                    if read_check and utilities.regx_match(utilities.kasan_read_addr_regx, line):
                            ret = True
                            self.crash_checker.logger.info("OOB/UAF Read without mutating")
                            break
        return ret, title
    
    def init_crash_checker(self, port, store_read):
        self.crash_checker = CrashChecker(
            self.project_path,
            self.current_case_path,
            port,
            self.logger,
            self.debug,
            self.index,
            self.max_qemu_for_one_case,
            store_read=store_read,
            compiler=self.compiler)
    
    def cleanup(self, obj):
        obj.cleanup()
        del obj

    def reproduced_ori_poc(self, hash_val, folder):
        return self.__check_stamp(stamp_reproduce_ori_poc, hash_val[:7], folder)
    
    def finished_fuzzing(self, hash_val, folder):
        return self.__check_stamp(stamp_finish_fuzzing, hash_val[:7], folder)
    
    def finished_symbolic_tracing(self, hash_val, folder):
        return self.__check_stamp(stamp_symbolic_tracing, hash_val[:7], folder)
    
    def finished_static_analysis(self, hash_val, folder):
        return self.__check_stamp(stamp_static_analysis, hash_val[:7], folder)
    
    def cleanup_finished_fuzzing(self, hash_val):
        self.__clean_stamp(stamp_finish_fuzzing, hash_val[:7])
    
    def cleanup_built_kernel(self, hash_val):
        self.__clean_stamp(stamp_build_kernel, hash_val[:7])
    
    def cleanup_built_syzkaller(self, hash_val):
        self.__clean_stamp(stamp_build_syzkaller, hash_val[:7])
    
    def cleanup_reproduced_ori_poc(self, hash_val):
        self.__clean_stamp(stamp_reproduce_ori_poc, hash_val[:7])
    
    def __create_stamp(self, name):
        self.logger.info("Create stamp {}".format(name))
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        call(['touch',stamp_path])
    
    def __check_stamp(self, name, hash_val, folder):
        stamp_path1 = "{}/work/{}/{}/.stamp/{}".format(self.project_path, folder, hash_val, name)
        return os.path.isfile(stamp_path1)
    
    def __clean_stamp(self, name, hash_val):
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        if os.path.isfile(stamp_path):
            os.remove(stamp_path)
    
    def __write_to_sucess(self, hash_val):
        with open("{}/work/success".format(self.project_path), "a+") as f:
            f.write(hash_val[:7]+"\n")
    
    def __write_to_confirmed_sucess(self, hash_val):
        with open("{}/work/confirmedSuccess".format(self.project_path), "a+") as f:
            f.write(hash_val[:7]+"\n")

    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)
    
    def __init_logger(self, log_path):
        handler = logging.FileHandler(log_path)
        format = logging.Formatter('%(asctime)s Thread {}: %(message)s'.format(self.index))
        handler.setFormatter(format)
        logger = logging.getLogger(log_path)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if self.debug:
            logger.propagate = True
            logger.setLevel(logging.DEBUG)
        return logger
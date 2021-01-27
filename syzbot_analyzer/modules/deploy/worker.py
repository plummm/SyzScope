import re
import os, stat, sys
from syzbot_analyzer.interface.sym_exec.stateManager import StateManager
import requests
import threading
import logging
import time
import shutil
import syzbot_analyzer.interface.utilities as utilities

from syzbot_analyzer.modules.syzbotCrawler import syzbot_host_url, syzbot_bug_base_url
from syzbot_analyzer.interface import s2e, static_analysis, sym_exec
from subprocess import call, Popen, PIPE, STDOUT
from syzbot_analyzer.modules.crash import CrashChecker
from syzbot_analyzer.interface.utilities import chmodX
from dateutil import parser as time_parser
from .case import Case, stamp_build_kernel, stamp_build_syzkaller, stamp_finish_fuzzing, stamp_reproduce_ori_poc, stamp_symbolic_execution, stamp_static_analysis
from syzbot_analyzer.interface.sym_exec.error import VulnerabilityNotTrigger, ExecutionError, AbnormalGDBBehavior
from syzbot_analyzer.interface.static_analysis.error import CompilingError
from syzbot_analyzer.interface.vm.error import QemuIsDead, AngrRefuseToLoadKernel

TIMEOUT_DYNAMIC_VALIDATION=60*60
TIMEOUT_STATIC_ANALYSIS=60*30

class Workers(Case):
    def __init__(self, index, parallel_max, debug=False, force=False, port=53777, replay='incomplete', linux_index=-1, time=8, kernel_fuzzing=True, alert=[], static_analysis=False, symbolic_execution=False, gdb_port=1235, qemu_monitor_port=9700, max_compiling_kernel=-1, timeout_dynamic_validation=None, timeout_static_analysis=None, timeout_symbolic_execution=None):
        Case.__init__(self, index, parallel_max, debug, force, port, replay, linux_index, time, kernel_fuzzing, alert, static_analysis, symbolic_execution, gdb_port, qemu_monitor_port, max_compiling_kernel)
        if timeout_dynamic_validation == None:
            self.timeout_dynamic_validation=TIMEOUT_DYNAMIC_VALIDATION
        else:
            self.timeout_dynamic_validation=int(timeout_dynamic_validation)
        if timeout_static_analysis == None:
            self.timeout_static_analysis = TIMEOUT_STATIC_ANALYSIS
        else:
            self.timeout_static_analysis=int(timeout_static_analysis)
        if timeout_symbolic_execution != None:
            self.timeout_symbolic_execution = int(timeout_symbolic_execution)
            self.timeout_dynamic_validation = self.timeout_symbolic_execution + self.timeout_static_analysis
        else:
            if timeout_dynamic_validation != None and timeout_static_analysis != None:
                self.timeout_symbolic_execution = None
            else:
                self.timeout_symbolic_execution = 365*24*60*60

    def do_symbolic_execution(self, case, i386, max_round=3, raw_tracing=False, timeout=None):
        ret = 1
        valid_contexts = self.valid_offset_and_size(case)
        for context in valid_contexts:
            if not self._do_symbolic_execution(case, context, i386, max_round, raw_tracing, timeout):
                ret = 0
        return ret

    def _do_symbolic_execution(self, case, context, i386, max_round=3, raw_tracing=False, timeout=None):
        self.logger.info("initial environ of symbolic execution")
        if timeout != None:
            self.timeout_symbolic_execution = timeout
        else:
            self.timeout_symbolic_execution = self.timeout_dynamic_validation - self.timeout_static_analysis
        offset = context['offset']
        size = context['size']
        workdir = context['workdir']
        self.sa = static_analysis.StaticAnalysis(self.case_logger, self.project_path, self.index, self.current_case_path, self.linux_folder, self.max_compiling_kernel)
        #self.init_crash_checker(self.ssh_port, False)
        r = utilities.request_get(case['report'])
        #_, _, _, offset, size = self.sa.KasanVulnChecker(r.text)

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

        sym_folder = os.path.join(self.current_case_path, workdir)
        if os.path.isdir(sym_folder):
            n=1
            dest_path = "{}-{}".format(sym_folder, n)
            while(1):
                if not os.path.isdir(dest_path):
                    shutil.move(sym_folder, dest_path)
                    self.logger.info("Found {}, copy them to {}".format(sym_folder, dest_path))
                    break
                else:
                    n += 1
                    dest_path = "{}-{}".format(sym_folder, n)
        os.mkdir(sym_folder)
        is_propagating_global = False
        result = StateManager.NO_ADDITIONAL_USE
        exception_count = 0
        flag_stop_execution = False
        for i in range(0, max_round):
            cur_sym_log = sym_folder + "/symbolic_execution.log" + "-" + str(i)
            sym_logger = self.__init_logger(cur_sym_log)
            sym_logger.info("round {}: symbolic tracing".format(i))
            sym = sym_exec.SymExec(logger=sym_logger, workdir=sym_folder, index=self.index, debug=self.debug)
            sym.setup_vm(linux_path, arch, self.ssh_port, self.image_path, self.gdb_port, self.qemu_monitor_port, proj_path=sym_folder, cpu="2", mem="2G", logger=self.case_logger, hash_tag=self.hash_val[:7], log_name="vm.log", log_suffix="-{}".format(i),  timeout=self.timeout_symbolic_execution+5*60)
            p = None
            try:
                p = sym.run_vm()
            except QemuIsDead:
                self.logger.error("Error occur when executing symbolic tracing: QemuIsDead")
            except AngrRefuseToLoadKernel:
                self.logger.error("Error occur when loading kernel into angr: AngrRefuseToLoadKernel")
                sym.cleanup()
                del sym
                continue
            if p == None:
                self.logger.error("Fail to lauch qemu")
                sym.cleanup()
                del sym
                continue
            exitcode = p.poll()
            if exitcode != None:
                err = 'Unknown reason'
                if exitcode == -9:
                    err = 'SIGKILL'
                self.logger.error('QEMU exit due to: {}'.format(err))
                sym.cleanup()
                del sym
                continue
            sym_logger.info("Uploading poc and triggering the crash")
            ok = self.crash_checker.upload_exp(case["syz_repro"], self.ssh_port, case["syzkaller"], utilities.URL, case["c_repro"], i386, 0, sym_logger)
            if ok == 0:
                self.logger.error("Error occur at upload exp")
                sym.cleanup()
                del sym
                continue

            self.crash_checker.run_exp(case["syz_repro"], self.ssh_port, utilities.URL, ok, i386, 0, sym_logger)
            sym.setup_bug_capture(offset, size)
            try:
                static_analysis_result_paths = os.path.join(self.current_case_path, "paths")
                if not os.path.isdir(static_analysis_result_paths):
                    path_files = [None]
                else:
                    path_files = os.listdir(static_analysis_result_paths)
                    if path_files == []:
                        path_files = [None]
                if path_files != [None]:
                    self.logger.info("Running under-constrained symbolic execution with guided paths")
                else:
                    self.logger.info("Running under-constrained symbolic execution")

                paths = []
                for each_file in path_files:
                    if each_file != None:
                        guided_path = os.path.join(static_analysis_result_paths, each_file)
                        p = self.retrieve_guided_paths(guided_path)
                        if p != []:
                            paths.append(p)
                """p = []
                p.append({'cond': 0xffffffff83234a29, 'correct': 0xffffffff83234a2b, 'wrong': 0xffffffff832349a9})
                p.append({'cond': 0xffffffff83234a2b, 'correct': 0xffffffff83234a5a, 'wrong': 0xffffffff832349a9})
                p.append({'cond': 0xffffffff83e62f10, 'correct': 0xffffffff83e62e39, 'wrong': 0xffffffff83e7d5f0})
                p.append({'cond': 0xffffffff83e5fe76, 'correct': 0xffffffff83e5fe8b, 'wrong': 0xffffffff83e7ba0e})
                p.append({'cond': 0xffffffff83e5fea3, 'correct': 0xffffffff83e5feb5, 'wrong': 0xffffffff83e5fec0})
                paths = [p]"""
                ret = sym.run_sym(path=paths, raw_tracing=raw_tracing, timeout=self.timeout_symbolic_execution)
                if ret == None:
                    self.logger.warning("Can not locate the vulnerable memory")
                    sym.cleanup()
                    del sym
                    continue
                result |= ret
                if ret == 0:
                    self.logger.warning("No additional use")
                sym.cleanup()
                del sym
                break
                #if ret != None and len(ret) > 0:
                #    is_propagating_global = True
            except VulnerabilityNotTrigger:
                self.logger.warning("Can not trigger vulnerability. Abaondoned")
                exception_count += 1
            except ExecutionError:
                sym_logger.warning("Execution Error")
                exception_count += 1
            except AbnormalGDBBehavior:
                sym_logger.warning("Abnormal GDB behavior occured")
                exception_count += 1
            except QemuIsDead:
                self.logger.error("Error occur when executing symbolic tracing: QemuIsDead")
                exception_count += 1
            #except Exception as e:
            #    sym_logger.error("Unknown exception occur during symboulic execution: {}".format(e))
            sym.cleanup()
            del sym
            time.sleep(1)
        if max_round == exception_count:
            return 1
        if result & StateManager.CONTROL_FLOW_HIJACK:
            self.logger.warning("Control flow hijack found")
        if result & StateManager.ARBITRARY_VALUE_WRITE:
            self.logger.warning("Arbitrary value write found")
        if result & StateManager.FINITE_VALUE_WRITE:
            self.logger.warning("Finite value write found")
        if result & StateManager.ARBITRARY_ADDR_WRITE:
            self.logger.warning("Arbitrary address write found")
        if result & StateManager.FINITE_ADDR_WRITE:
            self.logger.warning("Finite address write found")
        """if is_propagating_global:
            if raw_tracing:
                self.logger.warning("{} access to global/local variables on symbolic tracing".format(self.hash_val))
            #self.__create_stamp(stamp_symbolic_execution)
        elif exception_count < max_round:
            if raw_tracing:
                self.logger.warning("{} has no access to variables".format(self.hash_val))
            #self.__create_stamp(stamp_symbolic_execution)
        else:
            self.logger.warning("Can not trigger vulnerability. Abaondoned")"""
        
        self.create_finished_symbolic_execution_stamp()
        return result == StateManager.NO_ADDITIONAL_USE
    
    def retrieve_guided_paths(self, guided_path):
        paths = []
        if guided_path != None:
            with open(guided_path, 'r') as f:
                text = f.readlines()
                for site in text:
                    fesible_condition = False
                    site = site.strip('\n')
                    tmp = site.split(' ')
                    if site == '$':
                        break
                    if len(tmp) == 1:
                        t = tmp[0].split(':')
                        file = t[0]
                        line = t[1]
                        paths.append({'file': file, 'line': line})
                        break
                    base_index = 0
                    if tmp[0] == '*':
                        fesible_condition = True
                        base_index = 1
                    cond = tmp[base_index].split(':')
                    correct = tmp[base_index+1].split(':')
                    wrong = tmp[base_index+2].split(':')
                    paths.append({'cond': {'file': cond[0], 'line': cond[1], 'feasible': True}, 'correct': {'file': correct[0], 'line': correct[1], 'feasible': True}, 'wrong': {'file': wrong[0], 'line': wrong[1], 'feasible': False}})
                    if fesible_condition:
                        paths.append({'cond': {'file': cond[0], 'line': cond[1], 'feasible': True}, 'wrong': {'file': correct[0], 'line': correct[1], 'feasible': True}, 'correct': {'file': wrong[0], 'line': wrong[1], 'feasible': False}})
        return paths


    def do_static_analysis(self, case):
        self.sa = static_analysis.StaticAnalysis(self.case_logger, self.project_path, self.index, self.current_case_path, self.linux_folder, self.timeout_static_analysis, self.max_compiling_kernel)
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
        
        self.logger.info("prepare for static analysis")
        r = self.sa.prepare_static_analysis(case, vul_site, func_site)
        if r != 0:
            raise CompilingError
        # Before save the Calltrace, we need to checkout to a right commit
        report_list = res.text.split('\n')
        trace = utilities.extrace_call_trace(report_list)
        self.sa.saveCallTrace2File(trace, vul_site)
        r, time_on_static_analysis = self.sa.run_static_analysis(vul_site, func_site, func, offset, size)
        if r != 0:
            self.logger.error("Error occur when getting pointer in IR")
        if self.timeout_symbolic_execution == None:
            self.timeout_symbolic_execution = self.timeout_dynamic_validation - time_on_static_analysis
        self.create_finished_static_analysis_stamp()
    
    def do_reproducing_ori_poc(self, case, hash_val, i386):
        self.logger.info("Try to triger the OOB/UAF by running original poc")
        self.case_info_logger.info("compiler: "+self.compiler)
        report, trigger = self.crash_checker.read_crash(case["syz_repro"], case["syzkaller"], None, 0, case["c_repro"], i386)
        hunted_type_without_mutating, title = self.KasanChecker(report, hash_val)
        self.create_reproduced_ori_poc_stamp()
        return hunted_type_without_mutating, title
    
    def KasanChecker(self, report, hash_val):
        title = None
        ret = False
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
            for each in report:
                for line in each:
                    if utilities.regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line) or \
                        utilities.regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                    if utilities.regx_match(utilities.double_free_regx, line) and not flag_double_free:
                            ret = True
                            self.crash_checker.logger.info("Double free without mutating")
                            self.logger.info("Write to ConfirmedDoubleFree")
                            self.__write_to_DoubleFree(hash_val)
                            self.__write_to_ConfirmedDoubleFree(hash_val)
                            flag_double_free = True
                            break
                    if utilities.regx_match(utilities.kasan_write_addr_regx, line) and not flag_kasan_write:
                            ret = True
                            self.crash_checker.logger.info("OOB/UAF Write without mutating")
                            self.logger.info("Write to ConfirmedAbnormallyMemWrite")
                            self.__write_to_AbnormallyMemWrite(hash_val)
                            flag_kasan_write = True
                            break
                    if self.store_read and utilities.regx_match(utilities.kasan_read_addr_regx, line) and not flag_kasan_read:
                            ret = True
                            self.crash_checker.logger.info("OOB/UAF Read without mutating")
                            self.logger.info("Write to ConfirmedAbnormallyMemRead")
                            self.__write_to_AbnormallyMemRead(hash_val)
                            flag_kasan_read
                            break
        return ret, title
    
    def valid_offset_and_size(self, case):
        ret = []
        offset = case["vul_offset"]
        size = case["obj_size"]
        if offset != None and size != None:
            ret.append({'workdir': 'sym-ori', 'offset': offset, 'size': size, 'repro': case["syz_repro"], 'type': utilities.URL, 'c_repro': case["syz_repro"]})
        if self.store_read:
            output = os.path.join(self.current_case_path, "output")
            if os.path.exists(output):
                all_cases = os.listdir(output)
                for each_case in all_cases:
                    case_base = os.path.join(output, each_case)
                    description = os.path.join(case_base, "description")
                    if not os.path.exists(description):
                        continue
                    f = open(description, 'r')
                    title = f.readline()
                    f.close()
                    if utilities.regx_match('KASAN', title):
                        log = os.path.join(case_base, "repro.log")
                        if not os.path.exists(log):
                            continue
                        f = open(log, 'r')
                        texts = f.readlines()
                        offset, size = utilities.extract_vul_obj_offset_and_size(texts)
                        prog = os.path.join(case_base, "repro.prog")
                        if offset != None and size != None and os.path.exists(prog):
                            ret.append({'workdir': 'sym-{}'.format(each_case[:7]), 'offset': offset, 'size': size, 'repro': prog, 'type': utilities.CASE, 'c_repro': None})
        return ret
    
    def init_crash_checker(self, port):
        self.crash_checker = CrashChecker(
            self.project_path,
            self.current_case_path,
            port,
            self.logger,
            self.debug,
            self.index,
            self.max_qemu_for_one_case,
            store_read=self.store_read,
            compiler=self.compiler)
    
    def write_to_confirm(self, hash_val, new_impact_type):
        if new_impact_type == utilities.AbMemRead:
            self.__write_to_ConfirmedAbnormallyMemRead(hash_val)
        if new_impact_type == utilities.AbMemWrite:
            self.__write_to_ConfirmedAbnormallyMemWrite(hash_val)
        if new_impact_type == utilities.InvFree:
            self.__write_to_ConfirmedDoubleFree(hash_val)

    def reproduced_ori_poc(self, hash_val, folder):
        return self.__check_stamp(stamp_reproduce_ori_poc, hash_val[:7], folder)
    
    def finished_fuzzing(self, hash_val, folder):
        return self.__check_stamp(stamp_finish_fuzzing, hash_val[:7], folder)
    
    def finished_symbolic_execution(self, hash_val, folder):
        return self.__check_stamp(stamp_symbolic_execution, hash_val[:7], folder)
    
    def finished_static_analysis(self, hash_val, folder):
        return self.__check_stamp(stamp_static_analysis, hash_val[:7], folder)

    def create_finished_fuzzing_stamp(self):
        return self.__create_stamp(stamp_finish_fuzzing)
    
    def create_finished_symbolic_execution_stamp(self):
        return self.__create_stamp(stamp_symbolic_execution)

    def create_finished_static_analysis_stamp(self):
        return self.__create_stamp(stamp_static_analysis)
    
    def create_reproduced_ori_poc_stamp(self):
        return self.__create_stamp(stamp_reproduce_ori_poc)
    
    def cleanup_finished_fuzzing(self, hash_val):
        self.__clean_stamp(stamp_finish_fuzzing, hash_val[:7])
    
    def cleanup_built_kernel(self, hash_val):
        self.__clean_stamp(stamp_build_kernel, hash_val[:7])
    
    def cleanup_built_syzkaller(self, hash_val):
        self.__clean_stamp(stamp_build_syzkaller, hash_val[:7])
    
    def cleanup_reproduced_ori_poc(self, hash_val):
        self.__clean_stamp(stamp_reproduce_ori_poc, hash_val[:7])
    
    def cleanup_finished_symbolic_execution(self, hash_val):
        self.__clean_stamp(stamp_symbolic_execution, hash_val[:7])

    def cleanup_finished_static_analysis(self, hash_val):
        self.__clean_stamp(stamp_static_analysis, hash_val[:7])
    
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
    
    def __write_to_AbnormallyMemWrite(self, hash_val):
        self.__write_to(hash_val, "AbnormallyMemWrite")
    
    def __write_to_ConfirmedAbnormallyMemWrite(self, hash_val):
        self.__write_to(hash_val, "ConfirmedAbnormallyMemWrite")
    
    def __write_to_AbnormallyMemRead(self, hash_val):
        self.__write_to(hash_val, "AbnormallyMemRead")
    
    def __write_to_ConfirmedAbnormallyMemRead(self, hash_val):
        self.__write_to(hash_val, "ConfirmedAbnormallyMemRead")
    
    def __write_to_DoubleFree(self, hash_val):
        self.__write_to(hash_val, "DoubleFree")
    
    def __write_to_ConfirmedDoubleFree(self, hash_val):
        self.__write_to(hash_val, "ConfirmedDoubleFree")
    
    def __write_to(self, hash_val, name):
        with open("{}/work/{}".format(self.project_path, name), "a+") as f:
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
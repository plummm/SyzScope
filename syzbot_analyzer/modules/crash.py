import os, re, stat, sys
import logging
import argparse
import syzbot_analyzer.interface.utilities as utilities
import time
import threading
import json
import pathlib
import queue
from syzbot_analyzer.interface.vm import VM

from subprocess import call, Popen, PIPE, STDOUT
from .syzbotCrawler import Crawler
from dateutil import parser as time_parser

startup_regx = r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'
boundary_regx = r'======================================================'
call_trace_regx = r'Call Trace:'
message_drop_regx = r'printk messages dropped'
panic_regx = r'Kernel panic'
kasan_mem_regx = r'BUG: KASAN: ([a-z\\-]+) in ([a-zA-Z0-9_]+).*'
kasan_double_free_regx = r'BUG: KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
kasan_write_regx = r'KASAN: ([a-z\\-]+) Write in ([a-zA-Z0-9_]+).*'
kasan_read_regx = r'KASAN: ([a-z\\-]+) Read in ([a-zA-Z0-9_]+).*'
double_free_regx = r'KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
magic_regx = r'\?!\?MAGIC\?!\?read->(\w*) size->(\d*)'
write_regx = r'Write of size (\d+) at addr (\w*)'
read_regx = r'Read of size (\d+) at addr (\w*)'
default_port = 3777
project_path = ""
NONCRASH = 0
CONFIRM = 1
SUSPICIOUS = 2
thread_fn = None

class CrashChecker:
    def __init__(self, project_path, case_path, ssh_port, logger, debug, offset, qemu_num, store_read=False, compiler="gcc-7"):
        os.makedirs("{}/poc".format(case_path), exist_ok=True)
        self.logger = logger
        self.project_path = project_path
        self.package_path = os.path.join(project_path, "syzbot_analyzer")
        self.case_path = case_path
        self.image_path = "{}/img".format(self.case_path)
        self.linux_path = "{}/linux".format(self.case_path)
        self.qemu_num = qemu_num
        self.ssh_port = ssh_port
        self.kasan_func_list = self.read_kasan_funcs()
        self.debug = debug
        self.store_read = store_read
        self.compiler = compiler
        self.kill_qemu = False
        self.queue = queue.Queue()
        self.case_logger = self.__init_case_logger("{}-info".format(case_path))

    def run(self, syz_repro, syz_commit, log=None, linux_commit=None, config=None, c_repro=None, i386=None):
        self.case_logger.info("=============================crash.run=============================")
        if log != None:
            exitcode = self.deploy_linux(linux_commit, config, 0)
            if exitcode == 1:
                self.logger.info("Error occur at deploy_linux.sh")
                return [False, None]
        ori_crash_report, trigger = self.read_crash(syz_repro, syz_commit, log, 0, c_repro, i386)
        if ori_crash_report == []:
            self.logger.info("No crash trigger by original poc")
            return [False, None]
        crashes_path = self.extract_existed_crash(self.case_path)
        self.case_logger.info("Found {} existed crashes".format(len(crashes_path)))
        for path in crashes_path:
            self.case_logger.info("Inspect crash: {}".format(path))
            new_crash_reports = self.read_existed_crash(path)
            if self.compare_crashes(ori_crash_report, new_crash_reports):
                return [True, path]
        return [False, None]
    
    def check_read_before_write(self, path):
        new_crash_reports = self.read_existed_crash(path)
        for each_report in new_crash_reports:
            for line in each_report:
                if utilities.regx_match(magic_regx, line):
                    return True
        return False

    
    def diff_testcase(self, crash_path, syz_repro):
        new_testcase = []
        old_testcase = []
        f = open(os.path.join(crash_path, "repro.prog"), "r")
        text = f.readlines()
        for line in text:
            if len(line) > 0 and line[0] != '#':
                line = line.strip('\n')
                new_testcase.append(line)
        r = utilities.request_get(syz_repro)
        text = r.text.split('\n')
        for line in text:
            if len(line) > 0 and line[0] != '#':
                line = line.strip('\n')
                old_testcase.append(line)
        return utilities.levenshtein("\n".join(old_testcase), "\n".join(new_testcase))

    
    def repro_on_fixed_kernel(self, syz_commit, linux_commit=None, config=None, c_repro=None, i386=None, patch_commit=None, crashes_path=None):
        if crashes_path == None:
            crashes_path = self.extract_existed_crash(self.case_path)
            if len(crashes_path) == 0:
                return []
        self.case_logger.info("=============================crash.repro_on_fixed_kernel=============================")
        res = []
        reproduceable = {}

        #check if the patch can be applied
        exitcode = self.patch_applying_check(linux_commit, config, patch_commit)
        if exitcode == 1:
            self.logger.info("Error occur at patch_applying_check.sh")
            return res
        #reproduce on unfixed kernel
        for path in crashes_path:
            key = os.path.basename(path)
            path_repro = os.path.join(path, "repro.prog")
            self.case_logger.info("Go for {}".format(path_repro))
            ori_crash_report, trigger = self.read_crash(path_repro, syz_commit, None, 0, c_repro, i386)
            if ori_crash_report != []:
                if trigger:
                    reproduceable[key] = CONFIRM
                else:
                    reproduceable[key] = SUSPICIOUS
            else:
                reproduceable[key] = NONCRASH
        #apply the patch
        exitcode = self.deploy_linux(patch_commit, config, 1)
        if exitcode == 1:
            self.logger.info("Error occur at deploy_linux.sh")
            return res
        #reproduce on fixed kernel
        for path in crashes_path:
            key = os.path.basename(path)
            path_repro = os.path.join(path, "repro.prog")
            ori_crash_report, trigger = self.read_crash(path_repro, syz_commit, None, 1, c_repro, i386)
            if ori_crash_report != []:
                if trigger:
                    self.logger.info("Reproduceable: {}".format(key))
                else:
                    if reproduceable[key] == CONFIRM:
                        # still crash but no OOB/UAF write any more
                        self.logger.info("Slightly Fixed: {}".format(key))
                        res.append(path)
            else:
                if reproduceable[key] == CONFIRM:
                    self.logger.info("Fixed: {}".format(key))
                    res.append(path)
                if reproduceable[key] == NONCRASH:
                    self.logger.info("Invalid crash: {} unreproduceable on both fixed and unfixed kernel".format(key))
                if reproduceable[key] == SUSPICIOUS:
                    self.logger.info("Suspicious crash: {} triggered a crash but doesn't belong to OOB/UAF write".format(key))
        return res
    
    def patch_applying_check(self, linux_commit, config, patch_commit):
        target = os.path.join(self.package_path, "scripts/patch_applying_check.sh")
        utilities.chmodX(target)
        p = Popen([target, self.linux_path, linux_commit, config, patch_commit, self.compiler],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        return exitcode
    
    def read_kasan_funcs(self):
        res = []
        path = os.path.join(self.package_path, "resources/kasan_related_funcs")
        with open(path, "r") as f:
            lines = f.readlines()
            for line in lines:
                res.append(line.strip('\n'))
            return res

    def compare_crashes(self, ori_crash_report, new_crash_reports):
        ratio_allocation = 1
        ratio_call_race = 1
        res_allocation = False
        res_call_trace = False
        for report1 in ori_crash_report:
            if len(report1) > 2:
                for report2 in new_crash_reports:
                    if len(report2) > 2:
                        res1 = self.__match_allocated_section(report1, report2)     
                        res2 = self.__match_call_trace(report1, report2)
                        if ratio_allocation > res1[1]:
                            ratio_allocation = res1[1]
                            res_allocation = res1[0]
                        if ratio_call_race > res2[1]:
                            ratio_call_race = res2[1]
                            res_call_trace = res2[0]
        self.logger.info("ratio for allocation: {}  ratio for call trace: {}".format(ratio_allocation, ratio_call_race))
        return res_allocation or res_call_trace

    def extract_existed_crash(self, path):
        crash_path = os.path.join(path, "crashes")
        #extrace the latest crashes
        if os.path.isdir(crash_path):
            for i in range(0,99):
                crash_path_tmp = os.path.join(path, "crashes-{}".format(i))
                if os.path.isdir(crash_path_tmp):
                    crash_path = crash_path_tmp
                else:
                    break
        res = []

        if os.path.isdir(crash_path):
            for case in os.listdir(crash_path):
                description_file = "{}/{}/description".format(crash_path, case)
                if os.path.isfile(description_file):
                    with open(description_file, "r") as f:
                        line = f.readline()
                        if self.store_read and utilities.regx_match(kasan_read_regx, line) and os.path.isfile('{}/{}/repro.prog'.format(crash_path, case)):
                            res.append(os.path.join(crash_path, case))
                            continue
                        if utilities.regx_match(kasan_write_regx, line) and os.path.isfile('{}/{}/repro.prog'.format(crash_path, case)):
                            res.append(os.path.join(crash_path, case))
                            continue
                        if utilities.regx_match(double_free_regx, line) and os.path.isfile('{}/{}/repro.prog'.format(crash_path, case)):
                            res.append(os.path.join(crash_path, case))
                            continue
        return res
    
    def read_crash(self, syz_repro, syz_commit, log, fixed, c_repro, i386):
        self.kill_qemu = False
        res = []
        trigger = False
        if log != None:
            res = self.read_from_log(log)
        else:
            self.case_logger.info("=============================crash.read_crash=============================")
            for i in range(0, self.qemu_num):
                x = threading.Thread(target=self.trigger_ori_crash, args=(syz_repro, syz_commit, c_repro, i386, i, fixed,), name="trigger_ori_crash-{}".format(i))
                x.start()
                if self.debug:
                    x.join()
                #crashes, trigger = self.trigger_ori_crash(syz_repro, syz_commit, c_repro, i386, fixed)
            for i in range(0, self.qemu_num):
                [crashes, high_risk] = self.queue.get(block=True)
                if not trigger and high_risk:
                    trigger = high_risk
                    res = crashes
                    self.kill_qemu = True
                if res == []:
                    res = crashes
        if len(res) == 1 and isinstance(res[0], str):
            self.case_logger.error(res[0])
            self.logger.error(res[0])
            return [], trigger
        self.save_crash_log(res)
        return res, trigger
    
    def read_existed_crash(self, crash_path):
        res = []
        crash = []
        record_flag = 0
        kasan_flag = 0
        report_path = os.path.join(crash_path, "repro.log")
        if os.path.isfile(report_path):
            with open(report_path, "r") as f:
                lines = f.readlines()
                for line in lines:
                    if utilities.regx_match(boundary_regx, line) or \
                       utilities.regx_match(message_drop_regx, line):
                        record_flag ^= 1
                        if record_flag == 0 and kasan_flag == 1:
                            res.append(crash)
                            crash = []
                            kasan_flag ^= 1
                        continue
                    if utilities.regx_match(kasan_mem_regx, line) or \
                       utilities.regx_match(kasan_double_free_regx, line):
                       kasan_flag ^= 1
                    if record_flag and kasan_flag:
                        crash.append(line)
        return res

    def read_from_log(self, log):
        res = []
        crash = []
        record_flag = 0
        kasan_flag = 0
        r = utilities.request_get(log)
        text = r.text.split('\n')
        for line in text:
            if record_flag == 0 and utilities.regx_match(call_trace_regx, line):
                record_flag ^= 1
                kasan_flag ^= 1
            if utilities.regx_match(boundary_regx, line) or \
                utilities.regx_match(message_drop_regx, line):
                record_flag ^= 1
                if record_flag == 0 and kasan_flag == 1:
                    res.append(crash)
                    crash = []
                continue
            if utilities.regx_match(kasan_mem_regx, line) or \
                utilities.regx_match(kasan_double_free_regx, line):
                kasan_flag ^= 1
            if record_flag and kasan_flag:
                crash.append(line)
        return res
        
    def save_crash_log(self, log):
        with open("{}/poc/crash_log".format(self.case_path), "w+") as f:
            for each in log:
                for line in each:
                    f.write(line+"\n")
                f.write("\n")
    
    def deploy_linux(self, commit, config, fixed):
        target = os.path.join(self.package_path, "scripts/deploy_linux.sh")
        utilities.chmodX(target)
        p = None
        if commit == None and config == None:
            #self.logger.info("run: scripts/deploy_linux.sh {} {}".format(self.linux_path, patch_path))
            p = Popen([target, self.compiler, str(fixed), self.linux_path, self.package_path],
                stdout=PIPE,
                stderr=STDOUT)
        else:
            #self.logger.info("run: scripts/deploy_linux.sh {} {} {} {}".format(self.linux_path, patch_path, commit, config))
            p = Popen([target, self.compiler, str(fixed), self.linux_path, self.package_path, commit, config,  "0"],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        return exitcode

    def trigger_ori_crash(self, syz_repro, syz_commit, c_repro, i386, th_index,fixed=0):
        res = []
        trgger_hunted_bug = False
        repro_type = utilities.CASE
        if utilities.regx_match(r'https:\/\/syzkaller\.appspot\.com\/', syz_repro):
            repro_type = utilities.URL
        c_hash = ""
        if repro_type == utilities.CASE:
            try:
                c_hash = syz_repro.split('/')[-2]
            except:
                self.logger.info("Failed to parse repro {}".format(syz_repro))
        else:
            c_hash = syz_commit + "-ori"
        qemu = VM(hash_tag=syz_commit, linux=self.linux_path, port=self.ssh_port+th_index, image=self.image_path, proj_path="{}/poc/".format(self.case_path) ,log_name="qemu-{}.log".format(c_hash), log_suffix=str(th_index), timeout=10*60, debug=self.debug)
        qemu.qemu_logger.info("QEMU-{} launched. Fixed={}\n".format(th_index, fixed))
        p = qemu.run()
        
        extract_report = False
        qemu_close = False
        out_begin = 0
        record_flag = 0
        kasan_flag = 0
        write_flag = 0
        read_flag = 0
        crash = []
        try:
            while not qemu_close:
                # We need one more iteration to get remain output from qemu
                if p.poll() != None and not qemu.qemu_ready:
                    qemu_close = True
                if qemu.qemu_ready and out_begin == 0:
                    ok = self.upload_exp(syz_repro, self.ssh_port+th_index, syz_commit, repro_type, c_repro, i386, fixed, qemu.qemu_logger)
                    if not ok:
                        p.kill()
                        break
                    ok = self.run_exp(syz_repro, self.ssh_port+th_index, repro_type, ok, i386, th_index, qemu.qemu_logger)
                    if not ok:
                        p.kill()
                        break
                    extract_report=True
                if extract_report:
                    out_end = len(qemu.output)
                    for line in qemu.output[out_begin:]:
                        if utilities.regx_match(call_trace_regx, line) or \
                        utilities.regx_match(message_drop_regx, line):
                            record_flag = 1
                        if utilities.regx_match(boundary_regx, line) or \
                        utilities.regx_match(panic_regx, line):
                            if record_flag == 1:
                                res.append(crash)
                                crash = []
                                if kasan_flag and (write_flag or read_flag):
                                    trgger_hunted_bug = True
                                    if write_flag:
                                        self.logger.debug("QEMU threaded {}: OOB/UAF write triggered".format(th_index))
                                    if read_flag:
                                        self.logger.debug("QEMU threaded {}: OOB/UAF read triggered".format(th_index))
                                    p.kill()
                                    break
                            record_flag = 1
                            continue
                        if utilities.regx_match(kasan_mem_regx, line) or \
                        utilities.regx_match(kasan_double_free_regx, line):
                            kasan_flag = 1
                        if utilities.regx_match(write_regx, line):
                            write_flag = 1
                        if self.store_read and utilities.regx_match(read_regx, line):
                            read_flag = 1
                        if record_flag or kasan_flag:
                            crash.append(line)
                    out_begin = out_end
        except Exception as e:
            self.case_logger.error("Exception occur when reporducing crash: {}".format())
            if p.poll() == None:
                p.kill()
        if not extract_report:
            res = ['QEMU threaded {}: Error occur at booting qemu'.format(th_index)]
            if p.poll() == None:
                p.kill()
        self.queue.put([res, trgger_hunted_bug])
        return

    def upload_exp(self, syz_repro, port, syz_commit, repro_type, c_repro, i386, fixed, logger):
        target = os.path.join(self.package_path, "scripts/upload-exp.sh")
        utilities.chmodX(target)
        p = Popen([target, self.case_path, syz_repro,
            str(port), self.image_path, syz_commit, str(repro_type), str(c_repro), str(i386), str(fixed), self.compiler],
        stdout=PIPE,
        stderr=STDOUT)
        with p.stdout:
            log_anything(p.stdout, logger, self.debug)
        exitcode = p.wait()
        if exitcode != 2 and exitcode != 3:
            return 0
        return exitcode
    
    def run_exp(self, syz_repro, port, repro_type, exitcode, i386, th_index, logger=None):
        if repro_type == utilities.URL:
            r = utilities.request_get(syz_repro)
            text = r.text.split('\n')
            command = self.make_commands(text, exitcode, i386)
        else:
            with open(syz_repro, "r") as f:
                text = f.readlines()
            #Temporarily disable read command from repro.command
            #It may cause misbehavior of bugs.
            #Since the new capabilities are from a specific version of syzkaler
            #We just need to parse one type of testcase, it's totally OK
            """dirname = os.path.dirname(syz_repro)
            command_path = os.path.join(dirname, "repro.command")
            if os.path.isfile(command_path):
                with open(command_path, 'r') as f:
                    command = f.readline().strip('\n')
            else:"""
            command = self.make_commands(text, exitcode, i386)
        target = os.path.join(self.package_path, "scripts/run-script.sh")
        utilities.chmodX(target)
        p1 = Popen([target, command, str(port), self.image_path, self.case_path],
        stdout=PIPE,
        stderr=STDOUT)
        with p1.stdout:
            if logger != None:
                log_anything(p1.stdout, logger, self.debug)
        exitcode = p1.wait()
        if exitcode == 1:
            self.case_logger.error("QEMU threaded {}: Usually, there is no reproducer in the crash".format(th_index))
            return 0

        """p2 = process(["ssh", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
        "-i", "{}/stretch.img.key".format(self.image_path), 
        "-p", str(port), "root@localhost"])
        p2.sendline("chmod +x run.sh && ./run.sh")"""
        p2 = Popen(["ssh", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
        "-i", "{}/stretch.img.key".format(self.image_path), 
        "-p", str(port), "root@localhost", "chmod +x run.sh && ./run.sh"],
        stdout=PIPE,
        stderr=STDOUT)
        with p2.stdout:
            if logger != None:
                x = threading.Thread(target=log_anything, args=(p2.stdout, logger, self.debug), name="{} run.sh logger".format(th_index))
                x.start()
        return 1

    def make_commands(self, text, support_enable_features, i386):
        command = "/syz-execprog -executor=/syz-executor "
        enabled = "-enable="
        normal_pm = {"arch":"amd64", "threaded":"false", "collide":"false", "sandbox":"none", "fault_call":"-1", "fault_nth":"0"}
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                pm = {}
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    self.case_logger.info("Using old syz_repro")
                    pm = utilities.syzrepro_convert_format(line[1:])
                for each in normal_pm:
                    if each in pm and pm[each] != "":
                        command += "-" + each + "=" +str(pm[each]).lower() + " "
                    else:
                        if each=='arch' and i386:
                            command += "-" + each + "=386" + " "
                        else:
                            command += "-" + each + "=" +str(normal_pm[each]).lower() + " "
                if "procs" in pm and str(pm["procs"]) != "1":
                    num = int(pm["procs"])
                    command += "-procs=" + str(num*2) + " "
                else:
                    command += "-procs=" + str(pm["procs"]) + " "
                if "repeat" in pm and pm["repeat"] != "":
                    command += "-repeat=" + "0 "
                #It makes no sense that limiting the features of syz-execrpog, just enable them all
                
                if support_enable_features != 2:
                    if "tun" in pm and str(pm["tun"]).lower() == "true":
                        enabled += "tun,"
                    if "binfmt_misc" in pm and str(pm["binfmt_misc"]).lower() == 'true':
                        enabled += "binfmt_misc,"
                    if "cgroups" in pm and str(pm["cgroups"]).lower() == "true":
                        enabled += "cgroups,"
                    if "close_fds" in pm and str(pm["close_fds"]).lower() == "true":
                        enabled += "close_fds,"
                    if "devlinkpci" in pm and str(pm["devlinkpci"]).lower() == "true":
                        enabled += "devlink_pci,"
                    if "netdev" in pm and str(pm["netdev"]).lower() == "true":
                        enabled += "net_dev,"
                    if "resetnet" in pm and str(pm["resetnet"]).lower() == "true":
                        enabled += "net_reset,"
                    if "usb" in pm and str(pm["usb"]).lower() == "true":
                        enabled += "usb,"
                
                if enabled[-1] == ',':
                    command += enabled[:-1] + " testcase"
                else:
                    command += "testcase"
                break
        return command
    
    def monitor_execution(self, p):
        count = 0
        while (count <60):
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
            
    def __match_allocated_section(self, report1 ,report2):
        self.case_logger.info("match allocated section")
        ratio = 1
        allocation1 = utilities.extract_allocated_section(report1, self.kasan_func_list)
        allocation2 = utilities.extract_allocated_section(report2, self.kasan_func_list)
        seq1 = [utilities.extract_func_name(x) for x in allocation1 if utilities.extract_func_name(x) != None]
        seq2 = [utilities.extract_func_name(x) for x in allocation2 if utilities.extract_func_name(x) != None]
        counter = 0

        """
        for i in range(0, min(len(seq1), len(seq2))):
            if seq1[i] == seq2[i]:
                counter += 1
            else:
                break
            if counter == 2 or counter == min(len(seq1), len(seq2)):
                return [True, ratio]
        """

        diff = utilities.levenshtein(seq1, seq2)
        m = max(len(seq1), len(seq2))
        if m > 0:
            ratio = diff/float(m)
        else:
            self.case_logger.error("Allocation do not exist")
        self.case_logger.info("diff ratio: {}".format(ratio))
        if ratio > 0.3:
            return [False, ratio]
        return [True, ratio]
    
    def __match_call_trace(self, report1, report2):
        self.case_logger.info("match call trace")
        ratio = 1
        trace1 = utilities.extrace_call_trace(report1, self.kasan_func_list)
        trace2 = utilities.extrace_call_trace(report2, self.kasan_func_list)
        seq1 = [utilities.extract_func_name(x) for x in trace1 if utilities.extract_func_name(x) != None]
        seq2 = [utilities.extract_func_name(x) for x in trace2 if utilities.extract_func_name(x) != None]
        counter = 0

        """
        for i in range(0, min(len(seq1), len(seq2))):
            if seq1[i] == seq2[i]:
                counter += 1
            else:
                break
            if counter == 2 or counter == min(len(seq1), len(seq2)):
                return [True, ratio]
        """

        diff = utilities.levenshtein(seq1, seq2)
        m = max(len(seq1), len(seq2))
        if m > 0:
            ratio = diff/float(m)
        else:
            self.case_logger.error("Call trace do not exist")
        self.case_logger.info("diff ratio: {}".format(ratio))
        if ratio > 0.3:
            return [False, ratio]
        return [True, ratio]
    
    def __init_case_logger(self, logger_name):
        handler = logging.FileHandler("{}/poc/log".format(self.case_path))
        format = logging.Formatter('%(asctime)s %(message)s')
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.logger.level)
        logger.addHandler(handler)
        logger.propagate = False
        if self.debug:
            logger.propagate = True
        return logger
    
    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            line = line.decode("utf-8").strip('\n').strip('\r')
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)

def log_anything(pipe, logger, debug):
    try:
        for line in iter(pipe.readline, b''):
            try:
                line = line.decode("utf-8").strip('\n').strip('\r')
            except:
                logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                continue
            if logger.level == logging.INFO:
                logger.info(line)
            if logger.level == logging.DEBUG:
                logger.debug(line)
            if debug:
                print(line)
    except ValueError:
        if pipe.close:
            return

def log_by_pwn_process(p, logger, debug):
    while p.poll() == None:
        try:
            line = p.recvuntil("\n", timeout=10)
        except EOFError:
            break
        if logger.level == logging.INFO:
                logger.info(line)
        if logger.level == logging.DEBUG:
            logger.debug(line)
        if debug:
            print(line)

def link_correct_linux_repro(case_path, index):
    dst = os.path.join(case_path, "linux")
    try:
        os.remove(dst)
    except:
        pass
    src = "{}/tools/linux-{}".format(project_path, index)
    os.symlink(src, dst)

def reproduce_with_ori_poc(index):
    while(1):
        lock.acquire(blocking=True)
        l = list(crawler.cases.keys())
        if len(l) == 0:
            lock.release()
            break
        hash = l[0]
        case = crawler.cases.pop(hash)
        lock.release()

        print("Thread {}: running case {} [{}/{}]".format(index, hash, len(l)-1, total))
        case_path = "{}/work/{}/{}".format(project_path, path, hash[:7])
        if not os.path.isdir(case_path):
            print("Thread {}: running case {}: {} does not exist".format(index, hash[:7], case_path))
            continue
        if args.linux != "-1":
            offset = int(args.linux)
            index = int(args.linux)
        link_correct_linux_repro(case_path, index)

        #hdlr = logging.FileHandler('./replay.out')
        #logger = logging.getLogger('crash-{}'.format(hash))
        #formatter = logging.Formatter('%(asctime)s Thread {}: {}: %(message)s'.format(index, hash[:7]))
        #hdlr.setFormatter(formatter)
        #logger.addHandler(hdlr) 
        #logger.setLevel(logging.INFO)
        logger = logging.getLogger("thread-{}".format(index))
        handler = logging.StreamHandler(sys.stdout)
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s Thread {}: {}: %(message)s'.format(index, hash[:7]))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        syz_repro = case["syz_repro"]
        syz_commit = case["syzkaller"]
        commit = case["commit"]
        config = case["config"]
        c_repro = case["c_repro"]
        i386 = None
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        log = case["log"]
        logger.info("Running case: {}".format(hash))
        offset = index
        gcc = utilities.set_gcc_version(time_parser.parse(case["time"]))
        checker = CrashChecker(project_path, case_path, default_port, logger, args.debug, offset, 4, gcc=gcc)
        if checker.deploy_linux(commit,config,0) == 1:
            print("Thread {}: running case {}: Error occur in deploy_linux.sh".format(index, hash[:7]))
            continue
        report, trigger = checker.read_crash(case["syz_repro"], case["syzkaller"], None, 0, case["c_repro"], i386)
        if report != [] and trigger:
            for each in report:
                for line in each:
                    if utilities.regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line) or\
                    utilities.regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                    if utilities.regx_match(r'Write of size (\d+) at addr (\w*)', line):
                        write_without_mutating = True
                        print("Thread {}: running case {}: OOB/UAF Write without mutating".format(index, hash[:7]))
                        print("Thread {}: running case {}: Detect read before write".format(index, hash[:7]))
                        break

def reproduce_one_case(index):
    while(1):
        lock.acquire(blocking=True)
        l = list(crawler.cases.keys())
        if len(l) == 0:
            lock.release()
            break
        hash = l[0]
        case = crawler.cases.pop(hash)
        lock.release()

        print("Thread {}: running case {} [{}/{}]".format(index, hash, len(l)-1, total))
        case_path = "{}/work/{}/{}".format(project_path, path, hash[:7])
        if not os.path.isdir(case_path):
            print("{} does not exist".format(case_path))
            continue
        if args.linux != "-1":
            offset = int(args.linux)
            index = int(args.linux)
        link_correct_linux_repro(case_path, index)

        #hdlr = logging.FileHandler('./replay.out')
        #logger = logging.getLogger('crash-{}'.format(hash))
        #formatter = logging.Formatter('%(asctime)s Thread {}: {}: %(message)s'.format(index, hash[:7]))
        #hdlr.setFormatter(formatter)
        #logger.addHandler(hdlr) 
        #logger.setLevel(logging.INFO)

        logger = logging.getLogger("case-{}".format(hash))
        handler = logging.StreamHandler(sys.stdout)
        logger.setLevel(logging.INFO)

        if args.debug:
            logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s Thread {}: {}: %(message)s'.format(index, hash[:7]))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        syz_repro = case["syz_repro"]
        syz_commit = case["syzkaller"]
        commit = case["commit"]
        config = case["config"]
        c_repro = case["c_repro"]
        i386 = None
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        log = case["log"]
        logger.info("Running case: {}".format(hash))
        offset = index
        gcc = utilities.set_gcc_version(time_parser.parse(case["time"]))
        checker = CrashChecker(project_path, case_path, default_port, logger, args.debug, offset, 4, gcc=gcc)
        checker.case_logger.info("=============================A reproducing process starts=============================")
        if args.identify_by_trace:
            if args.reproduce:
                res = checker.run(syz_repro, syz_commit, None, commit, config, c_repro, i386)
            else:
                res = checker.run(syz_repro, syz_commit, log, commit, config, c_repro, i386)
            checker.logger.info("{}:{}".format(hash, res[0]))
            if res[0]:
                n = checker.diff_testcase(res[1], syz_repro)
                checker.logger.info("difference of characters of two testcase: {}".format(n))
                checker.logger.info("successful crash: {}".format(res[1]))
        if args.identify_by_patch:
            commit = utilities.get_patch_commit(hash)
            if commit != None:
                checker.repro_on_fixed_kernel(syz_commit, case["commit"], config, c_repro, i386, commit)

    print("Thread {} exit->".format(index))

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Determine if the new crashes are from the same root cause of the old one\n'
                                                 'eg. python crash.py -i 7fd1cbe3e1d2b3f0366d5026854ee5754d451405')
    parser.add_argument('-i', '--input', nargs='?', action='store',
                        help='By default it analyze all cases under folder \'succeed\', but you can indicate a specific one.')
    parser.add_argument('--ignore', nargs='?', action='store',
                        help='A file contains cases hashs which are ignored. One line for each hash.')
    parser.add_argument('-r', '--reproduce', action='store_true',
                        help='Reproduce cases with the original testcase')
    parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                        default='5', help='The maximum of parallel processes\n'
                        '(default valus is 5)')
    parser.add_argument('--folder', const='succeed', nargs='?', default='succeed',
                        choices=['succeed', 'completed', 'incomplete', 'error'],
                        help='Reproduce cases with the original testcase')
    parser.add_argument('--linux', nargs='?', action='store',
                        default='-1',
                        help='Indicate which linux repo to be used for running\n'
                            '(--parallel-max will be set to 1)')
    parser.add_argument('-p', '--port', nargs='?',
                        default='3777',
                        help='The default port that is used by reproducing\n'
                        '(default value is 3777)')
    parser.add_argument('--identify-by-trace', '-ibt', action='store_true',
                        help='Reproduce on fixed kernel')
    parser.add_argument('--store-read', action='store_true',
                        help='Do not ignore memory reading')
    parser.add_argument('--identify-by-patch', '-ibp', action='store_true',
                        help='Reproduce on unfixed kernel')
    parser.add_argument('--test-original-poc', action='store_true',
                        help='Reproduce with original PoC')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    print("running crash.py")
    args = args_parse()
    crawler = Crawler()

    if args.debug:
        args.parallel_max="1"

    ignore = []
    if args.ignore != None:
        with open(args.ignore, "r") as f:
            text = f.readlines()
            for line in text:
                line = line.strip('\n')
                ignore.append(line)

    path = args.folder
    type = utilities.FOLDER
    if args.input != None:
        if len(args.input) == 40:
            crawler.run_one_case(args.input)
        else:
            with open(args.input, 'r') as f:
                text = f.readlines()
                for line in text:
                    line = line.strip('\n')
                    crawler.run_one_case(line)
    else:
        for url in utilities.urlsOfCases(path, type):
            if url not in ignore:
                crawler.run_one_case(url)
    
    project_path = os.getcwd()
    lock = threading.Lock()
    l = list(crawler.cases.keys())
    total = len(l)
    default_port = int(args.port)
    parallel_max = int(args.parallel_max)
    if args.test_original_poc:
        thread_fn = reproduce_with_ori_poc
    else:
        thread_fn = reproduce_one_case
    for i in range(min(len(crawler.cases), parallel_max)):
        x = threading.Thread(target=thread_fn, args=(i,))
        x.start()
        
import os, re, stat, sys
import logging
import argparse
import utilities
import time
import threading
import json
import pathlib

from subprocess import call, Popen, PIPE, STDOUT
from syzbotCrawler import Crawler
from dateutil import parser as time_parser

startup_regx = r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'
boundary_regx = r'======================================================'
call_trace_regx = r'Call Trace:'
message_drop_regx = r'printk messages dropped'
panic_regx = r'Kernel panic'
kasan_regx = r'BUG: KASAN: ([a-z\\-]+) in ([a-zA-Z0-9_]+).*'
free_regx = r'BUG: KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
reboot_regx = r'reboot: machine restart'
port_error_regx = r'Could not set up host forwarding rule'
magic_regx = r'\?!\?MAGIC\?!\?read->(\w*) size->(\d*)'
write_regx = r'Write of size (\d+) at addr (\w*)'
default_port = 3777
project_path = ""
NONCRASH = 0
CONFIRM = 1
SUSPICIOUS = 2
thread_fn = None

class CrashChecker:
    def __init__(self, project_path, case_path, ssh_port, logger, debug, gcc="gcc-7"):
        os.makedirs("{}/poc".format(case_path), exist_ok=True)
        self.kasan_regx = r'KASAN: ([a-z\\-]+) Write in ([a-zA-Z0-9_]+).*'
        self.free_regx = r'KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
        self.logger = logger
        self.project_path = project_path
        self.case_path = case_path
        self.image_path = "{}/img".format(self.case_path)
        self.linux_path = "{}/linux".format(self.case_path)
        self.case_logger = self.__init_case_logger("{}-info".format(case_path))
        self.ssh_port = ssh_port
        self.kasan_func_list = self.read_kasan_funcs()
        self.debug = debug
        self.gcc = gcc

    def run(self, syz_repro, syz_commit, log=None, linux_commit=None, config=None, c_repro=None, i386=None):
        self.case_logger.info("=============================crash.run=============================")
        if log != None:
            exitcode = self.deploy_linux(linux_commit, config, 0)
            if exitcode == 1:
                self.logger.info("Error occur at deploy_linux.sh")
                return [False, None]
        ori_crash_report = self.read_crash(syz_repro, syz_commit, log, 0, c_repro, i386)
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
            ori_crash_report = self.read_crash(path_repro, syz_commit, None, 1, c_repro, i386)
            if ori_crash_report != []:
                reproduceable[key] = CONFIRM
            else:
                reproduceable[key] = NONCRASH
            if len(ori_crash_report) == 1 and ori_crash_report[0] == 'crash without kasan':
                reproduceable[key] = SUSPICIOUS
        #apply the patch
        exitcode = self.deploy_linux(patch_commit, config, 1)
        if exitcode == 1:
            self.logger.info("Error occur at deploy_linux.sh")
            return res
        #reproduce on fixed kernel
        for path in crashes_path:
            key = os.path.basename(path)
            path_repro = os.path.join(path, "repro.prog")
            ori_crash_report = self.read_crash(path_repro, syz_commit, None, 1, c_repro, i386)
            if ori_crash_report != []:
                self.logger.info("Reproduceable: {}".format(key))
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
        utilities.chmodX("scripts/patch_applying_check.sh")
        p = Popen(["scripts/patch_applying_check.sh", self.linux_path, linux_commit, config, patch_commit, self.gcc],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        return exitcode
    
    def read_kasan_funcs(self):
        res = []
        path = os.path.join(self.project_path, "resources/kasan_related_funcs")
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
                        if utilities.regx_match(self.kasan_regx, line) and os.path.isfile('{}/{}/repro.prog'.format(crash_path, case)):
                            res.append(os.path.join(crash_path, case))
                            continue
                        if utilities.regx_match(self.free_regx, line) and os.path.isfile('{}/{}/repro.prog'.format(crash_path, case)):
                            res.append(os.path.join(crash_path, case))
                            continue
        return res
    
    def read_crash(self, syz_repro, syz_commit, log, fixed, c_repro, i386):
        if log != None:
            res = self.read_from_log(log)
        else:
            res = self.trigger_ori_crash(syz_repro, syz_commit, c_repro, i386, fixed)
        if len(res) == 1 and isinstance(res[0], str):
            self.case_logger.error(res[0])
            self.logger.error(res[0])
            return []
        self.save_crash_log(res)
        return res
    
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
                    if utilities.regx_match(kasan_regx, line) or \
                       utilities.regx_match(free_regx, line):
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
            if utilities.regx_match(kasan_regx, line) or \
                utilities.regx_match(free_regx, line):
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
        utilities.chmodX("scripts/deploy_linux.sh")
        p = None
        if commit == None and config == None:
            #self.logger.info("run: scripts/deploy_linux.sh {} {}".format(self.linux_path, patch_path))
            p = Popen(["scripts/deploy_linux.sh", self.gcc, str(fixed), self.linux_path, self.project_path],
                stdout=PIPE,
                stderr=STDOUT)
        else:
            #self.logger.info("run: scripts/deploy_linux.sh {} {} {} {}".format(self.linux_path, patch_path, commit, config))
            p = Popen(["scripts/deploy_linux.sh", self.gcc, str(fixed), self.linux_path, self.project_path, commit, config],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        return exitcode

    def trigger_ori_crash(self, syz_repro, syz_commit, c_repro, i386, fixed=0):
        res = []
        p = Popen(["qemu-system-x86_64", "-m", "2G", "-smp", "2", 
                    "-net", "nic,model=e1000", "-net", "user,host=10.0.2.10,hostfwd=tcp::{}-:22".format(self.ssh_port),
                    "-display", "none", "-serial", "stdio", "-no-reboot", "-enable-kvm", "-cpu", "host,migratable=off", 
                    "-hda", "{}/stretch.img".format(self.image_path), 
                    "-snapshot", "-kernel", "{}/arch/x86_64/boot/bzImage".format(self.linux_path),
                    "-append", "earlyprintk=serial oops=panic nmi_watchdog=panic panic=1 \
                        ftrace_dump_on_oops=orig_cpu rodata=n vsyscall=native net.ifnames=0 \
                        biosdevname=0 root=/dev/sda console=ttyS0 kvm-intel.nested=1 \
                        kvm-intel.unrestricted_guest=1 kvm-intel.vmm_exclusive=1 \
                        kvm-intel.fasteoi=1 kvm-intel.ept=1 kvm-intel.flexpriority=1 \
                        kvm-intel.vpid=1 kvm-intel.emulate_invalid_guest_state=1 \
                        kvm-intel.eptad=1 kvm-intel.enable_shadow_vmcs=1 kvm-intel.pml=1 \
                        kvm-intel.enable_apicv=1"],
                  stdout=PIPE,
                  stderr=STDOUT
                  )
        x = threading.Thread(target=self.monitor_execution, args=(p,))
        x.start()
        with p.stdout:
            extract_report = False
            record_flag = 0
            kasan_flag = 0
            write_flag = 0
            crash = []
            for line in iter(p.stdout.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    self.logger.error('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                if utilities.regx_match(reboot_regx, line) or utilities.regx_match(port_error_regx, line):
                    self.case_logger.error("Booting qemu failed")
                if self.debug:
                    print(line)
                if utilities.regx_match(startup_regx, line):
                    repro_type = utilities.CASE
                    if utilities.regx_match(r'https:\/\/syzkaller\.appspot\.com\/', syz_repro):
                        repro_type = utilities.URL
                    utilities.chmodX("scripts/upload-exp.sh")
                    p2 = Popen(["scripts/upload-exp.sh", self.case_path, syz_repro,
                        str(self.ssh_port), self.image_path, syz_commit, str(repro_type), str(c_repro), str(i386), str(fixed), self.gcc],
                    stdout=PIPE,
                    stderr=STDOUT)
                    with p2.stdout:
                        self.__log_subprocess_output(p2.stdout, logging.INFO)
                    exitcode = p2.wait()
                    if exitcode != 0:
                        p.kill()
                        break
                    if repro_type == utilities.URL:
                        r = utilities.request_get(syz_repro)
                        text = r.text.split('\n')
                        command = self.make_commands(text, exitcode, i386)
                    else:
                        with open(syz_repro, "r") as f:
                            text = f.readlines()
                        dirname = os.path.dirname(syz_repro)
                        command_path = os.path.join(dirname, "repro.command")
                        if os.path.isfile(command_path):
                            with open(command_path, 'r') as f:
                                command = f.readline().strip('\n')
                        else:
                            command = self.make_commands(text, exitcode, i386)
                    utilities.chmodX("scripts/run-script.sh")
                    p3 = Popen(["scripts/run-script.sh", command, str(self.ssh_port), self.image_path, self.case_path],
                    stdout=PIPE,
                    stderr=STDOUT)
                    exitcode = p3.wait()
                    if exitcode == 1:
                        self.case_logger.error("Usually, there is no reproducer in the crash")
                        p.kill()
                        break
                    Popen(["ssh", "-p", str(self.ssh_port), "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
                    "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
                    "-o", "ConnectTimeout=10", "-i", "{}/stretch.img.key".format(self.image_path), 
                    "-v", "root@localhost", "chmod +x run.sh && ./run.sh"],
                    stdout=PIPE,
                    stderr=STDOUT)
                    extract_report = True
                if extract_report:
                    self.case_logger.info(line)
                    if utilities.regx_match(call_trace_regx, line) or \
                       utilities.regx_match(message_drop_regx, line):
                        record_flag = 1
                    if utilities.regx_match(boundary_regx, line) or \
                       utilities.regx_match(panic_regx, line):
                        if record_flag == 1:
                            res.append(crash)
                            crash = []
                            if kasan_flag == 1 and write_flag == 1:
                                self.logger.info("OOB/UAF write triggered")
                                p.kill()
                                break
                        record_flag = 1
                        continue
                    if utilities.regx_match(kasan_regx, line) or \
                       utilities.regx_match(free_regx, line):
                        kasan_flag = 1
                    if utilities.regx_match(write_regx, line):
                        write_flag = 1
                    if record_flag or kasan_flag:
                        crash.append(line)
        if not extract_report:
            res = ['Error occur at booting qemu']
        return res

    def make_commands(self, text, support_enable_features, i386):
        command = "/syz-execprog -executor=/syz-executor "
        enabled = "-enable="
        normal_pm = {"arch":"amd64", "threaded":"false", "collide":"false", "sandbox":"none", "fault_call":"-1", "fault_nth":"0", "os":"linux"}
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
                    if str(pm["repeat"]).lower() == 'true':
                        command += "-repeat=" + "0 "
                    else:
                        command += "-repeat=" + "1 "
                #It makes no sense that limiting the features of syz-execrpog, just enable them all
                """
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
                """
                if enabled[-1] == ',':
                    command += enabled[:-1] + " testcase"
                else:
                    command += "testcase"
                break
        return command
    
    def monitor_execution(self, p):
        count = 0
        while (count <10):
            count += 1
            time.sleep(60)
            poll = p.poll()
            if poll != None:
                return
        self.case_logger.info('Time out, kill qemu')
        p.kill()
            
    def __match_allocated_section(self, report1 ,report2):
        self.case_logger.info("match allocated section")
        ratio = 1
        allocation1 = self.__extract_allocated_section(report1)
        allocation2 = self.__extract_allocated_section(report2)
        seq1 = [self.__extract_func_name(x) for x in allocation1 if self.__extract_func_name(x) != None]
        seq2 = [self.__extract_func_name(x) for x in allocation2 if self.__extract_func_name(x) != None]
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
        trace1 = self.__extrace_call_trace(report1)
        trace2 = self.__extrace_call_trace(report2)
        seq1 = [self.__extract_func_name(x) for x in trace1 if self.__extract_func_name(x) != None]
        seq2 = [self.__extract_func_name(x) for x in trace2 if self.__extract_func_name(x) != None]
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

    def __is_kasan_func(self, func_name):
        if func_name in self.kasan_func_list:
            return True
        return False
    
    def __extract_allocated_section(self, report):
        res = []
        record_flag = 0
        for line in report:
            if record_flag and not self.__is_kasan_func(self.__extract_func_name(line)):
                res.append(line)
            if utilities.regx_match(r'Allocated by task \d+', line):
                record_flag ^= 1
            if utilities.regx_match(r'Freed by task \d+', line):
                record_flag ^= 1
                break
        return res[:-2]
    
    def __extrace_call_trace(self, report):
        res = []
        record_flag = 0
        implicit_call_regx = r'\[.+\]  \?.*'
        for line in report:
            if record_flag and \
               not utilities.regx_match(implicit_call_regx, line) and \
               not self.__is_kasan_func(self.__extract_func_name(line)):
                res.append(line)
            if utilities.regx_match(r'Call Trace', line):
                record_flag ^= 1
            if record_flag == 1 and utilities.regx_match(r'Allocated by task', line):
                record_flag ^= 1
                break
        return res

    def __extract_func_name(self, line):
        m = re.search(r'([A-Za-z0-9_.]+)\+0x[0-9a-f]+', line)
        if m != None and len(m.groups()) != 0:
            return m.groups()[0]
    
    def __init_case_logger(self, logger_name):
        handler = logging.FileHandler("{}/poc/log".format(self.case_path))
        format = logging.Formatter('%(asctime)s %(message)s')
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.logger.level)
        logger.addHandler(handler)
        return logger
    
    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            line = line.decode("utf-8").strip('\n').strip('\r')
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)

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
        checker = CrashChecker(project_path, case_path, default_port+offset, logger, args.debug, gcc=gcc)
        if checker.deploy_linux(commit,config,0) == 1:
            print("Thread {}: running case {}: Error occur in deploy_linux.sh".format(index, hash[:7]))
            continue
        report = checker.read_crash(case["syz_repro"], case["syzkaller"], None, 0, case["c_repro"], i386)
        if report != []:
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
        checker = CrashChecker(project_path, case_path, default_port+offset, logger, args.debug, gcc=gcc)
        checker.case_logger.info("=============================A reproducing process starts=============================")
        if not args.fixed_only:
            if args.reproduce:
                res = checker.run(syz_repro, syz_commit, None, commit, config, c_repro, i386)
            else:
                res = checker.run(syz_repro, syz_commit, log, commit, config, c_repro, i386)
            checker.logger.info("{}:{}".format(hash, res[0]))
            if res[0]:
                n = checker.diff_testcase(res[1], syz_repro)
                checker.logger.info("difference of characters of two testcase: {}".format(n))
                checker.logger.info("successful crash: {}".format(res[1]))
        if not args.unfixed_only:
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
    parser.add_argument('--fixed-only', action='store_true',
                        help='Reproduce on fixed kernel')
    parser.add_argument('--unfixed-only', action='store_true',
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

    logger = logging.getLogger("main")
    handler = logging.StreamHandler(sys.stdout)
    logger.setLevel(logging.INFO)

    if args.debug:
        args.parallel_max="1"
        logger.setLevel(logging.DEBUG)

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
        
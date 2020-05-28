import os, re, stat
import logging
import argparse
import utilities
import time
import threading
import json

from subprocess import call, Popen, PIPE, STDOUT
from syzbotCrawler import Crawler

startup_regx = r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'
boundary_regx = r'======================================================'
message_drop_regx = r'printk messages dropped'
panic_regx = r'Kernel panic'
kasan_regx = r'BUG: KASAN: ([a-z\\-]+) in ([a-zA-Z0-9_]+).*'
free_regx = r'BUG: KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
reboot_regx = r'reboot: machine restart'
magic_regx = r'\?!\?MAGIC\?!\?read->(\w*) size->(\d*)'
default_port = 3777
p_poc = None

class CrashChecker:
    def __init__(self, project_path, case_path, ssh_port, logger, debug, linux_index=-1):
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
        if linux_index > -1:
            self.rearrange_linux(linux_index)
        
    def rearrange_linux(self, linux_index):
        os.remove(self.linux_path)
        src = "{}/tools/linux-{}".format(self.project_path, linux_index)
        os.symlink(src, self.linux_path)

    def run(self, syz_repro, syz_commit, log=None, linux_commit=None, config=None, c_repro=None, i386=None):
        self.case_logger.info("=============================crash.run=============================")
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

    
    def repro_on_fixed_kernel(self, syz_commit, linux_commit=None, config=None, c_repro=None, i386=None):
        self.case_logger.info("=============================crash.repro_on_fixed_kernel=============================")
        crashes_path = self.extract_existed_crash(self.case_path)
        res = []
        reproduceable = {}
        #reproduce on unfixed kernel
        for path in crashes_path:
            key = os.path.basename(path)
            path_repro = os.path.join(path, "repro.prog")
            ori_crash_report = self.read_crash(path_repro, syz_commit, None, 0, c_repro, i386)
            if ori_crash_report != []:
                reproduceable[key] = True
            else:
                reproduceable[key] = False
        #apply the patch
        exitcode = self.deploy_linux(linux_commit, config, 1)
        if exitcode == 1:
            self.logger.info("Error occur at deploy_linux.sh")
            return [False, None]
        #reproduce on fixed kernel
        for path in crashes_path:
            key = os.path.basename(path)
            path_repro = os.path.join(path, "repro.prog")
            ori_crash_report = self.read_crash(path_repro, syz_commit, None, 1, c_repro, i386)
            if ori_crash_report != []:
                self.logger.info("Reproduceable: {}".format(key))
            else:
                if reproduceable[key]:
                    self.logger.info("Fixed: {}".format(key))
                    res.append(path)
                else:
                    self.logger.info("Invalid crash {}, unreproduceable on both fixed and unfixed kernel".format(key))
        return path
        
    
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
        res = []

        if os.path.isdir(crash_path):
            for case in os.listdir(crash_path):
                description_file = "{}/{}/description".format(crash_path, case)
                if os.path.isfile(description_file):
                    with open(description_file, "r") as f:
                        line = f.readline()
                        if utilities.regx_match(self.kasan_regx, line):
                            res.append(os.path.join(crash_path, case))
                            continue
                        if utilities.regx_match(self.free_regx, line):
                            res.append(os.path.join(crash_path, case))
                            continue
        return res
    
    def read_crash(self, syz_repro, syz_commit, log, fixed, c_repro, i386):
        if log != None:
            res = self.read_from_log(log)
        else:
            res = self.trigger_ori_crash(syz_repro, syz_commit, c_repro, i386, fixed)
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
            p = Popen(["scripts/deploy_linux.sh", str(fixed), self.linux_path, self.project_path],
                stdout=PIPE,
                stderr=STDOUT)
        else:
            #self.logger.info("run: scripts/deploy_linux.sh {} {} {} {}".format(self.linux_path, patch_path, commit, config))
            p = Popen(["scripts/deploy_linux.sh", str(fixed), self.linux_path, self.project_path, commit, config],
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
            crash = []
            for line in iter(p.stdout.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    self.logger.error('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                if utilities.regx_match(reboot_regx, line):
                    self.case_logger.info("Booting qemu failed")
                if self.debug:
                    print(line)
                if utilities.regx_match(startup_regx, line):
                    repro_type = utilities.CASE
                    if utilities.regx_match(r'https:\/\/syzkaller\.appspot\.com\/', syz_repro):
                        repro_type = utilities.URL
                    utilities.chmodX("scripts/upload-exp.sh")
                    p2 = Popen(["scripts/upload-exp.sh", self.case_path, syz_repro,
                        str(self.ssh_port), self.image_path, syz_commit, str(repro_type), str(c_repro), str(i386), str(fixed)],
                    stdout=PIPE,
                    stderr=STDOUT)
                    with p2.stdout:
                        self.__log_subprocess_output(p2.stdout, logging.INFO)
                    exitcode = p2.wait()
                    if exitcode == 1:
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
                        p.kill()
                        break
                    p_poc = Popen(["ssh", "-p", str(self.ssh_port), "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
                    "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
                    "-o", "ConnectTimeout=10", "-i", "{}/stretch.img.key".format(self.image_path), 
                    "-v", "root@localhost", "chmod +x run.sh && ./run.sh"],
                    stdout=PIPE,
                    stderr=STDOUT)
                    extract_report = True
                if extract_report:
                    self.case_logger.info(line)
                    if utilities.regx_match(boundary_regx, line) or \
                       utilities.regx_match(message_drop_regx, line) or \
                       utilities.regx_match(panic_regx, line):
                        record_flag ^= 1
                        if record_flag == 0 and kasan_flag == 1:
                            self.logger.info("Crash reproduceable")
                            res.append(crash)
                            crash = []
                            p.kill()
                            break
                        continue
                    if utilities.regx_match(kasan_regx, line) or \
                       utilities.regx_match(free_regx, line):
                        kasan_flag ^= 1
                    if record_flag and kasan_flag:
                        crash.append(line)
        return res

    def make_commands(self, text, support_enable_features, i386):
        command = "./syz-execprog -executor=./syz-executor "
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
        while (count <6*60):
            count += 1
            time.sleep(60)
            if p_poc != None:
                poll = p_poc.poll()
                if poll != None:
                    self.case_logger.info("PoC terminated, exit vm")
                    p.kill()
                    return
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
        syz_repro = case["syz_repro"]
        syz_commit = case["syzkaller"]
        commit = case["commit"]
        config = case["config"]
        c_repro = case["c_repro"]
        i386 = None
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        log = case["log"]
        logger.info("\nThread {}: Running case: {}".format(index, hash))
        offset = index
        linux_index = -1
        if args.linux != "-1":
            offset = int(args.linux)
            linux_index = int(args.linux)
        checker = CrashChecker(project_path, case_path, default_port+offset, logger, args.debug, linux_index)
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
                checker.repro_on_fixed_kernel(syz_commit, commit, config, c_repro, i386)

    print("Thread {} exit->".format(index, hash))

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
    parser.add_argument('--fixed-only', action='store_true',
                        help='Reproduce on fixed kernel')
    parser.add_argument('--unfixed-only', action='store_true',
                        help='Reproduce on unfixed kernel')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    print("running crash.py")
    args = args_parse()
    crawler = Crawler()

    logger = logging.getLogger('crash')
    hdlr = logging.FileHandler('./replay.out')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr) 
    logger.setLevel(logging.INFO)

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
        crawler.run_one_case(args.input)
    else:
        for url in utilities.urlsOfCases(path, type):
            if url not in ignore:
                crawler.run_one_case(url)
    
    project_path = os.getcwd()
    lock = threading.Lock()
    l = list(crawler.cases.keys())
    total = len(l)
    parallel_max = int(args.parallel_max)
    for i in range(min(len(crawler.cases), parallel_max)):
        x = threading.Thread(target=reproduce_one_case, args=(i,))
        x.start()
        
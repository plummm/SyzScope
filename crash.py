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
default_port = 3777

class CrashChecker:
    def __init__(self, project_path, case_path, ssh_port, logger):
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

    def run(self, syz_repro, syz_commit, log=None, linux_commit=None, config=None, c_repro=None, i386=None):
        self.case_logger.info("=============================crash.run=============================")
        ori_crash_report = self.read_crash(syz_repro, syz_commit, log, linux_commit, config, 0, c_repro, i386)
        if ori_crash_report == []:
            self.logger.info("No crash trigger by original poc")
            return [False, None]
        crashes_path = self.extract_existed_crash(self.case_path)
        for path in crashes_path:
            self.case_logger.info("Inspect crash: {}".format(path))
            new_crash_reports = self.read_existed_crash(path)
            if self.compare_crashes(ori_crash_report, new_crash_reports):
                return [True, path]
        return [False, None]
    
    def repro_on_fixed_kernel(self, syz_commit, linux_commit=None, config=None, c_repro=None, i386=None):
        self.case_logger.info("=============================crash.repro_on_fixed_kernel=============================")
        crashes_path = self.extract_existed_crash(self.case_path)
        for path in crashes_path:
            path_repro = os.path.join(path, "repro.prog")
            ori_crash_report = self.read_crash(path_repro, syz_commit, None, linux_commit, config, 1, c_repro, i386)
            if ori_crash_report != []:
                self.logger.info("Reproduceable: {}".format(os.path.basename(path)))
            else:
                self.logger.info("Fixed: {}".format(os.path.basename(path)))
    
    def read_kasan_funcs(self):
        res = []
        path = os.path.join(self.project_path, "resources/kasan_related_funcs")
        with open(path, "r") as f:
            lines = f.readlines()
            for line in lines:
                res.append(line.strip('\n'))
            return res

    def compare_crashes(self, ori_crash_report, new_crash_reports):
        for report1 in ori_crash_report:
            if len(report1) > 2:
                for report2 in new_crash_reports:
                    if len(report2) > 2:
                        if self.__match_allocated_section(report1, report2):
                            return True
                        if self.__match_call_trace(report1, report2):
                            return True
        return False

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
    
    def read_crash(self, syz_repro, syz_commit, log, linux_commit, config, fixed, c_repro, i386):
        if log != None:
            print("Go for log")
            res = self.read_from_log(log)
        else:
            print("Go for triggering crash")
            exitcode = self.deploy_linux(linux_commit, config, fixed)
            if exitcode == 1:
                self.logger.info("Error occur at deploy_linux-sh")
                return []
            res = self.trigger_ori_crash(syz_repro, syz_commit, c_repro, i386)
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
        patch_path = "{}/patches".format(self.project_path)
        p = None
        if commit == None and config == None:
            print("run: scripts/deploy_linux.sh {} {}".format(self.linux_path, patch_path))
            p = Popen(["scripts/deploy_linux.sh", str(fixed), self.linux_path, patch_path],
                stdout=PIPE,
                stderr=STDOUT)
        else:
            print("run: scripts/deploy_linux.sh {} {} {} {}".format(self.linux_path, patch_path, commit, config))
            p = Popen(["scripts/deploy_linux.sh", str(fixed), self.linux_path, patch_path, commit, config],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        return exitcode

    def trigger_ori_crash(self, syz_repro, syz_commit, c_repro, i386):
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
                line = line.decode("utf-8").strip('\n').strip('\r')
                if utilities.regx_match(reboot_regx, line):
                    self.case_logger.info("Booting qemu failed")
                print(line)
                if utilities.regx_match(startup_regx, line):
                    repro_type = utilities.CASE
                    if utilities.regx_match(r'https:\/\/syzkaller\.appspot\.com\/', syz_repro):
                        repro_type = utilities.URL
                    utilities.chmodX("scripts/upload-exp.sh")
                    p2 = Popen(["scripts/upload-exp.sh", self.case_path, syz_repro,
                        str(self.ssh_port), self.image_path, syz_commit, str(repro_type), str(c_repro), str(i386)],
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
                    else:
                        with open(syz_repro, "r") as f:
                            text = f.readlines()
                    command = self.make_commands(text, exitcode, i386)
                    utilities.chmodX("scripts/run-script.sh")
                    p3 = Popen(["scripts/run-script.sh", command, str(self.ssh_port), self.image_path, self.case_path],
                    stdout=PIPE,
                    stderr=STDOUT)
                    exitcode = p3.wait()
                    if exitcode == 1:
                        p.kill()
                        break
                    Popen(["ssh", "-p", str(self.ssh_port), "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
                    "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
                    "-o", "ConnectTimeout=10", "-i", "{}/stretch.img.key".format(self.image_path), 
                    "-v", "root@localhost", "chmod +x run.sh && ./run.sh"])
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
        while (count < 10*60):
            count += 1
            time.sleep(1)
            poll = p.poll()
            if poll != None:
                return
        self.case_logger.info('Time out, kill qemu')
        p.kill()
            
    def __match_allocated_section(self, report1 ,report2):
        self.case_logger.info("match allocated section")
        allocation1 = self.__extract_allocated_section(report1)
        allocation2 = self.__extract_allocated_section(report2)
        seq1 = [self.__extract_func_name(x) for x in allocation1 if self.__extract_func_name(x) != None]
        seq2 = [self.__extract_func_name(x) for x in allocation2 if self.__extract_func_name(x) != None]
        counter = 0

        for i in range(0, min(len(seq1), len(seq2))):
            if seq1[i] == seq2[i]:
                counter += 1
            else:
                break
            if counter == 2 or counter == min(len(seq1), len(seq2)):
                return True

        diff = utilities.levenshtein_for_calltrace(seq1, seq2)
        ratio = diff/float(max(len(seq1), len(seq2)))
        self.case_logger.info("diff ratio: {}".format(ratio))
        if ratio > 0.3:
            return False
        return True
    
    def __match_call_trace(self, report1, report2):
        self.case_logger.info("match call trace")
        trace1 = self.__extrace_call_trace(report1)
        trace2 = self.__extrace_call_trace(report2)
        seq1 = [self.__extract_func_name(x) for x in trace1 if self.__extract_func_name(x) != None]
        seq2 = [self.__extract_func_name(x) for x in trace2 if self.__extract_func_name(x) != None]
        counter = 0

        for i in range(0, min(len(seq1), len(seq2))):
            if seq1[i] == seq2[i]:
                counter += 1
            else:
                break
            if counter == 2 or counter == min(len(seq1), len(seq2)):
                return True

        diff = utilities.levenshtein_for_calltrace(seq1, seq2)
        ratio = diff/float(max(len(seq1), len(seq2)))
        self.case_logger.info("diff ratio: {}".format(ratio))
        if ratio > 0.3:
            return False
        return True

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
    parser.add_argument('--fixed-only', action='store_true',
                        help='Reproduce on fixed kernel')
    parser.add_argument('--unfixed-only', action='store_true',
                        help='Reproduce on unfixed kernel')
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

    path = "succeed"
    type = utilities.FOLDER
    if args.input != None:
        path = os.path.join(path, args.input[:7])
        type = utilities.CASE
    for url in utilities.urlsOfCases(path, type):
        if url not in ignore:
            crawler.run_one_case(url)
    
    count = 0
    for hash in crawler.cases:
        print("running case {} [{}/{}]".format(hash, count, len(crawler.cases)))
        project_path = os.getcwd()
        case_path = "{}/work/succeed/{}".format(project_path, hash[:7])
        case = crawler.cases[hash]
        syz_repro = case["syz_repro"]
        syz_commit = case["syzkaller"]
        commit = case["commit"]
        config = case["config"]
        c_repro = case["c_repro"]
        i386 = None
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        log = case["log"]
        logger.info("\nRunning case: {}".format(hash))
        checker = CrashChecker(project_path, case_path, default_port, logger)
        if not args.fixed_only:
            if args.reproduce:
                res = checker.run(syz_repro, syz_commit, None, commit, config, c_repro, i386)
            else:
                res = checker.run(syz_repro, syz_commit, log, commit, config, c_repro, i386)
            checker.logger.info("{}:{}".format(hash, res[0]))
            if res[0]:
                checker.logger.info("successful crash: {}".format(res[1]))
        if not args.unfixed_only:
            commit = crawler.get_patch_commit(hash)
            if commit != None:
                checker.repro_on_fixed_kernel(syz_commit, commit, config, c_repro, i386)
        count += 1
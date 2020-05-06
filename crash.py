import os, re, stat
import logging
import argparse
import utilities
import time
import threading

from subprocess import call, Popen, PIPE, STDOUT
from syzbotCrawler import Crawler

startup_regx = r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'
boundary_reg = r'======================================================'
default_port = 3777

class CrashChecker:
    def __init__(self, project_path, case_path, ssh_port, poc, logger):
        os.makedirs("{}/poc".format(case_path), exist_ok=True)
        self.kasan_regx = r'KASAN: ([a-z\\-]+) Write in ([a-zA-Z0-9_]+).*'
        self.free_regx = r'KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
        self.logger = logger
        self.project_path = project_path
        self.case_path = case_path
        self.image_path = "{}/tools/img".format(self.project_path)
        self.linux_path = "{}/linux".format(self.case_path)
        self.case_logger = self.__init_case_logger("{}-info".format(poc))
        self.ssh_port = ssh_port
        self.poc = poc
        self.kasan_func_list = self.read_kasan_funcs()

    def run(self, commit=None, config=None):
        exitcode = self.deploy_ori_linux(commit, config)
        if exitcode == 1:
            self.logger.info("Error occur at deploy-ori-linux-sh")
            return False
        ori_crash_report = self.read_ori_crash()
        if ori_crash_report == []:
            return False
        crashes_path = self.extract_existed_crash(self.case_path)
        for path in crashes_path:
            new_crash_reports = self.read_existed_crash(path)
            if self.compare_crashes(ori_crash_report, new_crash_reports):
                return True
        return False
    
    def read_kasan_funcs(self):
        res = []
        path = os.path.join(self.project_path, "resources/kasan_related_funcs")
        with open(path, "r") as f:
            lines = f.readlines()
            for line in lines:
                res.append(line.strip('\n'))
            return res

    def compare_crashes(self, ori_crash_report, new_crash_reports):
        for report in new_crash_reports:
            if self.__match_allocated_section(ori_crash_report, report):
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
                            break
                        if utilities.regx_match(self.free_regx, line):
                            res.append(os.path.join(crash_path, case))
                            break
        return res
    
    def read_ori_crash(self):
        res = self.trigger_ori_crash()
        self.save_crash_log(res)
        return res
    
    def read_existed_crash(self, crash_path):
        res = []
        crash = []
        record_flag = 0
        report_path = os.path.join(crash_path, "repro.log")
        if os.path.isfile(report_path):
            with open(report_path, "r") as f:
                lines = f.readlines()
                for line in lines:
                    if utilities.regx_match(boundary_reg, line):
                        record_flag ^= 1
                        crash.append(line)
                        if record_flag == 0:
                            res.append(crash)
                        continue
                    if record_flag:
                        crash.append(line)
        return res

    def save_crash_log(self, log):
        with open("{}/poc/crash_log".format(self.case_path), "w+") as f:
            for line in log:
                f.write(line+"\n")
    
    def deploy_ori_linux(self, commit, config):
        utilities.chmodX("scripts/deploy-ori-linux.sh")
        patch_path = "{}/patches".format(self.project_path)
        p = None
        if commit == None and config == None:
            self.logger.debug("run: scripts/deploy-ori-linux.sh {} {}".format(self.linux_path, patch_path))
            p = Popen(["scripts/deploy-ori-linux.sh", self.linux_path, patch_path],
                stdout=PIPE,
                stderr=STDOUT)
        else:
            self.logger.debug("run: scripts/deploy-ori-linux.sh {} {} {} {}".format(self.linux_path, patch_path, commit, config))
            p = Popen(["scripts/deploy-ori-linux.sh", self.linux_path, patch_path, commit, config],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()

    def trigger_ori_crash(self):
        res = []
        p = Popen(["qemu-system-x86_64", "-m", "2048M", "-smp", "2", "-net", "nic,model=e1000", "-enable-kvm",
                   "-cpu", "host", "-net", "user,host=10.0.2.10,hostfwd=tcp::{}-:22".format(self.ssh_port),
                   "-display", "none", "-serial", "stdio", "-no-reboot", "-hda", "{}/stretch.img".format(self.image_path), 
                   "-kernel", "{}/arch/x86_64/boot/bzImage".format(self.linux_path),
                   "-append", "console=ttyS0 net.ifnames=0 root=/dev/sda"],
                  stdout=PIPE,
                  stderr=STDOUT
                  )
        x = threading.Thread(target=monitor_execution, args=(p,))
        x.start()
        with p.stdout:
            extract_report = False
            record_flag = 0
            for line in iter(p.stdout.readline, b''):
                line = line.decode("utf-8").strip('\n').strip('\r')
                self.case_logger.info(line)
                if utilities.regx_match(startup_regx, line):
                    utilities.chmodX("scripts/upload-exp.sh")
                    p2 = Popen(["scripts/upload-exp.sh", self.case_path, self.poc, str(self.ssh_port), self.image_path],
                    stdout=PIPE,
                    stderr=STDOUT)
                    with p2.stdout:
                        self.__log_subprocess_output(p2.stdout, logging.INFO)
                    if p2.wait() == 1:
                        p.kill()
                        break
                    Popen(["ssh", "-p", str(self.ssh_port), "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
                    "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
                    "-o", "ConnectTimeout=10", "-i", "{}/stretch.id_rsa".format(self.image_path), 
                    "-v", "root@localhost", "chmod +x poc && ./poc"],
                    stdout=PIPE)
                    extract_report = True
                if extract_report:
                    if utilities.regx_match(boundary_reg, line):
                        record_flag ^= 1
                        res.append(line)
                        if record_flag == 0:
                            p.kill()
                            break
                        continue
                    if record_flag:
                        res.append(line)
        return res

    def __match_allocated_section(self, report1 ,report2):
        allocation1 = self.__extract_allocated_section(report1)
        allocation2 = self.__extract_allocated_section(report2)
        counter = 0
        self.case_logger.info("Original report   |   New crash report")
        for i in range(0, min(len(allocation1), len(allocation2))):
            func_name1 = self.__extract_func_name(allocation1[i])
            func_name2 = self.__extract_func_name(allocation2[i])
            self.case_logger.info("{}  |  {}".format(func_name1, func_name2))
            if func_name1 == func_name2:
                counter += 1
                if self.__is_kasan_func(func_name1):
                    counter -= 1
                if counter >= 3 or counter == min(len(allocation1), len(allocation2)):
                    return True
            else:
                return False
        self.logger.info("unlikely: __match_allocated_section")
        return True

    def __is_kasan_func(self, func_name):
        if func_name in self.kasan_func_list:
            return True
        return False
    
    def __extract_allocated_section(self, report):
        res = []
        record_flag = 0
        for line in report:
            if record_flag:
                res.append(line)
            if utilities.regx_match(r'Allocated by task \d+', line):
                record_flag ^= 1
            if utilities.regx_match(r'Freed by task \d+', line):
                record_flag ^= 1
                break
        return res[:-2]

    def __extract_func_name(self, line):
        m = re.search(r'([A-Za-z0-9_.]+)\+0x[0-9a-f]+', line)
        if m != None and len(m.groups()) != 0:
            return m.groups()[0]
    
    def __init_case_logger(self, logger_name):
        handler = logging.FileHandler("{}/poc/log".format(self.case_path))
        format = logging.Formatter('%(message)s')
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.logger.level)
        logger.addHandler(handler)
        return logger
    
    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)

def monitor_execution(p):
    count = 0
    while (count < 5*60):
        time.sleep(1)
        poll = p.poll()
        if poll != None:
            return
    p.kill()

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Determine if the new crashes are from the same root cause of the old one\n'
                                                 'eg. python crash.py -i 7fd1cbe3e1d2b3f0366d5026854ee5754d451405')
    parser.add_argument('-i', '--input', nargs='?', action='store',
                        help='By default it analyze all cases under folder \'succeed\', but you can indicate a specific one.')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = args_parse()
    crawler = Crawler()

    logger = logging.getLogger('crash')
    hdlr = logging.FileHandler('./replay.out')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr) 
    logger.setLevel(logging.INFO)

    path = "succeed"
    type = utilities.FOLDER
    if args.input != None:
        path = os.path.join(path, args.input[:7])
        type = utilities.CASE
    for url in utilities.urlsOfCases(path, type):
        crawler.run_one_case(url)
    
    for hash in crawler.cases:
        project_path = os.getcwd()
        case_path = "{}/work/succeed/{}".format(project_path, hash[:7])
        case = crawler.cases[hash]
        poc_url = case["c_repro"]
        commit = case["commit"]
        config = case["config"]
        logger.info("Running case: {}".format(hash))
        checker = CrashChecker(project_path, case_path, default_port, poc_url, logger)
        checker.logger.info("{}:{}".format(hash, checker.run(commit, config)))
import re
import os, stat, sys
import requests
import shutil
import syzbotCrawler
import logging
import datetime
import utilities

from subprocess import call, Popen, PIPE, STDOUT
from crash import CrashChecker, kasan_regx, free_regx
from utilities import chmodX
from dateutil import parser as time_parser

default_port = 53777
stamp_finish_fuzzing = "FINISH_FUZZING"
stamp_build_syzkaller = "BUILD_SYZKALLER"
stamp_build_kernel = "BUILD_KERNEL"
stamp_reproduce_ori_poc = "REPRO_ORI_POC"

syz_config_template="""
{{ 
        "target": "linux/amd64/{8}",
        "http": "127.0.0.1:{5}",
        "workdir": "{0}/workdir",
        "kernel_obj": "{1}",
        "image": "{2}/stretch.img",
        "sshkey": "{2}/stretch.img.key",
        "syzkaller": "{0}",
        "procs": 8,
        "type": "qemu",
        "testcase": "{0}/workdir/testcase-{4}",
        "analyzer_dir": "{6}",
        "time_limit": "{7}",
        "vm": {{
                "count": 4,
                "kernel": "{1}/arch/x86/boot/bzImage",
                "cpu": 2,
                "mem": 2048
        }},
        "enable_syscalls" : [
            {3}
        ],
        "ignores": [
            "WARNING",
            "INFO",
            "no output"
        ]
}}"""

class Deployer:
    def __init__(self, index, debug=False, force=False, port=default_port, replay='incomplete', linux_index=-1, time=8):
        self.linux_path = "linux"
        self.project_path = ""
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
        if replay == None:
            self.replay = False
            self.catalog = 'incomplete'
        else:
            self.replay = True
            self.catalog = replay
        default_port = port
        if linux_index != -1:
            self.index = linux_index
        self.init_logger(debug)
        self.debug = debug
        self.clone_linux()

    def init_logger(self, debug):
        self.logger = logging.getLogger(__name__+str(self.index))
        handler = logging.StreamHandler(sys.stdout)
        format = logging.Formatter('%(asctime)s Thread {}: %(message)s'.format(self.index))
        handler.setFormatter(format)
        self.logger.addHandler(handler)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
    
    def init_replay_crash(self, hash):
        chmodX("scripts/init-replay.sh")
        self.logger.info("run: scripts/init-replay.sh {} {}".format(self.catalog, hash))
        call(["scripts/init-replay.sh", self.catalog, hash])

    def deploy(self, hash, case):
        self.project_path = os.getcwd()
        self.current_case_path = "{}/work/{}/{}".format(self.project_path, self.catalog, hash[:7])
        self.image_path = "{}/img".format(self.current_case_path)
        self.syzkaller_path = "{}/gopath/src/github.com/google/syzkaller".format(self.current_case_path)
        self.kernel_path = "{}/linux".format(self.current_case_path)
        self.arch = "amd64"
        if utilities.regx_match(r'386', case["manager"]):
            self.arch = "386"
        self.logger.info(hash)

        if self.replay:
            self.init_replay_crash(hash[:7])    
        if self.force or not self.__check_stamp(stamp_finish_fuzzing, hash[:7]):
            write_without_mutating = False
            self.__create_dir_for_case()
            if self.force:
                self.__clean_stamp(stamp_finish_fuzzing, hash[:7])
                self.__clean_stamp(stamp_build_kernel, hash[:7])
                self.__clean_stamp(stamp_build_syzkaller, hash[:7])
            self.crash_checker = CrashChecker(
                self.project_path,
                self.current_case_path,
                3777+self.index,
                self.logger,
                self.debug)
            self.case_logger = self.__init_case_logger("{}-log".format(hash))
            self.case_info_logger = self.__init_case_logger("{}-info".format(hash))
            url = syzbotCrawler.syzbot_host_url + syzbotCrawler.syzbot_bug_base_url + hash
            self.case_info_logger.info(url)
            r = self.__run_delopy_script(hash[:7], case)
            if r != 0:
                self.logger.error("Error occur in deploy.sh")
                self.__save_error(hash)
                return
            i386 = None
            if utilities.regx_match(r'386', case["manager"]):
                i386 = True
            need_fuzzing = False
            title = None
            self.logger.info("Try to triger the OOB/UAF by running original poc")
            if not self.__check_stamp(stamp_reproduce_ori_poc, hash[:7]):
                report = self.crash_checker.read_crash(case["syz_repro"], case["syzkaller"], None, 0, case["c_repro"], i386)
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
                                self.crash_checker.logger.info("OOB/UAF Write without mutating")
                                self.crash_checker.logger.info("Detect read before write")
                                self.logger.info("Write to confirmed success")
                                self.__write_to_sucess(hash)
                                self.__write_to_confirmed_sucess(hash)
                                self.__save_case(hash, 0, case, need_fuzzing, title)
                                break
                self.__create_stamp(stamp_reproduce_ori_poc)
            if not write_without_mutating:
                path = None
                need_fuzzing = True
                self.__write_config(case["syz_repro"], hash[:7])
                exitcode = self.run_syzkaller(hash)
                self.__save_case(hash, exitcode, case, need_fuzzing)
        else:
            self.logger.info("{} has finished".format(hash[:7]))
        return self.index

    def clone_linux(self):
        self.__run_linux_clone_script()

    def run_syzkaller(self, hash):
        self.logger.info("run syzkaller".format(self.index))
        syzkaller = os.path.join(self.syzkaller_path, "bin/syz-manager")
        exitcode = 0
        # First round, we only enable limited syscalls.
        # If failed to trigger a write crash, we enable more syscalls to run it again
        if self.logger.level == logging.DEBUG:
            p = Popen([syzkaller, "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash[:7]), "--debug", "--poc"],
                  stdout=PIPE,
                  stderr=STDOUT
                  )
            with p.stdout:
                self.__log_subprocess_output(p.stdout, logging.INFO)
            exitcode = p.wait()

            if not self.__success_check(hash[:7]):
                p = Popen([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash[:7]), "--debug"],
                  stdout=PIPE,
                  stderr=STDOUT
                  )
                with p.stdout:
                    self.__log_subprocess_output(p.stdout, logging.INFO)
                exitcode = p.wait()
        else:
            p = Popen([syzkaller, "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash[:7]), "--poc"],
                stdout = PIPE,
                stderr = STDOUT
                )
            with p.stdout:
                self.__log_subprocess_output(p.stdout, logging.INFO)
            exitcode = p.wait()

            if not self.__success_check(hash[:7]):
                p = Popen([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash[:7])],
                    stdout = PIPE,
                    stderr = STDOUT
                    )
                with p.stdout:
                    self.__log_subprocess_output(p.stdout, logging.INFO)
                exitcode = p.wait()
        self.logger.info("syzkaller is done with exitcode {}".format(exitcode))
        return exitcode
    
    def confirmSuccess(self, hash, case):
        syz_repro = case["syz_repro"]
        syz_commit = case["syzkaller"]
        commit = case["commit"]
        config = case["config"]
        c_repro = case["c_repro"]
        i386 = None
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        log = case["log"]
        path = None
        if not self.__check_confirmed(hash):
            self.logger.info("Compare with original PoC")
            res = self.crash_checker.run(syz_repro, syz_commit, log, commit, config, c_repro, i386)
            if res[0]:
                n = self.crash_checker.diff_testcase(res[1], syz_repro)
                self.crash_checker.logger.info("difference of characters of two testcase: {}".format(n))
                self.crash_checker.logger.info("successful crash: {}".format(res[1]))
                read_before_write = self.crash_checker.check_read_before_write(res[1])
                if read_before_write:
                    self.crash_checker.logger.info("Detect read before write")
                self.logger.info("Write to confirmedSuccess")
                self.__write_to_confirmed_sucess(hash)
                path = res[1]
            else:
                self.crash_checker.logger.info("Call trace match failed")
            
            res = self.repro_on_fixed_kernel(hash, case)
            """
            if res != []:
                self.logger.info("Write to confirmedSuccess")
                self.__write_to_confirmed_sucess(hash)
            """
            return path
        return None
    
    def repro_on_fixed_kernel(self, hash, case):
        syz_repro = case["syz_repro"]
        syz_commit = case["syzkaller"]
        commit = case["commit"]
        config = case["config"]
        c_repro = case["c_repro"]
        i386 = None
        res = []
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        commit = utilities.get_patch_commit(hash)
        if commit != None:
            res = self.crash_checker.repro_on_fixed_kernel(syz_commit, commit, config, c_repro, i386)
        return res

    def __check_confirmed(self, hash):
        return False

    def __write_to_confirmed_sucess(self, hash):
        with open("{}/work/confirmedSuccess".format(self.project_path), "a+") as f:
            f.write(hash[:7]+"\n")
    
    def __write_to_sucess(self, hash):
        with open("{}/work/success".format(self.project_path), "a+") as f:
            f.write(hash[:7]+"\n")

    def __run_linux_clone_script(self):
        chmodX("scripts/linux-clone.sh")
        index = str(self.index)
        self.logger.info("run: scripts/linux-clone.sh {} {}".format(self.index, self.linux_path, index))
        call(["scripts/linux-clone.sh", self.linux_path, index])

    def __run_delopy_script(self, hash, case):
        commit = case["commit"]
        syzkaller = case["syzkaller"]
        config = case["config"]
        testcase = case["syz_repro"]
        time = case["time"]
        self.case_info_logger.info("\ncommit: {}\nsyzkaller: {}\nconfig: {}\ntestcase: {}\ntime: {}\narch: {}".format(commit,syzkaller,config,testcase,time,self.arch))

        if self.__check_using_flag(self.kernel_path):
            return 1
        case_time = time_parser.parse(time)
        if self.image_switching_date <= case_time:
            image = "stretch"
        else:
            image = "wheezy"
        chmodX("scripts/deploy.sh")
        index = str(self.index)
        self.logger.info("run: scripts/deploy.sh".format(self.index))
        p = Popen(["scripts/deploy.sh", self.linux_path, hash, commit, syzkaller, config, testcase, index, self.catalog, image, self.arch],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def __check_using_flag(self, path):
        flag_path = "{}/THIS_KERNEL_HAS_BEEN_USED".format(path)
        if os.path.isfile(flag_path):
            self.logger.error("THIS_KERNEL_HAS_BEEN_USED is detected, check if anything wrong, this happen at when two cases are using the same linue repo.")
            return True
        return False

    def __write_config(self, testcase_url, hash):
        dependent_syscalls = []
        req = requests.request(method='GET', url=testcase_url)
        testcase = req.content
        syscalls = self.__extract_syscalls(testcase.decode("utf-8"))
        if syscalls == []:
            self.logger.info("No syscalls found in testcase: {}".format(self.index, testcase))
            return -1
        for each in syscalls:
            dependent_syscalls.extend(self.__extract_dependent_syscalls(each, self.syzkaller_path))
        if len(dependent_syscalls) < 1:
            self.logger.info("Cannot find dependent syscalls for {}.\nTry to continue without them".format(self.index))
        new_syscalls = syscalls.copy()
        new_syscalls.extend(dependent_syscalls)
        new_syscalls = utilities.unique(new_syscalls)
        enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""
        syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash, default_port+self.index, self.current_case_path, self.time_limit, self.arch)
        f = open(os.path.join(self.syzkaller_path, "workdir/{}-poc.cfg".format(hash)), "w")
        f.writelines(syz_config)
        f.close()

        #Add more syscalls
        new_added_syscalls = []
        for i in range(0, min(2,len(syscalls))):
            if syscalls[len(syscalls)-1-i] not in new_added_syscalls:
                new_added_syscalls.extend(self.__extract_all_syscalls(syscalls[len(syscalls)-1-i], self.syzkaller_path))
        raw_syscalls = self.__extract_raw_syscall(new_added_syscalls)
        new_syscalls = syscalls.copy()
        new_syscalls.extend(raw_syscalls)
        new_syscalls = utilities.unique(new_syscalls)
        enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""
        syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash, default_port+self.index, self.current_case_path, self.time_limit, self.arch)
        f = open(os.path.join(self.syzkaller_path, "workdir/{}.cfg".format(hash)), "w")
        f.writelines(syz_config)
        f.close()

    def __extract_syscalls(self, testcase):
        res = []
        text = testcase.split('\n')
        for line in text:
            if len(line)==0 or line[0] == '#':
                continue
            m = re.search(r'(\w+(\$\w+)?)\(', line)
            if m == None or len(m.groups()) == 0:
                self.logger.info("Failed to extract syscall from {}".format(self.index, line))
                return res
            syscall = m.groups()[0]
            res.append(syscall)
        return res

    def __extract_dependent_syscalls(self, syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
        res = []
        dir = os.path.join(syzkaller_path, search_path)
        if not os.path.isdir(dir):
            self.logger.info("{} do not exist".format(self.index, dir))
            return res
        for file in os.listdir(dir):
            if file.endswith(extension):
                find_it = False
                f = open(os.path.join(dir, file), "r")
                text = f.readlines()
                f.close()
                line_index = 0
                for line in text:
                    if line.find(syscall) != -1:
                        find_it = True
                        break
                    line_index += 1

                if find_it:
                    upper_bound = 0
                    lower_bound = 0
                    for i in range(0, len(text)):
                        if line_index+i<len(text):
                            line = text[line_index+i]
                            if utilities.regx_match(r'^\n', line):
                                upper_bound = 1
                            if upper_bound == 0:
                                m = re.match(r'(\w+(\$\w+)?)\(', line)
                                if m != None and len(m.groups()) > 0:
                                    call = m.groups()[0]
                                    res.append(call)
                        else:
                            upper_bound = 1

                        if line_index-i>=0:
                            line = text[line_index-i]
                            if utilities.regx_match(r'^\n', line):
                                lower_bound = 1
                            if lower_bound == 0:
                                m = re.match(r'(\w+(\$\w+)?)\(', line)
                                if m != None and len(m.groups()) > 0:
                                    call = m.groups()[0]
                                    res.append(call)
                        else:
                            lower_bound = 1

                        if upper_bound and lower_bound:
                            return res
        return res
        
    def __extract_all_syscalls(self, last_syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
        res = []
        dir = os.path.join(syzkaller_path, search_path)
        if not os.path.isdir(dir):
            self.logger.info("{} do not exist".format(self.index, dir))
            return res
        for file in os.listdir(dir):
            if file.endswith(extension):
                find_it = False
                f = open(os.path.join(dir, file), "r")
                text = f.readlines()
                f.close()
                for line in text:
                    if line.find(last_syscall) != -1:
                        find_it = True
                        break

                if find_it:
                    for line in text:
                        m = re.match(r'(\w+(\$\w+)?)\(', line)
                        if m == None or len(m.groups()) == 0:
                            continue
                        syscall = m.groups()[0]
                        res.append(syscall)
                    break
        return res
    
    def __extract_raw_syscall(self, syscalls):
        res = []
        for call in syscalls:
            m = re.match(r'((\w+)(\$\w+)?)', call)
            if m == None or len(m.groups()) == 0:
                continue
            syscall = m.groups()[1]
            if syscall not in res:
                res.append(syscall)
        return res

    def __save_case(self, hash, exitcode, case, need_fuzzing, title=None):
        if exitcode !=0:
            self.__save_error(hash)
        else:
            self.__copy_crashes(need_fuzzing)
            self.__create_stamp(stamp_finish_fuzzing)
            if self.__success_check(hash[:7]):
                if need_fuzzing:
                    path = self.confirmSuccess(hash, case)
                    if path != None:
                        self.__copy_new_capability(path, need_fuzzing, title)
                        self.__move_to_succeed()
                    else:
                        self.__move_to_completed()
                else:
                    self.__copy_new_capability(case, need_fuzzing, title)
                    self.__move_to_succeed()
            else:
                self.__move_to_completed()
    
    def __copy_new_capability(self, path, need_fuzzing, title):
        output = os.path.join(self.current_case_path, "output")
        os.makedirs(output, exist_ok=True)
        if not need_fuzzing:
            case = path
            if case['syz_repro'] != None:
                r = utilities.request_get(case['syz_repro'])
                with open(os.path.join(output, "repro.prog"), "w") as f:
                    f.write(r.text)
            if case['c_repro'] != None:
                r = utilities.request_get(case['c_repro'])
                with open(os.path.join(output, "repro.cprog"), "w") as f:
                    f.write(r.text)
            crash_log = "{}/{}".format(self.current_case_path, "poc/crash_log")
            if os.path.isfile(crash_log):
                shutil.copy(crash_log, os.path.join(output, "repro.log"))
            with open(os.path.join(output, "description"), "w") as f:
                    f.write(title)
        else:
            if path == None:
                self.logger.error("Error: crash path is None")
                return
            src_files = os.listdir(path)
            for file_name in src_files:
                full_file_name = os.path.join(path, file_name)
                if os.path.isfile(full_file_name):
                    shutil.copy(full_file_name, output)


    def __save_error(self, hash):
        self.logger.info("case {} encounter an error. See log for details.".format(hash))
        self.__move_to_error()

    def __copy_crashes(self, need_fuzzing):
        crash_path = "{}/workdir/crashes".format(self.syzkaller_path)
        dest_path = "{}/crashes".format(self.current_case_path)
        i = 0
        if os.path.isdir(crash_path) and len(os.listdir(crash_path)) > 0:
            while(1):
                try:
                    shutil.copytree(crash_path, dest_path)
                    self.logger.info("Found crashes, copy them to {}".format(dest_path))
                    break
                except FileExistsError:
                    dest_path = "{}/crashes-{}".format(self.current_case_path, i)
                    i += 1
        else:
            if need_fuzzing:
                self.logger.info("No crashes found in syzkaller")

    def __move_to_completed(self):
        self.logger.info("Copy to completed")
        src = self.current_case_path
        base = os.path.basename(src)
        completed = "{}/work/completed".format(self.project_path)
        des = "{}/{}".format(completed, base)
        if not os.path.isdir(completed):
            os.makedirs(completed, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des
    
    def __move_to_succeed(self):
        self.logger.info("Copy to succeed")
        src = self.current_case_path
        base = os.path.basename(src)
        succeed = "{}/work/succeed".format(self.project_path)
        des = "{}/{}".format(succeed, base)
        if not os.path.isdir(succeed):
            os.makedirs(succeed, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des
    
    def __move_to_error(self):
        self.logger.info("Copy to error")
        src = self.current_case_path
        base = os.path.basename(src)
        error = "{}/work/error".format(self.project_path)
        des = "{}/{}".format(error, base)
        if not os.path.isdir(error):
            os.makedirs(error, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            os.rmdir(des)
        shutil.move(src, des)
        self.current_case_path = des

    def __create_stamp(self, name):
        self.logger.info("Create stamp {}".format(name))
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        call(['touch',stamp_path])
    
    def __check_stamp(self, name, hash):
        stamp_path1 = "{}/work/completed/{}/.stamp/{}".format(self.project_path, hash, name)
        stamp_path2 = "{}/work/succeed/{}/.stamp/{}".format(self.project_path, hash, name)
        return os.path.isfile(stamp_path1) or os.path.isfile(stamp_path2)
    
    def __clean_stamp(self, name, hash):
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        if os.path.isfile(stamp_path):
            os.remove(stamp_path)

    def __create_dir_for_case(self):
        if self.__copy_from_duplicated_cases():
            return
        path = "{}/.stamp".format(self.current_case_path)
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)

    def __copy_from_duplicated_cases(self):
        des = self.current_case_path
        base = os.path.basename(des)
        for dirs in ["completed", "incomplete", "error", "succeed"]:
            src = "{}/work/{}/{}".format(self.project_path, dirs, base)
            if src == des:
                continue
            if os.path.isdir(src):
                try:
                    shutil.move(src, des)
                    self.logger.info("Found duplicated case in {}".format(src))
                    return True
                except:
                    self.logger.info("Fail to copy the duplicated case from {}".format(src))
        return False
    
    def __get_default_log_format(self):
        return logging.Formatter('%(asctime)s %(levelname)s [{}] %(message)s'.format(self.index))

    def __init_case_logger(self, logger_name):
        handler = logging.FileHandler("{}/log".format(self.current_case_path))
        format = logging.Formatter('[{}] %(message)s'.format(self.index))
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.logger.level)
        logger.addHandler(handler)
        return logger
    
    def __init_case_info_logger(self, logger_name):
        handler = logging.FileHandler("{}/info".format(self.current_case_path))
        format = self.__get_default_log_format()
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

    def __success_check(self, hash):
        success_path = "{}/work/success".format(self.project_path)
        if os.path.isfile(success_path):
            f = open(success_path, "r")
            text = f.readlines()
            f.close()
            for line in text:
                line = line.strip('\n')
                if line == hash:
                    return True
        return False
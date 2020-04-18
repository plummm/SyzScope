import re
import os, stat, sys
import requests
import shutil
import syzbotCrawler
import logging

from subprocess import call, Popen, PIPE, STDOUT

default_port = 56745
stamp_finish_fuzzing = "FINISH_FUZZING"

syz_config_template="""
{{ 
        "target": "linux/amd64",
        \"http\": \"127.0.0.1:{5}\",
        \"workdir\": \"{0}/workdir\",
        \"kernel_obj\": \"{1}\",
        \"image\": \"{2}/stretch.img\",
        \"sshkey\": \"{2}/stretch.id_rsa\",
        \"syzkaller\": \"{0}\",
        \"procs\": 8,
        \"type\": \"qemu\",
        \"testcase\": \"{0}/workdir/testcase-{4}\",
        \"analyzer_dir\": \"{6}",
        \"vm\": {{
                \"count\": 4,
                \"kernel\": \"{1}/arch/x86/boot/bzImage\",
                \"cpu\": 2,
                \"mem\": 2048
        }},
        \"enable_syscalls\" : [
            {3}
        ]
}}"""

class Deployer:
    def __init__(self, index, debug=False):
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
        self.init_logger(debug)
        self.clone_linux()

    def init_logger(self, debug):
        self.logger = logging.getLogger(__name__+str(self.index))
        handler = logging.StreamHandler(sys.stdout)
        format = logging.Formatter('Thread {}: %(message)s'.format(self.index, ))
        handler.setFormatter(format)
        self.logger.addHandler(handler)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

    def deploy(self, hash, case):
        self.project_path = os.getcwd()
        self.image_path = "{}/tools/img".format(self.project_path)
        self.current_case_path = "{}/work/incomplete/{}".format(self.project_path, hash[:7])
        self.syzkaller_path = "{}/gopath/src/github.com/google/syzkaller".format(self.current_case_path)
        self.kernel_path = "{}/linux".format(self.current_case_path)
        self.__create_dir_for_case()
        self.case_logger = self.__init_case_logger("{}-log".format(hash))
        self.case_info_logger = self.__init_case_logger("{}-info".format(hash))
        self.logger.info(hash)

        if not self.__check_stamp(stamp_finish_fuzzing, hash[:7]):
            r = self.__run_delopy_script(hash[:7], case)
            if r == 1:
                self.logger.error("Error occur in deploy.sh")
                return
            self.__write_config(case["syz_repro"], hash[:7])
            self.run_syzkaller(hash)
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
        self.logger.info("syzkaller is done with exitcode {}".format(self.index, exitcode))
        self.__save_case(hash)

    def __run_linux_clone_script(self):
        st = os.stat("scripts/linux-clone.sh")
        os.chmod("scripts/linux-clone.sh", st.st_mode | stat.S_IEXEC)
        index = str(self.index)
        self.logger.info("run: scripts/linux-clone.sh {} {}".format(self.index, self.linux_path, index))
        call(["scripts/linux-clone.sh", self.linux_path, index])

    def __run_delopy_script(self, hash, case):
        commit = case["commit"]
        syzkaller = case["syzkaller"]
        config = case["config"]
        testcase = case["syz_repro"]
        self.case_info_logger.info("\ncommit: {}\nsyzkaller: {}\nconfig: {}\ntestcase: {}".format(commit,syzkaller,config,testcase))

        st = os.stat("scripts/deploy.sh")
        os.chmod("scripts/deploy.sh", st.st_mode | stat.S_IEXEC)
        index = str(self.index)
        self.logger.info("run: scripts/deploy.sh".format(self.index))
        p = Popen(["scripts/deploy.sh", self.linux_path, hash, commit, syzkaller, config, testcase, index],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh from thread {0} is done with exitcode {1}".format(index, exitcode))
        return exitcode

    def __write_config(self, testcase_url, hash):
        req = requests.request(method='GET', url=testcase_url)
        testcase = req.content
        syscalls = self.__extract_syscalls(testcase.decode("utf-8"))
        if syscalls == []:
            self.logger.info("No syscalls found in testcase: {}".format(self.index, testcase))
            return -1
        last_syscall = syscalls[len(syscalls)-1]
        dependent_syscalls = self.__extract_dependent_syscalls(last_syscall, self.syzkaller_path)
        if len(dependent_syscalls) < 1:
            self.logger.info("Cannot find dependent syscalls for {}.\nTry to continue without them".format(self.index, last_syscall))
        new_syscalls = syscalls
        new_syscalls.extend(dependent_syscalls)
        enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""
        syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash, default_port+self.index, self.current_case_path)
        f = open(os.path.join(self.syzkaller_path, "workdir/{}-poc.cfg".format(hash)), "w")
        f.writelines(syz_config)
        f.close()

        #Add more syscalls
        new_dependent_syscalls = []
        for i in range(0, len(syscalls)-2):
            if syscalls[len(syscalls)-2-i] not in dependent_syscalls:
                new_dependent_syscalls = self.__extract_dependent_syscalls(syscalls[len(syscalls)-2-i], self.syzkaller_path)
                break
        raw_syscalls = self.__extract_raw_syscall(dependent_syscalls)
        raw_syscalls.extend(self.__extract_raw_syscall(new_dependent_syscalls))
        #syzkaller would help remove the duplicates
        syscalls.extend(raw_syscalls)
        enable_syscalls = "\"" + "\",\n\t\"".join(syscalls) + "\""
        syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash, default_port+self.index, self.current_case_path)
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

    def __extract_dependent_syscalls(self, last_syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
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

    def __save_case(self, hash):
        self.__copy_crashes()
        url = syzbotCrawler.syzbot_host_url + syzbotCrawler.syzbot_bug_base_url + hash
        self.case_info_logger.info(url)
        self.__create_stamp(stamp_finish_fuzzing)
        self.__move_to_completed()

    def __copy_crashes(self):
        crash_path = "{}/workdir/crashes".format(self.syzkaller_path)
        dest_path = "{}/crashes".format(self.current_case_path)
        i = 0
        if os.path.isdir(crash_path):
            while(1):
                try:
                    shutil.copytree(crash_path, dest_path)
                    self.logger.info("Found crashes, copy them to {}".format(dest_path))
                    break
                except FileExistsError:
                    dest_path = "{}/crashes-{}".format(self.current_case_path, i)
                    i += 1
        else:
            self.logger.info("No crashes found")

    def __move_to_completed(self):
        self.logger.info("Copy to completed")
        src = self.current_case_path
        base = os.path.basename(src)
        des = "{}/work/completed/{}".format(self.project_path, base)
        shutil.move(src, des)

    def __create_stamp(self, name):
        self.logger.info("Create stamp {}".format(self.index, name))
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        call(['touch',stamp_path])
    
    def __check_stamp(self, name, hash):
        stamp_path = "{}/work/completed/{}/.stamp/{}".format(self.project_path, hash, name)
        return os.path.isfile(stamp_path)

    def __create_dir_for_case(self):
        if not os.path.isdir(self.current_case_path):
            os.makedirs("{}/.stamp".format(self.current_case_path), exist_ok=True)
    
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
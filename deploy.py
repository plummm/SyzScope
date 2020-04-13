import re
import os, stat
import requests
import shutil
import syzbotCrawler
import logging

from subprocess import Popen, PIPE, STDOUT

syz_config_template="""
{{ 
        "target": "linux/amd64",
        \"http\": \"127.0.0.1:56745\",
        \"workdir\": \"{0}/workdir\",
        \"kernel_obj\": \"{1}\",
        \"image\": \"{2}/stretch.img\",
        \"sshkey\": \"{2}/stretch.id_rsa\",
        \"syzkaller\": \"{0}\",
        \"procs\": 8,
        \"type\": \"qemu\",
        \"testcase\": \"{0}/workdir/testcase-{4}\",
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
        #self.clone_linux()
        self.case_logger = None
        self.logger = None
        self.success_logger = None
        self.case_info_logger = None
        self.init_logger(debug)

    def init_logger(self, debug):
        self.logger = logging.getLogger(__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        self.case_info_logger = self.__init_case_logger("{}-info".format(hash), "info")
        self.success_logger = self.__init_success_logger()

    def deploy(self, hash, case):
        self.project_path = os.getcwd()
        self.syzkaller_path = "{}/tools/gopath/src/github.com/google/syzkaller".format(self.project_path)
        self.image_path = "{}/tools/img".format(self.project_path)
        self.current_case_path = "{}/work/{}".format(self.project_path, hash[:7])
        self.kernel_path = "{}/linux-{}".format(self.current_case_path, self.index)
        self.__create_dir_for_case()
        self.case_logger = self.__init_case_logger("{}-log".format(hash), "log")
        r = self.__run_delopy_script(hash[:7], case)
        if r == 1:
            self.logger.error("Error occur in deploy.sh")
            return
        self.__write_config(case["syz_repro"], hash[:7])
        self.run_syzkaller(hash)
        return self.index

    def clone_linux(self):
        self.__run_linux_clone_script()

    def run_syzkaller(self, hash):
        syzkaller = os.path.join(self.syzkaller_path, "bin/syz-manager")
        if self.logger.level == logging.DEBUG:
            p = Popen([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash[:7]), "--debug"],
                  stdout=PIPE,
                  stderr=STDOUT
                  )
            with p.stdout:
                self.__log_subprocess_output(p.stdout)
            p.wait()
        else:
            p = Popen([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash[:7])],
                stdout = PIPE,
                stderr = STDOUT
                )
            with p.stdout:
                self.__log_subprocess_output(p.stdout)
            p.wait()
        self.__save_case(hash)
        self.__clean_stamps()

    def __run_linux_clone_script(self):
        st = os.stat("scripts/linux-clone.sh")
        os.chmod("scripts/linux-clone.sh", st.st_mode | stat.S_IEXEC)
        print("run: scripts/linux-clone.sh {}".format(self.linux_path))
        Popen(["scripts/linux-clone.sh", self.linux_path, self.index])

    def __run_delopy_script(self, hash, case):
        commit = case["commit"]
        syzkaller = case["syzkaller"]
        config = case["config"]
        testcase = case["syz_repro"]
        self.case_info_logger.debug("commit: {}\nsyzkaller: {}\nconfig: {}\ntestcase: {}".format(commit,syzkaller,config,testcase))

        st = os.stat("scripts/deploy.sh")
        os.chmod("scripts/deploy.sh", st.st_mode | stat.S_IEXEC)
        self.logger.info("run: scripts/deploy.sh {0} {1} {2} {3} {4} {5}".format(self.linux_path, hash, commit, syzkaller, config, testcase))
        p = Popen(["scripts/deploy.sh", self.linux_path, hash, commit, syzkaller, config, testcase, self.index],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout)
        exitcode = p.wait()
        return exitcode

    def __write_config(self, testcase_url, hash):
        req = requests.request(method='GET', url=testcase_url)
        testcase = req.content
        syscalls = self.__extract_syscalls(testcase.decode("utf-8"))
        if syscalls == []:
            print("No syscalls found in testcase: {}".format(testcase))
            return -1
        last_syscall = syscalls[len(syscalls)-1]
        dependent_syscalls = self.__extract_dependent_syscalls(last_syscall, self.syzkaller_path)
        if len(dependent_syscalls) < 1:
            print("Cannot find dependent syscalls for {}.\nTry to continue without them".format(last_syscall))
        syscalls.extend(dependent_syscalls)
        enable_syscalls = "\"" + "\",\n\t\"".join(syscalls) + "\""
        syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash)
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
                print("Failed to extract syscall from {}".format(line))
                return res
            syscall = m.groups()[0]
            res.append(syscall)
        return res

    def __extract_dependent_syscalls(self, last_syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
        res = []
        dir = os.path.join(syzkaller_path, search_path)
        if not os.path.isdir(dir):
            print("{} do not exist".format(dir))
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

    def __save_case(self, hash):
        self.__copy_crashes()
        url = syzbotCrawler.syzbot_host_url + syzbotCrawler.syzbot_bug_base_url + hash
        self.case_info_logger.info(url)
        self.success_logger.info(hash+"\n")

    def __copy_crashes(self):
        crash_path = "{}/workdir/crashes".format(self.syzkaller_path)
        dest_path = "{}/crashes".format(self.current_case_path)
        if os.path.isdir(crash_path):
            self.case_logger.info("Found crashes, copy them to {}".format(dest_path))
            shutil.copytree(crash_path, dest_path)

    def __clean_stamps(self):
        os.remove("{}/tools/.stamp/BUILD_KERNEL".format(self.project_path))
        os.remove("{}/tools/.stamp/BUILD_SYZKALLER".format(self.project_path))

    def __create_dir_for_case(self):
        if not os.path.isdir(self.current_case_path):
            os.makedirs(self.current_case_path, exist_ok=True)

    def __init_case_logger(self, logger_name, file_name):
        handler = logging.FileHandler("{}/{}".format(self.current_case_path, file_name))
        format = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        return logger

    def __init_success_logger(self):
        handler = logging.FileHandler("{}/work/success".format(self.project_path))
        format = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(format)
        logger = logging.getLogger("success")
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        return logger

    def __log_subprocess_output(self, pipe):
        for line in iter(pipe.readline, b''):
            self.case_logger.info(line)

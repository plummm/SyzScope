import re
import os, stat
import requests

from subprocess import call

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
    def __init__(self):
        self.linux_path = "linux"
        self.syzkaller_path = ""
        self.image_path = ""
        self.kernel_path = ""
        self.clone_linux()

    def deploy(self, cases):
        for hash in cases:
            case = cases[hash]
            hash = hash[:7]
            r = self.__run_delopy_script(hash, case)
            if r == 1:
                print("Error occur in deploy.sh")
                return
            self.syzkaller_path = "{}/tools/gopath/src/github.com/google/syzkaller".format(os.getcwd())
            self.image_path = "{}/tools/img".format(os.getcwd())
            self.kernel_path = "{}/work/{}/linux".format(os.getcwd(), hash)
            self.__write_config(case["syz_repro"], hash)
            self.run_syzkaller(hash)

    def clone_linux(self):
        self.__run_linux_clone_script()

    def run_syzkaller(self, hash, debug=False):
        syzkaller = os.path.join(self.syzkaller_path, "bin/syz-manager")
        if debug:
            call([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash), "--debug"])
        else:
            call([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash)])
        self.__clean_stamps()

    def __run_linux_clone_script(self):
        st = os.stat("scripts/linux-clone.sh")
        os.chmod("scripts/linux-clone.sh", st.st_mode | stat.S_IEXEC)
        print("run: scripts/linux-clone.sh {}".format(self.linux_path))
        call(["scripts/linux-clone.sh", self.linux_path], shell=False)

    def __run_delopy_script(self, hash, case):
        commit = case["commit"]
        syzkaller = case["syzkaller"]
        config = case["config"]
        testcase = case["syz_repro"]

        st = os.stat("scripts/deploy.sh")
        os.chmod("scripts/deploy.sh", st.st_mode | stat.S_IEXEC)
        print("run: scripts/deploy.sh {0} {1} {2} {3} {4} {5}".format(self.linux_path, hash, commit, syzkaller, config, testcase))
        return call(["scripts/deploy.sh", self.linux_path, hash, commit, syzkaller, config, testcase], shell=False)

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

    def __clean_stamps(self):
        os.remove("{}/tools/.stamp/BUILD_KERNEL".format(os.getcwd()))
        os.remove("{}/tools/.stamp/BUILD_SYZKALLER".format(os.getcwd()))
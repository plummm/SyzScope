from subprocess import call

class Deployer:
    def __init__(self):
        self.linux_path = "linux"
        self.clone_linux()

    def deploy(self, cases):
        for hash in cases:
            case = cases[hash]
            self.__run_delopy_script(hash, case)

    def clone_linux(self):
        self.__run_linux_clone_script()

    def __run_linux_clone_script(self):
        call(["scripts/linux-clone.sh", self.linux_path], shell=True)

    def __run_delopy_script(self, hash, case):
        commit = case["commit"]
        syzkaller = case["syzkaller"]
        config = case["config"]
        syz_repro = case["syz_repro"]
        call(["scripts/deploy.sh", self.linux_path, hash, commit, syzkaller, config, syz_repro], shell=True)



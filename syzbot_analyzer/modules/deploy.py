import re
import os, stat, sys
import requests
import shutil
import logging
import datetime
import syzbot_analyzer.interface.utilities as utilities

from .syzbotCrawler import syzbot_host_url, syzbot_bug_base_url
from syzbot_analyzer.interface import s2e, static_analysis, sym_exec
from subprocess import call, Popen, PIPE, STDOUT
from .crash import CrashChecker, kasan_regx, free_regx
from syzbot_analyzer.interface.utilities import chmodX
from dateutil import parser as time_parser

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
        ]
}}"""

class Deployer:
    def __init__(self, index, debug=False, force=False, port=53777, replay='incomplete', linux_index=-1, time=8, force_fuzz=False, alert=[], static_analysis=False):
        self.linux_folder = "linux"
        self.project_path = ""
        self.package_path = None
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
        #self.crash_checker = None
        self.image_switching_date = datetime.datetime(2020, 3, 15)
        self.arch = None
        self.compiler = None
        self.force_fuzz = force_fuzz
        self.alert = alert
        self.static_analysis = static_analysis
        if replay == None:
            self.replay = False
            self.catalog = 'incomplete'
        else:
            self.replay = True
            self.catalog = replay
        self.default_port = port
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
    
    def init_replay_crash(self, hash_val):
        chmodX("syzbot_analyzer/scripts/init-replay.sh")
        self.logger.info("run: scripts/init-replay.sh {} {}".format(self.catalog, hash_val))
        call(["syzbot_analyzer/scripts/init-replay.sh", self.catalog, hash_val])

    def deploy(self, hash_val, case):
        self.project_path = os.getcwd()
        self.package_path = os.path.join(self.project_path, "syzbot_analyzer")
        self.current_case_path = "{}/work/{}/{}".format(self.project_path, self.catalog, hash_val[:7])
        self.image_path = "{}/img".format(self.current_case_path)
        self.syzkaller_path = "{}/gopath/src/github.com/google/syzkaller".format(self.current_case_path)
        self.kernel_path = "{}/linux".format(self.current_case_path)
        self.arch = "amd64"
        if utilities.regx_match(r'386', case["manager"]):
            self.arch = "386"
        self.logger.info(hash_val)

        if self.replay:
            self.init_replay_crash(hash_val[:7])    
        if self.force or \
            (not self.__check_stamp(stamp_finish_fuzzing, hash_val[:7], 'succeed')  and\
            not self.__check_stamp(stamp_finish_fuzzing, hash_val[:7], 'completed')):
            self.compiler = utilities.set_compiler_version(time_parser.parse(case["time"]), case["config"])
            write_without_mutating = False
            self.__create_dir_for_case()
            if self.force:
                self.__clean_stamp(stamp_finish_fuzzing, hash_val[:7])
                self.__clean_stamp(stamp_build_kernel, hash_val[:7])
                self.__clean_stamp(stamp_build_syzkaller, hash_val[:7])
            self.case_logger = self.__init_case_logger("{}-log".format(hash_val))
            self.case_info_logger = self.__init_case_logger("{}-info".format(hash_val))
            url = syzbot_host_url + syzbot_bug_base_url + hash_val
            self.case_info_logger.info(url)

            if (self.static_analysis):
                sa = static_analysis.StaticAnalysis(self.case_logger, self.project_path, self.current_case_path)
                r = utilities.request_get(case['report'])
                vul_site, func_site, func, offset = sa.KasanVulnChecker(r.text)
                r = sa.prepare_static_analysis(case, vul_site, func_site)
                if r != 0:
                    self.logger.error("Error occur in deploy-bc.sh")
                self.run_static_analysis(vul_site, func_site, func, offset)
            need_patch = 0
            if self.__need_kasan_patch(case['title']):
                need_patch = 1
            r = self.__run_delopy_script(hash_val[:7], case, need_patch)
            if r != 0:
                self.logger.error("Error occur in deploy.sh")
                self.__save_error(hash_val)
                return
            self.case_info_logger.info("compiler: "+self.compiler)
            self.crash_checker = CrashChecker(
                self.project_path,
                self.current_case_path,
                3777,
                self.logger,
                self.debug,
                self.index,
                compiler=self.compiler)
            i386 = None
            if utilities.regx_match(r'386', case["manager"]):
                i386 = True
            need_fuzzing = False
            title = None
            self.logger.info("Try to triger the OOB/UAF by running original poc")
            if not self.__check_stamp(stamp_reproduce_ori_poc, hash_val[:7], 'incomplete'):
                report, trigger = self.crash_checker.read_crash(case["syz_repro"], case["syzkaller"], None, 0, case["c_repro"], i386)
                write_without_mutating, title = self.KasanWriteChecker(report, hash_val)
                self.__create_stamp(stamp_reproduce_ori_poc)
            ### DEBUG SYMEXEC ###
            sym = sym_exec.SymExec(debug=self.debug)
            linux_path = os.path.join(self.current_case_path, self.linux_folder)
            sym.setup_vm(linux_path, 2778, self.image_path, 1235, proj_path=self.current_case_path)
            sym.run_vm()
            ok, output = self.crash_checker.upload_exp(case["syz_repro"], 2778, case["syzkaller"], utilities.URL, case["c_repro"], i386, 0)
            self.crash_checker.run_exp(case["syz_repro"], 2778, utilities.URL, ok, i386, 0)
            paths = []
            paths.append({'cond': 0xffffffff8328c77d, 'correct_path': 0xffffffff8328c77f, 'wrong_path': 0xffffffff8328c79a})
            paths.append({'cond': 0xffffffff83295764, 'correct_path': 0xffffffff83295766, 'wrong_path': 0xffffffff8329576b})
            paths.append({'cond': 0xffffffff8329661f, 'correct_path': 0xffffffff8329667b, 'wrong_path': 0xffffffff83296621})
            paths.append({'cond': 0xffffffff83296f63, 'correct_path': 0xffffffff83296f65, 'wrong_path': 0xffffffff83296fc2})
            paths.append({'cond': 0xffffffff83296fc0, 'correct_path': 0xffffffff83296f65, 'wrong_path': 0xffffffff83296fc2})
            sym.setup_bug_capture(8, 32, 0xffffffff8328c776, 0xffffffff83295769, paths)
            sym.run_sym()
            ### DEBUG SYMEXEC ###
            if self.force_fuzz or not write_without_mutating:
                path = None
                need_fuzzing = True
                req = requests.request(method='GET', url=case["syz_repro"])
                self.__write_config(req.content.decode("utf-8"), hash_val[:7])
                exitcode = self.run_syzkaller(hash_val)
                self.__save_case(hash_val, exitcode, case, need_fuzzing)
            if write_without_mutating and title != None:
                # move to succeed group
                self.__save_case(hash_val, 0, case, need_fuzzing=False, title=title)
        else:
            self.logger.info("{} has finished".format(hash_val[:7]))
        return self.index
    
    def KasanWriteChecker(self, report, hash_val):
        title = None
        ret = False
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
                    if utilities.regx_match(utilities.kasan_write_addr_regx, line):
                        ret = True
                        self.crash_checker.logger.info("OOB/UAF Write without mutating")
                        self.crash_checker.logger.info("Detect read before write")
                        self.logger.info("Write to confirmed success")
                        self.__write_to_sucess(hash_val)
                        self.__write_to_confirmed_sucess(hash_val)
                        break
        return ret, title

    def clone_linux(self):
        self.__run_linux_clone_script()

    def run_syzkaller(self, hash_val):
        self.logger.info("run syzkaller".format(self.index))
        syzkaller = os.path.join(self.syzkaller_path, "bin/syz-manager")
        exitcode = 0
        # First round, we only enable limited syscalls.
        # If failed to trigger a write crash, we enable more syscalls to run it again
        if self.logger.level == logging.DEBUG:
            p = Popen([syzkaller, "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash_val[:7]), "-debug", "-poc"],
                  stdout=PIPE,
                  stderr=STDOUT
                  )
            with p.stdout:
                self.__log_subprocess_output(p.stdout, logging.INFO)
            exitcode = p.wait()

            p = Popen([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash_val[:7]), "-debug"],
                stdout=PIPE,
                stderr=STDOUT
                )
            with p.stdout:
                self.__log_subprocess_output(p.stdout, logging.INFO)
            exitcode = p.wait()
        else:
            p = Popen([syzkaller, "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash_val[:7]), "-poc"],
                stdout = PIPE,
                stderr = STDOUT
                )
            with p.stdout:
                self.__log_subprocess_output(p.stdout, logging.INFO)
            exitcode = p.wait()

            p = Popen([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash_val[:7])],
                stdout = PIPE,
                stderr = STDOUT
                )
            with p.stdout:
                self.__log_subprocess_output(p.stdout, logging.INFO)
            exitcode = p.wait()
        self.logger.info("syzkaller is done with exitcode {}".format(exitcode))
        if exitcode == 3:
            #Failed to parse the testcase
            if self.correctTemplate() and self.compileTemplate():
                exitcode = self.run_syzkaller(hash_val)
        return exitcode
    
    def compileTemplate(self):
        chmodX("syzbot_analyzer/scripts/syz-compile.sh")
        self.logger.info("run: scripts/syz-compile.sh")
        p = Popen(["syzbot_analyzer/scripts/syz-compile.sh", self.current_case_path ,self.arch],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/syz-compile.sh is done with exitcode {}".format(exitcode))
        return exitcode == 0
    
    def correctTemplate(self):
        find_it = False
        pattern_type = utilities.SYSCALL
        text = ''
        pattern = ''
        try:
            path = os.path.join(self.syzkaller_path, 'CorrectTemplate')
            f = open(path, 'r')
            text = f.readline()
            if len(text) == 0:
                self.logger.info("Error: CorrectTemplate is empty")
                return find_it
        except:
            return find_it
        
        if text.find('syscall:') != -1:
            pattern = text.split(':')[1]
            pattern_type = utilities.SYSCALL
            pattern = pattern + "\("
        if text.find('arg:') != -1:
            pattern = text.split(':')[1]
            pattern_type = utilities.STRUCT
            i = pattern.find('[')
            if i != -1:
                pattern = "type " + pattern[:i]
            else:
                pattern = pattern + " {"
        
        search_path="sys/linux"
        extension=".txt"
        ori_syzkaller_path = os.path.join(self.current_case_path, "poc/gopath/src/github.com/google/syzkaller")
        regx_pattern = "^"+pattern
        src = os.path.join(ori_syzkaller_path, search_path)
        dst = os.path.join(self.syzkaller_path, search_path)
        find_it = self.syncFilesByPattern(regx_pattern, pattern_type, src, dst, extension)
        return find_it

    def syncFilesByPattern(self, pattern, pattern_type, src, dst, ends):
        find_it = False
        data = []
        target_file = ''
        brackets = -1 #-1 means no '{' found ever 

        if not os.path.isdir(src):
            self.logger.info("{} do not exist".format(self.index, src))
            return find_it
        for file_name in os.listdir(src):
            if file_name.endswith(ends):
                find_it = False
                f = open(os.path.join(src, file_name), "r")
                text = f.readlines()
                f.close()
                for line in text:
                    if utilities.regx_match(pattern, line):
                        data.append(line)
                        find_it = True
                        if pattern_type == utilities.FUNC_DEF and line.find('{') != -1:
                            if brackets == -1:
                                brackets = 1
                        continue

                    if find_it:
                        if pattern_type == utilities.SYSCALL or (pattern_type == utilities.STRUCT and line == "\n"):
                            break
                        data.append(line)
                        if pattern_type == utilities.FUNC_DEF:
                            if line.find('{') != -1:
                                if brackets == -1:
                                    brackets = 0
                                brackets += 1
                            if line.find('}') != -1:
                                brackets -= 1
                            if brackets == 0:
                                break
                if find_it:
                    target_file = file_name
                    break
        
        if not os.path.isdir(dst):
            self.logger.info("{} do not exist".format(self.index, dst))
            return False
        for file_name in os.listdir(dst):
            if file_name.endswith(ends):
                find_it = False
                start = 0
                end = 0
                f = open(os.path.join(dst, file_name), "r")
                text = f.readlines()
                f.close()
                for i in range(0, len(text)):
                    line = text[i]
                    if line.find(pattern) != -1:
                        start = i
                        find_it = True
                        continue
                    
                    if find_it:
                        end = i
                        if pattern_type == utilities.SYSCALL or (pattern_type == utilities.STRUCT and line == "\n"):
                            break
            
                if find_it:
                    f = open(os.path.join(dst, file_name), "w")
                    new_data = []
                    new_data.extend(text[:start])
                    new_data.extend(data)
                    new_data.extend(text[end:])
                    f.writelines(new_data)
                    f.close()
                    break
                elif target_file == file_name:
                    f = open(os.path.join(dst, file_name), "w")
                    new_data = []
                    new_data.extend(text)
                    new_data.extend(data)
                    f.writelines(new_data)
                    f.close()
                    find_it = True
                    break
        if pattern_type == utilities.SYSCALL:
            if utilities.regx_match(r'^syz_', pattern):
                regx_pattern = "^"+pattern
                src = os.path.join(self.current_case_path, "poc/gopath/src/github.com/google/syzkaller/executor")
                dst = os.path.join(self.syzkaller_path, "executor")
                file_ends = "common_linux.h"
                self.syncFilesByPattern(regx_pattern, utilities.FUNC_DEF, src, dst, file_ends)
        #if pattern_type == utilities.STRUCT:
        #    for each_struct in self.getSubStruct(data):
        #        self.replaceTemplate(each_struct, utilities.STRUCT)
        return find_it

    def getSubStruct(self, struct_data):
        regx_field = r'\W*([a-zA-Z0-9\[\]_]+)\W+([a-zA-Z0-9\[\]_, ]+)'
        start = False
        end = False
        res = []
        for line in struct_data:
            if line.find('{') != -1:
                start = True
            if line.find('}') != -1:
                end = True
            if end:
                break
            if start:
                field_type = utilities.regx_get(regx_field, line, 1)
                struct_list = self.extractStruct(field_type)
                if len(struct_list) > 0:
                    res.extend(struct_list)
        return res

    def extractStruct(self, text):
        trivial_type = ["int8", "int16", "int32", "int64", "int16be", "int32be", "int64be", "intptr",
                        "in", "out", "inout", "dec", "hex", "oct", "fmt", "string", "target", 
                        "x86_real", "x86_16", "x86_32", "x86_64", "arm64", "text", "proc", "ptr", "ptr64",
                        "inet", "pseudo", "csum", "vma", "vma64", "flags", "const", "array", "void"
                        "len", "bytesize", "bytesize2", "bytesize4", "bytesize8", "bitsize", "offsetof"]
    
    def confirmSuccess(self, hash_val, case):
        syz_repro = case["syz_repro"]
        syz_commit = case["syzkaller"]
        commit = case["commit"]
        config = case["config"]
        c_repro = case["c_repro"]
        i386 = None
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        log = case["log"]
        res = []
        if not self.__check_confirmed(hash_val):
            """self.logger.info("Compare with original PoC")
            res = self.crash_checker.run(syz_repro, syz_commit, log, commit, config, c_repro, i386)
            if res[0]:
                n = self.crash_checker.diff_testcase(res[1], syz_repro)
                self.crash_checker.logger.info("difference of characters of two testcase: {}".format(n))
                self.crash_checker.logger.info("successful crash: {}".format(res[1]))
                read_before_write = self.crash_checker.check_read_before_write(res[1])
                if read_before_write:
                    self.crash_checker.logger.info("Detect read before write")
                self.logger.info("Write to confirmedSuccess")
                self.__write_to_confirmed_sucess(hash_val)
                path = res[1]
            else:
                self.crash_checker.logger.info("Call trace match failed")
            """
            res = self.repro_on_fixed_kernel(hash_val, case)
            """
            if res != []:
                self.logger.info("Write to confirmedSuccess")
                self.__write_to_confirmed_sucess(hash_val)
            """
            return res
        return []
    
    def repro_on_fixed_kernel(self, hash_val, case, crashes_path=None):
        syz_repro = case["syz_repro"]
        syz_commit = case["syzkaller"]
        commit = case["commit"]
        config = case["config"]
        c_repro = case["c_repro"]
        i386 = None
        res = []
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        commit = utilities.get_patch_commit(hash_val)
        if commit != None:
            res = self.crash_checker.repro_on_fixed_kernel(syz_commit, case["commit"], config, c_repro, i386, commit, crashes_path=crashes_path)
        return res
    
    def save_case(self, hash_val, exitcode, case, need_fuzzing, title=None, secondary_fuzzing=False):
        self.__save_case(hash_val=hash_val, exitcode=exitcode, case=case, need_fuzzing=need_fuzzing, title=title, secondary_fuzzing=secondary_fuzzing)

    def __check_confirmed(self, hash_val):
        return False

    def __write_to_confirmed_sucess(self, hash_val):
        with open("{}/work/confirmedSuccess".format(self.project_path), "a+") as f:
            f.write(hash_val[:7]+"\n")
    
    def __write_to_sucess(self, hash_val):
        with open("{}/work/success".format(self.project_path), "a+") as f:
            f.write(hash_val[:7]+"\n")

    def __run_linux_clone_script(self):
        chmodX("syzbot_analyzer/scripts/linux-clone.sh")
        index = str(self.index)
        self.logger.info("run: scripts/linux-clone.sh {} {}".format(self.index, self.linux_folder, index))
        call(["syzbot_analyzer/scripts/linux-clone.sh", self.linux_folder, index])

    def __run_delopy_script(self, hash_val, case, kasan_patch=0):
        commit = case["commit"]
        syzkaller = case["syzkaller"]
        config = case["config"]
        testcase = case["syz_repro"]
        time = case["time"]
        self.case_info_logger.info("\ncommit: {}\nsyzkaller: {}\nconfig: {}\ntestcase: {}\ntime: {}\narch: {}".format(commit,syzkaller,config,testcase,time,self.arch))

        case_time = time_parser.parse(time)
        if self.image_switching_date <= case_time:
            image = "stretch"
        else:
            image = "wheezy"
        chmodX("syzbot_analyzer/scripts/deploy.sh")
        index = str(self.index)
        self.logger.info("run: scripts/deploy.sh".format(self.index))
        p = Popen(["syzbot_analyzer/scripts/deploy.sh", self.linux_folder, hash_val, commit, syzkaller, config, testcase, index, self.catalog, image, self.arch, self.compiler, str(kasan_patch)],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode

    def __write_config(self, testcase, hash_val):
        dependent_syscalls = []
        syscalls = self.__extract_syscalls(testcase)
        if syscalls == []:
            self.logger.info("No syscalls found in testcase: {}".format(testcase))
            return -1
        for each in syscalls:
            dependent_syscalls.extend(self.__extract_dependent_syscalls(each, self.syzkaller_path))
        if len(dependent_syscalls) < 1:
            self.logger.info("Cannot find dependent syscalls for\n{}\nTry to continue without them".format(testcase))
        new_syscalls = syscalls.copy()
        new_syscalls.extend(dependent_syscalls)
        new_syscalls = utilities.unique(new_syscalls)
        enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""
        syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash_val, self.default_port+self.index, self.current_case_path, self.time_limit, self.arch)
        f = open(os.path.join(self.syzkaller_path, "workdir/{}-poc.cfg".format(hash_val)), "w")
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
        syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash_val, self.default_port+self.index, self.current_case_path, self.time_limit, self.arch)
        f = open(os.path.join(self.syzkaller_path, "workdir/{}.cfg".format(hash_val)), "w")
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

    def __save_case(self, hash_val, exitcode, case, need_fuzzing, title=None, secondary_fuzzing=False):
        if exitcode !=0:
            self.__save_error(hash_val)
        else:
            self.__copy_crashes(need_fuzzing)
            self.__create_stamp(stamp_finish_fuzzing)
            if self.__success_check(hash_val[:7]):
                if need_fuzzing:
                    paths = self.confirmSuccess(hash_val, case)
                    if len(paths) > 0:
                        for each in paths:
                            self.__copy_new_capability(each, need_fuzzing, title)
                        self.__move_to_succeed()
                    else:
                        self.__move_to_completed()
                else:
                    self.__copy_new_capability(case, need_fuzzing, title)
                    self.__move_to_succeed()
            else:
                #if found OOB/UAF read, do fuzzing again bases on it
                crash_path = utilities.extract_existed_crash(self.current_case_path, [utilities.kasan_read_regx])
                if len(crash_path) == 0 or secondary_fuzzing:
                    self.__move_to_completed()
                else:
                    need_patch = 0
                    for each in crash_path:
                        testcase_path = os.path.join(each, "repro.prog")
                        if os.path.isfile(testcase_path):
                            #Using patch to eliminate cases wuth different root cases
                            if len(self.repro_on_fixed_kernel(hash_val, case, [each]))>0:
                                dst = "{}/gopath/src/github.com/google/syzkaller/workdir/testcase-{}".format(self.current_case_path, hash_val[:7])
                                shutil.copy(testcase_path, dst)
                                with open(testcase_path, 'r') as f:
                                    self.logger.info("OOB/UAF Read detected, rerun syzkaller base on new testcase {}".format(testcase_path))
                                    raw_text = f.readlines()
                                    self.__write_config("".join(raw_text),hash_val)
                                    if need_patch == 0:
                                        need_patch = 1
                                        self.__run_delopy_script(hash_val[:7], case, need_patch)
                                    exitcode = self.run_syzkaller(hash_val)
                                    self.__save_case(hash_val, exitcode, case, need_fuzzing, secondary_fuzzing=True)
                                    return
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
            base = os.path.basename(path)
            for files in src_files:
                if files == "description":
                    with open(os.path.join(path, files), "r") as f:
                        line = f.readline()
                        for alert_key in self.alert:
                            if len(alert_key) > 0 and utilities.regx_match(alert_key, line):
                                self.__trigger_alert(base, alert_key)
            shutil.copytree(path, os.path.join(output, base))
    
    def __trigger_alert(self, name, alert_key):
        self.logger.info("An alert for {} was trigger by crash {}".format(alert_key, name))

    def __save_error(self, hash_val):
        self.logger.info("case {} encounter an error. See log for details.".format(hash_val))
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
    
    def __check_stamp(self, name, hash_val, folder):
        stamp_path1 = "{}/work/{}/{}/.stamp/{}".format(self.project_path, folder, hash_val, name)
        return os.path.isfile(stamp_path1)
    
    def __clean_stamp(self, name, hash_val):
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

    def __success_check(self, hash_val):
        success_path = "{}/work/success".format(self.project_path)
        if os.path.isfile(success_path):
            f = open(success_path, "r")
            text = f.readlines()
            f.close()
            for line in text:
                line = line.strip('\n')
                if line == hash_val:
                    return True
        return False
    
    def __need_kasan_patch(self, title):
        return utilities.regx_match(r'slab-out-of-bounds Read', title)

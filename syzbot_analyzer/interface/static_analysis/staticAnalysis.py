import os, stat
from socket import timeout
import logging
import shutil
import syzbot_analyzer.interface.utilities as utilities
import threading
import time
import queue

from subprocess import Popen, PIPE, STDOUT, TimeoutExpired, call
from .error import CompilingError

class StaticAnalysis:
    def __init__(self, logger, proj_path, index, case_path, linux_folder, max_compiling_kernel, timeout=30*60):
        self.case_logger = logger
        self.proj_path = proj_path
        self.package_path = os.path.join(proj_path, "syzbot_analyzer")
        self.case_path = case_path
        self.index = index
        self.linux_folder = linux_folder
        self.cmd_queue = queue.Queue()
        self.bc_ready = False
        self.timeout = timeout
        self.max_compiling_kernel = max_compiling_kernel

    def prepare_static_analysis(self, case, vul_site, func_site):
        exitcode = 0
        bc_path = ''
        commit = case["commit"]
        config = case["config"]
        vul_file, tmp = vul_site.split(':')
        func_file, tmp = func_site.split(':')

        if not os.path.exists("{}/paths".format(self.case_path)):
            os.mkdir("{}/paths".format(self.case_path))
        if os.path.exists("{}/one.bc".format(self.case_path)):
            return exitcode

        if os.path.splitext(vul_file)[1] == '.h':
            bc_path = os.path.dirname(func_file)
        else:
            dir_list1 = vul_file.split('/')
            dir_list2 = func_file.split('/')
            for i in range(0, min(len(dir_list1), len(dir_list2)) - 1):
                if dir_list1[i] == dir_list2[i]:
                    bc_path += dir_list1[i] + '/'
        
        script_path = os.path.join(self.package_path, "scripts/deploy-bc.sh")
        utilities.chmodX(script_path)
        index = str(self.index)
        self.case_logger.info("run: scripts/deploy-bc.sh")
        self.adjust_kernel_for_clang()

        p = Popen([script_path, self.linux_folder, index, self.case_path, commit, config, bc_path, "1", str(self.max_compiling_kernel)],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.case_logger.info("script/deploy-bc.sh is done with exitcode {}".format(exitcode))

        if exitcode == 1:
            x = threading.Thread(target=self.monitor_execution, args=(p, 60*60))
            x.start()
            if self.compile_bc_extra() != 0:
                self.case_logger.error("Error occur when compiling bc or linking them")
                return exitcode
        elif exitcode != 0:
            self.case_logger.error("Error occur in deploy-bc.sh")
            return exitcode
        
        # Restore CONFIG_KCOV CONFIG_KASAN CONFIG_BUG_ON_DATA_CORRUPTION
        # Kernel fuzzing and symbolic execution depends on some of them
        p = Popen([script_path, self.linux_folder, index, self.case_path, commit, config, bc_path, "0", str(self.max_compiling_kernel)],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        return exitcode
    
    def monitor_execution(self, p, seconds):
        count = 0
        while (count < seconds // 10):
            count += 1
            time.sleep(10)
            poll = p.poll()
            if poll != None:
                return
        self.case_logger.info('Time out, kill qemu')
        p.kill()
    
    def adjust_kernel_for_clang(self):
        opts = ["-fno-inline-functions", "-fno-builtin-bcmp"]
        self._fix_asm_volatile_goto()
        self._add_extra_options(opts)
    
    def compile_bc_extra(self):
        regx = r'echo \'[ \t]*CC[ \t]*(([A-Za-z0-9_\-.]+\/)+([A-Za-z0-9_.\-]+))\';'
        base = os.path.join(self.case_path, 'linux')
        path = os.path.join(base, 'clang_log')

        procs = []
        #for _ in range(0, 16):
        #    x = threading.Thread(target=self.executor, args={base,})
        #    x.start()
        #    procs.append(x)
        with open(path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                p2obj = utilities.regx_get(regx, line, 0)
                obj = utilities.regx_get(regx, line, 2)
                if p2obj == None or obj == None:
                    """cmds = line.split(';')
                    for e in cmds:
                        call(e, cwd=base)"""
                    continue
                if 'arch/x86/' in p2obj:
                    continue
                #print("CC {}".format(p2obj))
                new_cmd = []
                try:
                    clang_path = '{}/tools/llvm/build/bin/clang'.format(self.proj_path)
                    idx1 = line.index(clang_path)
                    idx2 = line[idx1:].index(';')
                    cmd = line[idx1:idx1+idx2].split(' ')
                    if cmd[0] == clang_path:
                        new_cmd.append(cmd[0])
                        new_cmd.append('-emit-llvm')
                    #if cmd[0] == 'wllvm':
                    #    new_cmd.append('{}/tools/llvm/build/bin/clang'.format(self.proj_path))
                    #    new_cmd.append('-emit-llvm')
                    new_cmd.extend(cmd[1:])
                except ValueError:
                    self.case_logger.error('No \'wllvm\' or \';\' found in \'{}\''.format(line))
                    raise CompilingError
                idx_obj = len(new_cmd)-2
                st = new_cmd[idx_obj]
                if st[len(st)-1] == 'o':
                    new_cmd[idx_obj] = st[:len(st)-1] + 'bc'
                    if os.path.exists(os.path.join(base, p2obj)):
                        continue
                else:
                    self.case_logger.error("{} is not end with .o".format(new_cmd[idx_obj]))
                    continue
                #self.cmd_queue.put(new_cmd)
                p = Popen(new_cmd, cwd=base, stdout=PIPE, stderr=PIPE)
                p.wait(timeout=5)
                if p.poll() == None:
                    p.kill()
            
            #self.bc_ready=True
            #for p in procs:
            #    p.join()
            if os.path.exists(os.path.join(self.case_path,'one.bc')):
                os.remove(os.path.join(self.case_path,'one.bc'))
            link_cmd = '{}/tools/llvm/build/bin/llvm-link --only-needed -o one.bc `find ./ -name "*.bc" ! -name "timeconst.bc"` && mv one.bc {}'.format(self.proj_path, self.case_path)
            p = Popen(['/bin/bash','-c', link_cmd], stdout=PIPE, stderr=PIPE, cwd=base)
            with p.stdout:
                self.__log_subprocess_output(p.stdout, logging.INFO)
            exitcode = p.wait()
            if exitcode != 0:
                self.case_logger.error("Fail to construct a monolithic bc")
            return exitcode
    
    def executor(self, base):
        while not self.bc_ready or not self.cmd_queue.empty():
            try:
                cmd = self.cmd_queue.get(block=True, timeout=5)
                p = Popen(cmd, cwd=base, stdout=PIPE, stderr=PIPE)
                p.wait(timeout=5)
                print("CC {}".format(cmd))
                if p.poll() == None:
                    p.kill()
            except queue.Empty:
                # get() is multithreads safe
                # 
                break

    def KasanVulnChecker(self, report):
        vul_site = ''
        func_site = ''
        func = ''
        inline_func = ''
        offset = -1
        report_list = report.split('\n')
        trace = utilities.extrace_call_trace(report_list)
        for each in trace:
            """if vul_site == '':
                vul_site = utilities.extract_debug_info(each)
            if utilities.isInline(each):
                inline_func = utilities.extract_func_name(each)
                continue
            func = utilities.extract_func_name(each)
            if func == inline_func:
                continue"""
            # See if it works after we disabled inline function
            vul_site = utilities.extract_debug_info(each)
            func = utilities.extract_func_name(each)
            if func == 'fail_dump':
                func = None
            func_site = vul_site
            break
        
        return vul_site, func_site, func
    
    def saveCallTrace2File(self, trace, vul_site):
        syscall_entrance = [r'SYS', r'_sys_', r'^sys_', r'entry_SYSENTER', r'entry_SYSCALL', r'ret_from_fork', r'bpf_prog_[a-z0-9]{16}']
        text = []
        flag_record = 0
        last_inline = ''
        flag_stop = False
        for each in trace:
            if utilities.extract_debug_info(each) == vul_site:
                flag_record ^= 1
            if flag_record:
                func = utilities.extract_func_name(each)
                for entrance in syscall_entrance:
                    if utilities.regx_match(entrance, func):
                        # system call entrance is not included
                        flag_stop = True
                        break
                if flag_stop:
                    break
                site = utilities.extract_debug_info(each)
                if site == None:
                    continue
                t = "{} {}".format(func, site)
                file, line = site.split(':')
                s, e = self.getFuncBounds(func, file, int(line))
                if s == 0 and e == 0:
                    break
                t += " {} {}".format(s, e)
                # We disabled inline function
                if utilities.isInline(each):
                    last_inline = func
                    #t += " [inline]
                text.append(t)
                # Sometimes an inline function will appear at the next line of calltrace as a non-inlined function
                if not utilities.isInline(each) and last_inline == func:
                    text.pop()
        path = os.path.join(self.case_path, "CallTrace")
        f = open(path, "w")
        f.writelines("\n".join(text))
        f.truncate()
        f.close()
    
    def getFuncBounds(self, func, file, lo_line):
        s = 0
        e = 0
        base = os.path.join(self.case_path, "linux")
        src_file_path = os.path.join(base, file)
        with open(src_file_path, 'r') as f:
            lines = f.readlines()
            text = "".join(lines)
            tmp = []
            for i in range(lo_line-1, 0, -1):
                tmp.insert(0,lines[i])
                expr = utilities.regx_get(utilities.kernel_func_def_regx, "".join(tmp), 0)
                if expr == None:
                    continue
                n = text.index(expr)
                left_bracket = n+len(expr)+1
                s = i+1
                for j in range(lo_line, len(lines)):
                    line = lines[j]
                    if line == '}\n':
                        e = j+1
                        return s, e
                self.case_logger.error("Incorrect range of {}()".format(func))
        return s ,e

    def run_static_analysis(self, vul_site, func_site, func, offset, size):
        vul_file, vul_line = vul_site.split(':')
        func_file, func_line = func_site.split(':')
        calltrace = os.path.join(self.case_path, 'CallTrace')
        cmd = ["opt", "-load", "{}/tools/dr_checker/build/SoundyAliasAnalysis/libSoundyAliasAnalysis.so".format(self.proj_path), 
                "-dr_checker", "-disable-output", "{}/one.bc".format(self.case_path),
                "-CalltraceFile={}".format(calltrace),
                "-VulFile={}".format(vul_file), "-VulLine={}".format(vul_line), 
                "-FuncFile={}".format(func_file), "-FuncLine={}".format(func_line),
                "-Func={}".format(func), "-Offset={}".format(offset),
                "-PrintPathDir={}/paths".format(self.case_path)]
        if size != None:
            cmd.append("-Size={}".format(size))
        self.case_logger.info("====================Here comes the taint analysis====================")
        self.case_logger.info(" ".join(cmd))
        p = Popen(cmd,
                  stdout=PIPE,
                  stderr=STDOUT
                  )
        x = threading.Thread(target=self.monitor_execution, args=(p, self.timeout))
        x.start()
        start_time = time.time()
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        end_time = time.time()
        time_on_static_analysis = end_time-start_time
        self.case_logger.info("Taint analysis took {}".format(time.strftime('%M:%S', time.gmtime(time_on_static_analysis))))
        return exitcode, time_on_static_analysis
    
    def _fix_asm_volatile_goto(self):
        regx = r'#define asm_volatile_goto'
        linux_repo = os.path.join(self.case_path, "linux")
        compiler_gcc = os.path.join(linux_repo, "include/linux/compiler-gcc.h")
        buf = ''
        if os.path.exists(compiler_gcc):
            with open(compiler_gcc, 'r') as f_gcc:
                lines = f_gcc.readlines()
                for line in lines:
                    if utilities.regx_match(regx, line):
                        buf = line
                        break
            if buf != '':
                compiler_clang = os.path.join(linux_repo, "include/linux/compiler-clang.h")
                with open(compiler_clang, 'r+') as f_clang:
                    lines = f_clang.readlines()
                    data = [buf]
                    data.extend(lines)
                    f_clang.seek(0)
                    f_clang.writelines(data)
                    f_clang.truncate()
        return

    def _add_extra_options(self, opts):
        regx = r'KBUILD_CFLAGS[ \t]+:='
        linux_repo = os.path.join(self.case_path, "linux")
        makefile = os.path.join(linux_repo, "Makefile")
        data = []
        with open(makefile, 'r+') as f:
            lines = f.readlines()
            for i in range(0, len(lines)):
                line = lines[i]
                if utilities.regx_match(regx, line):
                    parts = line.split(':=')
                    opts_str = " ".join(opts)
                    data.extend(lines[:i])
                    data.append(parts[0] + ":= " + opts_str + " " + parts[1])
                    data.extend(lines[i+1:])
                    f.seek(0)
                    f.writelines(data)
                    f.truncate()
                    break
        
    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)

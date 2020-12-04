import os, stat
import logging
import syzbot_analyzer.interface.utilities as utilities

from subprocess import Popen, PIPE, STDOUT

class StaticAnalysis:
    def __init__(self, logger, proj_path, index, case_path, linux_folder):
        self.case_logger = logger
        self.proj_path = proj_path
        self.package_path = os.path.join(proj_path, "syzbot_analyzer")
        self.case_path = case_path
        self.index = index
        self.linux_folder = linux_folder

    def prepare_static_analysis(self, case, vul_site, func_site):
        bc_path = ''
        commit = case["commit"]
        config = case["config"]
        vul_file, tmp = vul_site.split(':')
        func_file, tmp = func_site.split(':')
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
        self.case_logger.info("run: scripts/deploy-bc.sh".format(index))
        p = Popen([script_path, self.linux_folder, index, self.case_path, commit, config, bc_path],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.case_logger.info("script/deploy-bc.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def KasanVulnChecker(self, report):
        vul_site = ''
        func_site = ''
        func = ''
        inline_func = ''
        offset = -1
        report_list = report.split('\n')
        trace = utilities.extrace_call_trace(report_list)
        for each in trace:
            if vul_site == '':
                vul_site = utilities.extract_debug_info(each)
            if utilities.isInline(each):
                inline_func = utilities.extract_func_name(each)
                continue
            func = utilities.extract_func_name(each)
            if func == inline_func:
                continue
            func_site = utilities.extract_debug_info(each)
            break
        
        return vul_site, func_site, func
    
    def saveCallTrace2File(self, trace, vul_site):
        text = []
        flag_record = 0
        for each in trace:
            if utilities.extract_debug_info(each) == vul_site:
                flag_record ^= 1
            if flag_record:
                func = utilities.extract_func_name(each)
                if 'SYS' in func:
                    # system call entrance is not included
                    break
                site = utilities.extract_debug_info(each)
                t = "{} {}".format(func, site)
                file, _ = site.split(':')
                s, e = self.getFuncBounds(func, file)
                t += " {} {}".format(s, e)
                if utilities.isInline(each):
                    t += " [inline]"
                text.append(t)
        path = os.path.join(self.case_path, "CallTrace")
        f = open(path, "w")
        f.writelines("\n".join(text))
    
    def getFuncBounds(self, func, file):
        s = 0
        e = 0
        base = os.path.join(self.case_path, "linux")
        src_file_path = os.path.join(base, file)
        with open(src_file_path, 'r') as f:
            lines = f.readlines()
            text = "".join(lines)
            func_list = utilities.regx_getall(utilities.kernel_func_def_regx, text)
            for each in func_list:
                expr = each[0]
                func_name = each[11]
                if func_name == func:
                    tmp = text
                    idx = 0
                    while True:
                        try:
                            n = tmp.index(expr)
                        except ValueError:
                            break
                        if tmp[n+len(expr)+1] != '{':
                            tmp = tmp[n+len(expr)+1:]
                            idx += n+len(expr)+1
                        else:
                            idx += n
                            break
                    head = text[:idx]
                    s = len(head.split('\n'))
                    n = 0
                    for line in text[idx:].split('\n'):
                        if line == '}':
                            e = s+n
                            break
                        n += 1
                    return s, e
        return s, e

    
    def run_static_analysis(self, vul_site, func_site, func, offset, size):
        vul_file, vul_line = vul_site.split(':')
        func_file, func_line = func_site.split(':')
        calltrace = os.path.join(self.case_path, 'CallTrace')
        cmd = ["opt", "-load", "{}/llvm_passes/build/generateInput/libgenerateInput.so".format(self.package_path), 
                "-generateInput", "-disable-output", "{}/one.bc".format(self.case_path),
                "-CalltraceFile={}".format(calltrace),
                "-VulFile={}".format(vul_file), "-VulLine={}".format(vul_line), 
                "-FuncFile={}".format(func_file), "-FuncLine={}".format(func_line),
                "-Func={}".format(func), "-Offset={}".format(offset), "-Size={}".format(size)]
        self.case_logger.info(" ".join(cmd))
        p = Popen(cmd,
                  stdout=PIPE,
                  stderr=STDOUT
                  )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        return exitcode
        
    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)
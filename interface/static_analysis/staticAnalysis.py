import os, stat
import logging
import interface.utilities as utilities

from subprocess import Popen, PIPE, STDOUT

class StaticAnalysis:
    def __init__(self, logger, proj_path, case_path):
        self.case_logger = logger
        self.proj_path = proj_path
        self.case_path = case_path

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

        script_path = os.path.join(self.proj_path, "scripts/deploy-bc.sh")
        utilities.chmodX(script_path)
        index = str(self.index)
        self.logger.info("run: scripts/deploy-bc.sh".format(self.index))
        p = Popen([script_path, self.linux_path, index, self.current_case_path, commit, config, bc_path],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/deploy-bc.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def KasanVulnChecker(self, report):
        vul_site = ''
        func_site = ''
        offset = -1
        report_list = report.split('\n')
        trace = utilities.extrace_call_trace(report_list)
        for each in trace:
            if vul_site == '':
                vul_site = utilities.extract_debug_info(each)
            if utilities.isInline(each):
                continue
            func = utilities.extract_func_name(each)
            func_site = utilities.extract_debug_info(each)
            break
        
        offset = utilities.extract_vul_obj_offset(report_list)
        self.saveCallTrace2File(trace, vul_site)
        return vul_site, func_site, func, offset
    
    def saveCallTrace2File(self, trace, vul_site):
        text = []
        flag_record = 0
        for each in trace:
            if utilities.extract_debug_info(each) == vul_site:
                flag_record ^= 1
            if flag_record:
                func = utilities.extract_func_name(each)
                site = utilities.extract_debug_info(each)
                t = "{} {}".format(func, site)
                if utilities.isInline(each):
                    t += " [inline]"
                text.append(t)
        path = os.path.join(self.case_path, "CallTrace")
        f = open(path, "w")
        f.writelines("\n".join(text))
    
    def run_static_analysis(self, vul_site, func_site, func, offset):
        vul_file, vul_line = vul_site.split(':')
        func_file, func_line = func_site.split(':')
        cmd = ["opt", "-load", "{}/llvm_passes/build/generateInput/libgenerateInput.so".format(self.project_path), 
                "-generateInput", "-disable-output", "{}/llvm_linux/built-in.o.bc".format(self.project_path),
                "-VulFile={}".format(vul_file), "-VulLine={}".format(vul_line), 
                "-FuncFile={}".format(func_file), "-FuncLine={}".format(func_line),
                "-Func={}".format(func), "-Offset={}".format(offset)]
        p = Popen(cmd,
                  stdout=PIPE,
                  stderr=STDOUT
                  )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        
    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)
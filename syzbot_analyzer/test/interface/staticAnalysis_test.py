import shutil
import os
import syzbot_analyzer.interface.static_analysis as static_analysis
import logging
import syzbot_analyzer.interface.utilities as utilities

from subprocess import PIPE, STDOUT, Popen
from syzbot_analyzer.test.deploy_test import getMinimalDeployer, getCrawler

def compile_bc_extra_test():
    d = getMinimalDeployer("work/incomplete/873d6bc")
    sa = static_analysis.StaticAnalysis(logging, d.project_path, 1, d.current_case_path, "linux")
    sa.compile_bc_extra()
    """
    link_cmd = '{}/tools/llvm/build/bin/llvm-link -o one.bc `find ./ -name "*.bc" ! -name "timeconst.bc"` && mv one.bc {}'.format(d.project_path, d.current_case_path)
    p = Popen(['/bin/bash','-c', link_cmd], cwd=d.kernel_path)
    exitcode = p.wait()
    if exitcode ==0:
        if os.path.exists(os.path.join(d.current_case_path,'one.bc')):
            os.remove(os.path.join(d.current_case_path,'one.bc'))
    """

def saveCallTrace_test(case):
    d = getMinimalDeployer("work/incomplete/341e1a2")
    sa = static_analysis.StaticAnalysis(logging, d.project_path, 1, d.current_case_path, "linux")
    res = utilities.request_get(case['report'])
    vul_site, func_site, func = sa.KasanVulnChecker(res.text)
    report_list = res.text.split('\n')
    trace = utilities.extrace_call_trace(report_list)
    sa.saveCallTrace2File(trace, vul_site)

if __name__ == '__main__':
    hash_val = "341e1a2a55b389e54cc07624ed40eb3ecca577db"
    exitcode = 0
    crawler = getCrawler()
    crawler.run_one_case(hash_val)
    case = crawler.cases.pop(hash_val)
    saveCallTrace_test(case)
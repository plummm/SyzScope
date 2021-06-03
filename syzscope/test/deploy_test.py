from syzscope.modules import deploy, syzbotCrawler, crash
import syzscope.interface.utilities as utilities
from dateutil import parser as time_parser

import os

project_path = os.getcwd()

def getMinimalDeployer(case_path, case):
    force = True
    d = deploy.Deployer(0, 1, debug=True)
    d.compiler = utilities.set_compiler_version(time_parser.parse(case["time"]), case["config"])
    d.project_path = project_path
    d.current_case_path = os.path.join(project_path, case_path)
    d.image_path = os.path.join(d.current_case_path, "img")
    d.kernel_path = os.path.join(d.current_case_path, "linux")
    d.crash_checker = crash.CrashChecker(
        d.project_path,
        d.current_case_path,
        3777,
        d.logger,
        True,
        d.index,
        1,
        compiler=d.compiler)
    d.syzkaller_path = os.path.join(d.current_case_path, "gopath/src/github.com/google/syzkaller")
    return d

def getCrawler():
    crawler = syzbotCrawler.Crawler(debug=True)
    return crawler

def replaceTemplate_test(pattern, pattern_type):
    d = getMinimalDeployer()
    d.replaceTemplate(pattern, pattern_type)

def save_case_test(hash_val, exitcode, case, limitedMutation, impact_without_mutating, title=None, secondary_fuzzing=False):
    d = getMinimalDeployer("work/succeed/0655ccf", case)
    d.save_case(hash_val, exitcode, case, limitedMutation=limitedMutation, impact_without_mutating=impact_without_mutating, title=title, secondary_fuzzing=secondary_fuzzing)

def copy_new_impact_test(case):
    d = getMinimalDeployer('work/completed/232223b')
    d.copy_new_impact(case, True, "KASAN: slab-out-of-bounds in hpet_alloc")

if __name__ == '__main__':
    hash_val = "0655ccf655feea0f30dea3f1ba960af39bcd741a"
    exitcode = 0
    crawler = getCrawler()
    crawler.run_one_case(hash_val)
    case = crawler.cases.pop(hash_val)
    save_case_test(hash_val, 0, case, False, False, case['title'])
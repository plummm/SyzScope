from syzbot_analyzer.modules import deploy, syzbotCrawler, crash
import os

project_path = os.getcwd()

def getMinimalDeployer(case_path):
    force = True
    d = deploy.Deployer(0, 1, debug=True)
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

def save_case_test(hash_val, exitcode, case, need_fuzzing, title=None, secondary_fuzzing=False):
    d = getMinimalDeployer("work/incomplete/974293d")
    d.save_case(hash_val, exitcode, case, need_fuzzing, title=title, secondary_fuzzing=secondary_fuzzing)

def copy_new_impact_test(case):
    d = getMinimalDeployer('work/completed/232223b')
    d.copy_new_impact(case, True, "KASAN: slab-out-of-bounds in hpet_alloc")

if __name__ == '__main__':
    hash_val = "232223b1e1dc405ba8ca60125d643ea8bbeb65ac"
    exitcode = 0
    crawler = getCrawler()
    crawler.run_one_case(hash_val)
    case = crawler.cases.pop(hash_val)
    copy_new_impact_test(case)
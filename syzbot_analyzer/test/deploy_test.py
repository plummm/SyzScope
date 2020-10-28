import deploy
import syzbotCrawler
import crash
import os

project_path = "/home/xzou017/projects/SyzbotAnalyzer"

def getMinimalDeployer(case_path):
    force = True
    d = deploy.Deployer(0, debug=True)
    d.project_path = project_path
    d.image_path = os.path.join(project_path, "img")
    d.kernel_path = os.path.join(project_path, "linux")
    d.current_case_path = os.path.join(project_path, case_path)
    d.crash_checker = crash.CrashChecker(
        d.project_path,
        d.current_case_path,
        3777,
        d.logger,
        True,
        d.index,
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

if __name__ == '__main__':
    hash_val = "974293d3a48ddb44c35d97f946107559bda669ff"
    exitcode = 0
    crawler = getCrawler()
    crawler.run_one_case(hash_val)
    case = crawler.cases.pop(hash_val)
    need_fuzzing = True
    write_without_mutating = True
    #save_case_test(hash_val, exitcode, case, need_fuzzing)
    save_case_test(hash_val, 0, case, need_fuzzing=False, title="AAA")
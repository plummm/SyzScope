import deploy

def getMinimalDeployer():
    force = True
    return deploy.Deployer(0, debug=True)
def replaceTemplate_test(pattern, pattern_type):
    d = getMinimalDeployer()
    d.current_case_path = "/home/xzou017/projects/SyzbotAnalyzer/work/incomplete/fcae301"
    d.syzkaller_path = "/home/xzou017/projects/SyzbotAnalyzer/work/incomplete/fcae301/gopath/src/github.com/google/syzkaller"
    d.replaceTemplate(pattern, pattern_type)

if __name__ == '__main__':
    replaceTemplate_test("syz_open_dev$usb(", 0)
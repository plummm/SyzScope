import os, re, stat

FOLDER=0
CASE=1

def urlsOfCases(folder, type=FOLDER):
    res = []
    dirOfCases = "{}/work/{}".format(os.getcwd(), folder)
    paths = []

    if type == FOLDER:
        for dirs in os.listdir(dirOfCases):
            path = os.path.join(dirOfCases,dirs)
            paths.append(path)
    
    if type == CASE:
        paths.append(dirOfCases)
    
    for path in paths:
        for file in os.listdir(path):
            if file == "log":
                with open(os.path.join(path, file), "r") as f:
                    for line in f:
                        m = re.search(r'\[\d*\] https:\/\/syzkaller.appspot.com\/bug\?id=([a-z0-9]*)\n', line)
                        if m != None and len(m.groups()) != 0:
                            res.append(m.groups()[0])  
                            break
    
    return res

def regx_match(regx, line):
    m = re.search(regx, line)
    if m != None and len(m.group()) != 0:
        return True
    return False

def chmodX(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)
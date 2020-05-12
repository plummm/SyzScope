import os, re, stat
import requests
import numpy as np
import json

from syzbotCrawler import Crawler

FOLDER=0
CASE=1
URL=2

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

def request_get(url):
    return requests.request(method='GET', url=url)

def levenshtein_for_calltrace(seq1, seq2):
    size_x = len(seq1) + 1
    size_y = len(seq2) + 1
    matrix = np.zeros ((size_x, size_y))
    for x in range(size_x):
        matrix [x, 0] = x
    for y in range(size_y):
        matrix [0, y] = y

    for x in range(1, size_x):
        for y in range(1, size_y):
            if seq1[x-1] == seq2[y-1]:
                matrix [x,y] = min(
                    matrix[x-1, y] + 1,
                    matrix[x-1, y-1],
                    matrix[x, y-1] + 1
                )
            else:
                matrix [x,y] = min(
                    matrix[x-1,y] + 1,
                    matrix[x-1,y-1] + 1,
                    matrix[x,y-1] + 1
                )
    #print (matrix)
    return (matrix[size_x - 1, size_y - 1])

def syzrepro_convert_format(line):
        res = {}
        p = re.compile(r'({| )(\w+):([0-9a-zA-Z-]*)')
        raw = p.sub(r'\1"\2":"\3",', line)
        new_line =raw[:raw.find('}')-1] + "}"
        pm = json.loads(new_line)
        for each in pm:
            if each == 'Threaded':
                res['threaded']=pm[each]
            if each == 'Collide':
                res['collide']=pm[each]
            if each == 'Repeat':
                res['repeat']=pm[each]
            if each == 'Procs':
                res['procs']=pm[each]
            if each == 'Sandbox':
                res['sandbox']=pm[each]
            if each == 'FaultCall':
                res['fault_call']=pm[each]
            if each == 'FaultNth':
                res['fault_nth']=pm[each]
            if each == 'EnableTun':
                res['tun']=pm[each]
            if each == 'EnableCgroups' or each == 'Cgroups':
                res['cgroups']=pm[each]
            if each == 'UseTmpDir':
                res['tmpdir']=pm[each]
            if each == 'HandleSegv':
                res['segv']=pm[each]
            if each == 'Fault':
                res['fault']=pm[each]
            if each == 'WaitRepeat':
                res['wait_repeat']=pm[each]
            if each == 'Debug':
                res['debug']=pm[each]
            if each == 'Repro':
                res['repro']=pm[each]
            if each == 'NetDevices':
                res['netdev']=pm[each]
            if each == 'NetReset':
                res['resetnet']=pm[each]
            if each == 'BinfmtMisc':
                res['binfmt_misc']=pm[each]
            if each == 'CloseFDs':
                res['close_fds']=pm[each]
            if each == 'DevlinkPCI':
                res['devlinkpci']=pm[each]
            if each == 'USB':
                res['usb']=pm[each]
        #if len(pm) != len(res):
        #    self.logger.info("parameter is missing:\n%s\n%s", new_line, str(res))
        return res

#divide into race-condition and nonrace-condition
def get_types_of_cases(folder):
    race = []
    non_race = []
    hashs = urlsOfCases(folder)
    crawler = Crawler()
    for each in hashs:
        crawler.run_one_case(each)
    for hash in crawler.cases:
        case = crawler.cases[hash]
        syz_repro_url = case["syz_repro"]
        r = request_get(syz_repro_url)
        text = r.text.split('\n')
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                pm = {}
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    pm = syzrepro_convert_format(line[1:])
                if "repeat" in pm and str(pm["repeat"]).lower() == 'true':
                    race.append(hash)
                else:
                    non_race.append(hash)
                break
    return [race, non_race]

if __name__ == '__main__':
    print("race")
    with open('/tmp/race') as f:
        text = f.readlines()
        for line in text:
            line = line.strip('\n')
            crawler = Crawler()
            print(crawler.get_title_of_case(hash=line))
    print("non-race")
    with open('/tmp/non-race') as f:
        text = f.readlines()
        for line in text:
            line = line.strip('\n')
            crawler = Crawler()
            print(crawler.get_title_of_case(hash=line))
import os, re, stat
import requests
import numpy as np
import json
import datetime

from bs4 import BeautifulSoup
#from syzbot_analyzer.modules import Crawler
from dateutil import parser as time_parser

FOLDER=0
CASE=1
URL=2

KASAN_NONE=0
KASAN_OOB=1
KASAN_UAF=2

SYSCALL = 0
STRUCT = 1
FUNC_DEF = 2

syzbot_bug_base_url = "bug?id="
syzbot_host_url = "https://syzkaller.appspot.com/"
kasan_write_regx = r'KASAN: ([a-z\\-]+) Write in ([a-zA-Z0-9_]+).*'
kasan_read_regx = r'KASAN: ([a-z\\-]+) Read in ([a-zA-Z0-9_]+).*'
kasan_write_addr_regx = r'Write of size (\d+) at addr (\w+)'
kasan_read_addr_regx = r'Read of size (\d+) at addr (\w+)'
free_regx = r'KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
bug_desc_begin_regx = r'The buggy address belongs to the object at'
bug_desc_end_regx = r'The buggy address belongs to the page'
offset_desc_regx = r'The buggy address is located (\d+) bytes inside of'
size_desc_regx = r'which belongs to the cache [a-z0-9\-]+ of size (\d+)'
kernel_func_def_regx= r'^(static )?(const |struct )?\w+(\*)? ([a-zA-Z0-9:_]*( |\n))?(\*)?([a-zA-Z0-9:_]+)\((\)|void\)|((volatile)? (const |struct |unsigned )?\w+( )?[\*]*( )?\w+(, \.\.\.\)|, |,\n|\)))+)'

def get_hash_from_log(path):
    with open(path, "r") as f:
        for line in f:
            m = re.search(r'\[\d*\] https:\/\/syzkaller.appspot.com\/bug\?id=([a-z0-9]*)\n', line)
            if m != None and len(m.groups()) != 0:
                return m.groups()[0]  
    return None

def regx_match(regx, line):
    m = re.search(regx, line)
    if m != None and len(m.group()) != 0:
        return True
    return False

def regx_get(regx, line, index):
    m = re.search(regx, line)
    if m != None and len(m.groups()) > index:
        return m.groups()[index]
    return None

def regx_kasan_line(line):
    m = re.search(r'([A-Za-z0-9_.]+)(\+0x[0-9a-f]+\/0x[0-9a-f]+)?( (([A-Za-z0-9_\-.]+\/)+[A-Za-z0-9_.\-]+:\d+))?( \[inline\])?', line)
    if m != None:
        return m.groups()
    return None

def extract_debug_info(line):
    res = regx_kasan_line(line)
    if res == None:
        return res
    return res[3]

def isInline(line):
    res = regx_kasan_line(line)
    if res == None:
        return False
    if res[5] != None:
        return True
    return False

def extract_func_name(line):
    res = regx_kasan_line(line)
    if res == None:
        return res
    return res[0]

def is_kasan_func(source_path):
    if source_path == None:
        return False
    if regx_match(r'dump_stack.c', source_path) or regx_match(r'mm\/kasan', source_path):
        return True
    return False

def extract_allocated_section(report):
        res = []
        record_flag = 0
        for line in report:
            if record_flag and not is_kasan_func(extract_debug_info(line)):
                res.append(line)
            if regx_match(r'Allocated by task \d+', line):
                record_flag ^= 1
            if regx_match(r'Freed by task \d+', line):
                record_flag ^= 1
                break
        return res[:-2]
    
def extrace_call_trace(report):
    call_trace_end = [r"entry_SYSENTER", r"entry_SYSCALL", r"ret_from_fork"]
    res = []
    record_flag = 0
    implicit_call_regx = r'\[.+\]  \?.*'
    for line in report:
        if record_flag and \
            not regx_match(implicit_call_regx, line) and \
            not is_kasan_func(extract_debug_info(line)):
            res.append(line)
        if regx_match(r'Call Trace', line):
            record_flag ^= 1
        if record_flag == 1 and regx_match_list(call_trace_end, line):
            record_flag ^= 1
            break
    return res

def regx_match_list(regx_list, line):
    for regx in regx_list:
        if regx_match(regx, line):
            return True
    return False

def extract_bug_description(report):
    res = []
    record_flag = 0
    for line in report:
        if regx_match(bug_desc_begin_regx, line):
            record_flag ^= 1
        if regx_match(bug_desc_end_regx, line):
            record_flag ^= 1
        if record_flag:
            res.append(line)
    return res

def extract_bug_type(report):
    for line in report:
        if regx_match(r'KASAN: use-after-free', line):
            return KASAN_UAF
        if regx_match(r'KASAN: \w+-out-of-bounds', line):
            return KASAN_OOB
    return KASAN_NONE

def extract_bug_mem_addr(report):
    addr = None
    for line in report:
        addr = regx_get(kasan_read_addr_regx, line , 1)
        if addr != None:
            return int(addr, 16)
        addr = regx_get(kasan_write_addr_regx, line , 1)
        if addr != None:
            return int(addr, 16)
    return None

def extract_vul_obj_offset_and_size(report):
    offset = None
    size = None
    bug_desc = extract_bug_description(report)
    bug_type = extract_bug_type(report)
    bug_mem_addr = extract_bug_mem_addr(report)
    if bug_mem_addr == None:
        print("Failed to locate the memory address that trigger UAF/OOB")
        return offset
    if bug_type == KASAN_NONE:
        return offset
    if bug_type == KASAN_UAF or bug_type == KASAN_OOB:
        for line in bug_desc:
            if offset == None:
                offset = regx_get(offset_desc_regx, line, 0)
                if offset != None:
                    offset = int(offset)
            if size == None:
                size = regx_get(size_desc_regx, line, 0)
                if size != None:
                    size = int(size)
            if offset != None and size != None:
                break
        if offset == None:
            if len(bug_desc) == 0:
                return offset, size
            line = bug_desc[0]
            addr_begin = regx_get(r'The buggy address belongs to the object at \w+', line, 0)
            if addr_begin != None:
                addr_begin = int(addr_begin, 16)
                offset = bug_mem_addr - addr_begin
        if size == None:
            size = offset
    return offset, size

def urlsOfCases(dirOfCases, type=FOLDER):
    res = []
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
                r = get_hash_from_log(os.path.join(path, file))
                if r != None:
                    res.append(r)
    
    return res

def chmodX(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def request_get(url):
    return requests.request(method='GET', url=url)

def levenshtein(seq1, seq2):
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

def get_patch_commit(hash):
        url = syzbot_host_url + syzbot_bug_base_url + hash
        req = request_get(url)
        soup = BeautifulSoup(req.text, "html.parser")
        try:
            fix = soup.find('span', {'class': 'mono'})
            #fix = soup.body.span.contents[1]
            url = fix.contents[1].attrs['href']
            m = re.search(r'id=(\w*)', url)
            if m != None and m.groups() != None:
                res = m.groups()[0]
        except:
            res=None
        return res

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
            if each == 'EnableTun' or each == 'NetInjection':
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

def unique(seq):
    res = []
    for each in seq:
        if each not in res:
            res.append(each)
    return res

def use_and_free_same_task(url):
    res = None
    r = request_get(url)
    text = r.text.split('\n')
    use_flag = False
    free_flag = False
    for line in text:
        if regx_match(r'CPU: \d+ PID: \d+ Comm:', line):
            m = re.search(r'CPU: \d+ PID: (\d+) Comm:', line)
            task1 = m.groups()[0]
            use_flag = True
        if regx_match(r'Freed by task \d+', line):
            m = re.search(r'Freed by task (\d+):', line)
            task2 = m.groups()[0]
            free_flag = True
        """if use_flag:
            if regx_match(r'entry_SYSCALL', line):
                task1 = a1
                use_flag = False
            if regx_match(r'Allocated by task', line):
                use_flag = False
        if free_flag:
            if regx_match(r'entry_SYSCALL', line):
                task2 = a2
                free_flag = False
                break
            if regx_match(r'The buggy address belongs to the object at', line):
                free_flag = False
                break
        """
    try:
        if task1 == task2:
            res = True
        else:
            res = False
    except:
        print("Error: "+url)
    return res
        
"""
#divide into race-condition and nonrace-condition
def get_types_of_cases(hashs):
    race = []
    non_race = []
    crawler = Crawler()
    for each in hashs:
        crawler.run_one_case(each)
    for hash in crawler.cases:
        case = crawler.cases[hash]
        syz_repro_url = case["syz_repro"]
        log_url = case["log"]
        r = request_get(syz_repro_url)
        text = r.text.split('\n')
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                pm = {}
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    pm = syzrepro_convert_format(line[1:])
                if 'repeat' in pm and str(pm['repeat']).lower() == 'true':
                    same_task = use_and_free_same_task(log_url)
                    if "threaded" in pm and str(pm["threaded"]).lower() == 'true':
                        if "collide" in pm and str(pm["collide"]).lower() == 'true':
                            race.append(hash)
                        else:
                            if 'procs' in pm and str(pm['procs'])!="1":
                                if same_task == False:
                                    race.append(hash)
                                else:
                                    non_race.append(hash)
                            else:
                                non_race.append(hash)
                    else:
                        if 'procs' in pm and str(pm['procs'])!="1":
                            if same_task == False:
                                race.append(hash)
                            else:
                                non_race.append(hash)
                        else:
                            non_race.append(hash)
                else:
                    non_race.append(hash)

                if "procs" in pm:
                    procs = pm["procs"]
                else:
                    procs = 1
                if "repeat" in pm:
                    repeat = pm["repeat"]
                else:
                    repeat = False
                if "threaded" in pm:
                    threaded = pm["threaded"]
                else:
                    threaded = False
                if "collide" in pm:
                    collide = pm["collide"]
                else:
                    collide = False
                if "repeat" in pm and str(pm["repeat"]).lower() == 'true':
                    print("race {} : procs:{} repeat:{} threaded:{} collide:{} same task:{}".format(hash, procs, repeat, threaded, collide, str(same_task)))
                
                break
    return [race, non_race]
"""
def update_img_for_case(hash, folder, time):
    image_switching_date = datetime.datetime(2020, 3, 15)
    case_time = time_parser.parse(time)
    if image_switching_date <= case_time:
        image = "stretch"
    else:
        image = "wheezy"
    project_path = os.getcwd()
    src =  "{}/tools/img".format(project_path)
    des = "{}/work/{}/{}/img".format(project_path, folder, hash[:7])
    os.makedirs(des, exist_ok=True)
    os.symlink(os.path.join(src,image+".img"), os.path.join(des, "stretch.img"))
    os.symlink(os.path.join(src,image+".img.key"), os.path.join(des, "stretch.img.key"))

def get_case_from_file(path):
    res = []
    race = os.path.join(path,"race")
    non_race = os.path.join(path, "non-race")
    with open(race, 'r') as f:
        text = f.readlines()
        for line in text:
            line = line.strip('\n')
            res.append(line)
    with open(non_race, 'r') as f:
        text = f.readlines()
        for line in text:
            line = line.strip('\n')
            res.append(line)
    return res

def check_keyword_on_patch(hash):
    url = syzbot_host_url + syzbot_bug_base_url + hash
    req = request_get(url)
    soup = BeautifulSoup(req.text, "html.parser")
    try:
        fix = soup.body.span.contents[1]
        url = fix.attrs['href']
    except:
        res=None
    req = request_get(url)
    if regx_match(r' race(s)?( |-)| race(s)?\n| Race(s)?( |-)| Race(s)?\n', req.text):
        return True
    return False

def set_compiler_version(time, config_url):
    GCC = 0
    CLANG = 1
    regx_gcc_version = r'gcc \(GCC\) (\d+).\d+.\d+ (\d+)'
    regx_clang_version = r'clang version (\d+).\d+.\d+ \(https:\/\/github\.com\/llvm\/llvm-project\/ (\w+)\)'
    compiler = -1
    ret = ""
    
    r = request_get(config_url)
    text = r.text.split('\n')
    for line in text:
        if line.find('Compiler:') != -1:
            if regx_match(regx_gcc_version, line):
                compiler = GCC
                version = regx_get(regx_gcc_version, line, 0)
                commit = regx_get(regx_gcc_version, line, 1)
            if regx_match(regx_clang_version, line):
                compiler = CLANG
                version = regx_get(regx_clang_version, line, 0)
                commit = regx_get(regx_clang_version, line, 1)
            break
        if line.find('CONFIG_CC_VERSION_TEXT') != -1:
            if regx_match(regx_gcc_version, line):
                compiler = GCC
                version = regx_get(regx_gcc_version, line, 0)
                commit = regx_get(regx_gcc_version, line, 1)
            if regx_match(regx_clang_version, line):
                compiler = CLANG
                version = regx_get(regx_clang_version, line, 0)
                commit = regx_get(regx_clang_version, line, 1)
            break
    
    if compiler == GCC:
        if version == '7':
            ret = "gcc-7"
        if version == '8':
            ret = "gcc-8.0.1-20180412"
        if version == '9':
            ret = "gcc-9.0.0-20181231"
        if version == '10':
            ret = "gcc-10.1.0-20200507"

    if compiler == CLANG:
        if version == '7' and version.find('329060'):
            ret = "clang-7-329060"
        if version == '7' and version.find('334104'):
            ret = "clang-7-334104"
        if version == '8':
            ret = "clang-8-343298"
        if version == '10':
            #clang-10-c2443155 seems corrput (Compiler lacks asm-goto support)
            #return clang-11-ca2dcbd030e
            ret = "clang-11-ca2dcbd030e"
        if version == '11':
            ret = "clang-11-ca2dcbd030e"
    
    if compiler == -1:
        #filter by timestamp
        t1 = datetime.datetime(2018, 3, 1)
        t2 = datetime.datetime(2018, 4, 12)
        t3 = datetime.datetime(2018, 12, 31)
        t4 = datetime.datetime(2020, 5, 7)

        if time < t1:
            ret = "gcc-7"
        if time >= t1 and time < t2:
            #gcc-8.0.1-20180301 seems corrput (Compiler lacks asm-goto support)
            #return "gcc-8.0.1-20180301"
            ret = "gcc-8.0.1-20180412"
        if time >= t2 and time < t3:
            ret = "gcc-8.0.1-20180412"
        if time >= t3 and time < t4:
            ret = "gcc-9.0.0-20181231"
        if time >= t4:
            ret = "gcc-10.1.0-20200507"
    return ret

def extract_existed_crash(path, regx):
    crash_path = os.path.join(path, "crashes")
    #extrace the latest crashes
    if os.path.isdir(crash_path):
        for i in range(0,99):
            crash_path_tmp = os.path.join(path, "crashes-{}".format(i))
            if os.path.isdir(crash_path_tmp):
                crash_path = crash_path_tmp
            else:
                break
    res = []

    if os.path.isdir(crash_path):
        for case in os.listdir(crash_path):
            description_file = "{}/{}/description".format(crash_path, case)
            if os.path.isfile(description_file):
                with open(description_file, "r") as f:
                    line = f.readline()
                    for each in regx:
                        if regx_match(each, line):
                            res.append(os.path.join(crash_path, case))
                            continue
    return res

#Cases with OOB/UAF write, some cases may failed to generate reproducer but it still hopeful
def retrieve_cases_match_regx(dirOfCases, regx):
    res = []
    paths = []

    for dirs in os.listdir(dirOfCases):
        path = os.path.join(dirOfCases,dirs)
        paths.append(path)
    
    for path in paths:
        if len(extract_existed_crash(path, regx)) > 0:
            r = get_hash_from_log(os.path.join(path, 'log'))
            if r != None:
                res.append(r)
    
    return res
"""
def save_cases_as_json(key, max_num):
    crawler = Crawler(keyword=key, max_retrieve=max_num)
    cases = crawler.gather_cases()
    with open('cases_{}.json'.format("-".join(key)), 'w') as f:
        for each in cases:
            json.dump(each, f)
            f.write('\n')
"""
def load_cases_from_json(path):
    res = []
    with open(path, 'r') as f:
        text = f.readlines()
        for line in text:
            line = line.strip()
            crash = json.loads(line)
            res.append(crash)
    return res

def cmp_case_with_last_day(case):
    days = regx_get('(\d+)d',case['Last'],0)
    if days != None:
        return int(days)
    return -1

if __name__ == '__main__':
    res = urlsOfCases("/home/xzou017/projects/SyzbotAnalyzer/work/error/")
    for each in res:
        print(each)
    """
    crashes = load_cases_from_json('./cases_.json')
    sorted_cases = sorted(crashes, key=cmp_case_with_last_day)
    # libraries
    import numpy as np
    import seaborn as sns
    import matplotlib.pyplot as plt
    sns.set_style("whitegrid")
    
    # Color palette
    blue, = sns.color_palette("muted", 1)
    
    # Create data
    x_data = [0]
    y_data = []
    last = 0
    count = {}
    count[0]=0
    for each in sorted_cases:
        days = regx_get('(\d+)d',each['Last'],0)
        if days != None:
            if days not in count:
                count[days] = 1
            else:
                count[days] += 1
            if days != last:
                x_data.append(days)
                y_data.append(count[last])
                last = days
    y_data.append(count[last])
    
    x = np.array(x_data)
    y = np.array(y_data)
    # Make the plot
    fig, ax = plt.subplots()
    ax.plot(x, y)
    #ax.fill_between(x, 0, y, alpha=.3)
    ax.set(xlim=(0, len(x) - 1), ylim=(0, None), xticks=x)
    """

    
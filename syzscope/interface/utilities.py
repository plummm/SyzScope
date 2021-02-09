import os, re, stat
import requests
import numpy as np
import json
import datetime

from bs4 import BeautifulSoup
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

NONCRITICAL = 0
AbMemRead = 1
AbMemWrite = 2
InvFree = 4

syzbot_bug_base_url = "bug?id="
syzbot_host_url = "https://syzkaller.appspot.com/"
kasan_uaf_regx = r'KASAN: use-after-free in ([a-zA-Z0-9_]+).*'
kasan_oob_regx = r'KASAN: \w+-out-of-bounds in ([a-zA-Z0-9_]+).*'
kasan_write_regx = r'KASAN: ([a-z\\-]+) Write in ([a-zA-Z0-9_]+).*'
kasan_read_regx = r'KASAN: ([a-z\\-]+) Read in ([a-zA-Z0-9_]+).*'
kasan_write_addr_regx = r'Write of size (\d+) at addr (\w+)'
kasan_read_addr_regx = r'Read of size (\d+) at addr (\w+)'
double_free_regx = r'KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
bug_desc_begin_regx = r'The buggy address belongs to the object at'
bug_desc_end_regx = r'The buggy address belongs to the page'
offset_desc_regx = r'The buggy address is located (\d+) bytes ((inside)|(to the right)|(to the left)) of'
size_desc_regx = r'which belongs to the cache [a-z0-9\-_]+ of size (\d+)'
kernel_func_def_regx= r'(^(static )?(__always_inline |const |inline )?(struct )?\w+( )?(\*)?( |\n)(([a-zA-Z0-9:_]*( |\n))?(\*)*)?([a-zA-Z0-9:_]+)\([a-zA-Z0-9*_,\(\)\[\]<>&\-\n\t ]*\))'
case_hash_syzbot_regx = r'https:\/\/syzkaller\.appspot\.com\/bug\?id=([a-z0-9]+)'
trace_regx = r'([A-Za-z0-9_.]+)(\+0x[0-9a-f]+\/0x[0-9a-f]+)? (([A-Za-z0-9_\-.]+\/)+[A-Za-z0-9_.\-]+:\d+)( \[inline\])?'

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

def regx_getall(regx, line):
    m = re.findall(regx, line, re.MULTILINE)
    return m

def is_trace(line):
    return regx_match(trace_regx, line)

def regx_kasan_line(line):
    m = re.search(trace_regx, line)
    if m != None:
        return m.groups()
    return None

def extract_debug_info(line):
    res = regx_kasan_line(line)
    if res == None:
        return res
    return res[2]

def isInline(line):
    res = regx_kasan_line(line)
    if res == None:
        return False
    if res[4] != None:
        return True
    return False

def extract_func_name(line):
    res = regx_kasan_line(line)
    if res == None:
        return res
    func = strip_part_funcs(res[0])
    return func

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

def only_kasan_calltrace(report):
    ret = []
    record_flag = 0
    for line in report:
        if record_flag:
            ret.append(line)
        if regx_match(kasan_oob_regx, line) or regx_match(kasan_uaf_regx, line):
            record_flag = 1
    if ret == []:
        ret = report
    return ret
    
def extrace_call_trace(report):
    regs_regx = r'[A-Z0-9]+:( )+[a-z0-9]+'
    implicit_call_regx = r'\[.+\]  \?.*'
    fs_regx = r'FS-Cache:'
    ignore_func_regx = r'__(read|write)_once'
    call_trace_end = [r"entry_SYSENTER", r"entry_SYSCALL", r"ret_from_fork", r"bpf_prog_[a-z0-9]{16}\+", r"Allocated by"]
    exceptions = [" <IRQ>", " </IRQ>"]
    res = []
    record_flag = 0
    for line in report:
        line = line.strip('\n')
        if record_flag and is_trace(line):
            """not regx_match(implicit_call_regx, line) and \
            not regx_match(regs_regx, line) and \
            not regx_match(fs_regx, line) and \
            not regx_match(ignore_func_regx, line) and \
            not line in exceptions:"""
            res.append(line)
            """
            I cannot believe we do have a calltrace starting without dump_stack like this:

            __read_once_size include/linux/compiler.h:199 [inline]
            arch_atomic_read arch/x86/include/asm/atomic.h:31 [inline]
            atomic_read include/asm-generic/atomic-instrumented.h:27 [inline]
            dump_stack+0x152/0x1ca lib/dump_stack.c:114
            print_address_description.constprop.0.cold+0xd4/0x30b mm/kasan/report.c:375
            __kasan_report.cold+0x1b/0x41 mm/kasan/report.c:507
            kasan_report+0xc/0x10 mm/kasan/common.c:641
            """
            if is_kasan_func(extract_debug_info(line)):
                res = []
        if regx_match(r'Call Trace', line):
            record_flag = 1
            res = []
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
    rel_type = -1
    offset = None
    size = None
    bug_desc = extract_bug_description(report)
    bug_type = extract_bug_type(report)
    bug_mem_addr = extract_bug_mem_addr(report)
    if bug_mem_addr == None:
        #print("Failed to locate the memory address that trigger UAF/OOB")
        return offset, size
    if bug_type == KASAN_NONE:
        return offset, size
    if bug_type == KASAN_UAF or bug_type == KASAN_OOB:
        for line in bug_desc:
            if offset == None:
                offset = regx_get(offset_desc_regx, line, 0)
                if offset != None:
                    offset = int(offset)
                    if regx_match(r'inside', line):
                        rel_type = 0
                    if regx_match(r'to the right', line):
                        rel_type = 1
                    if regx_match(r'to the left', line):
                        rel_type = 2
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

def strip_part_funcs(func):
    l = func.split('.')
    return l[0]

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

def get_case_from_file(path, workdir, folder=[]):
    res = []
    with open(path, 'r') as f:
        text = f.readlines()
        for line in text:
            line = line.strip('\n')
            case_path = None
            for each_folder in folder:
                if os.path.isdir('{}/{}/{}'.format(workdir, each_folder, line)):
                    case_path = '{}/{}/{}'.format(workdir, each_folder, line)
                    break
            with open(case_path+'/log', 'r') as f_log:
                line = f_log.readline()
                case_hash = regx_get(case_hash_syzbot_regx, line, 0)
                if case_hash != None:
                    res.append(case_hash)
                else:
                    print("No hash found on case: {}".format(case_hash))
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

def calculate_patch_info(each):
    if 'Patch' in each:
        r = request_get(each['Patch'])
        soup = BeautifulSoup(r.text, "html.parser")
        commit_info = soup.find_all('table', {'class': 'commit-info'})
        if len(commit_info) > 0:
            try:
                commit_date_time_str = commit_info[0].contents[1].contents[2].contents[0]
                merge_date_time_str = commit_info[0].contents[3].contents[2].contents[0]
            except:
                print(each, 'has no valid commit date')
                return None
            import datetime
            from dateutil.tz import UTC
            commit_date_time_obj = datetime.datetime.strptime(commit_date_time_str, '%Y-%m-%d %H:%M:%S %z').astimezone(UTC)
            merge_date_time_obj = datetime.datetime.strptime(merge_date_time_str, '%Y-%m-%d %H:%M:%S %z').astimezone(UTC)
            patched_commit = datetime.datetime.today().astimezone(UTC) - commit_date_time_obj
            patched_merge = datetime.datetime.today().astimezone(UTC) - merge_date_time_obj
            reported = regx_get(r'(\d+)d', each['Reported'], 0)
            if reported == None:
                return None
            reported = int(reported)
            if reported > patched_commit.days:
                each['days_patch_commit'] = reported - patched_commit.days
            else:
                each['days_patch_commit'] = -1
            if reported > patched_merge.days:
                each['days_patch_merge'] = reported - patched_merge.days
            else:
                each['days_patch_merge'] = -1
            if each['days_patch_commit']>each['days_patch_merge']:
                return None
            return each
    return None

def save_cases_as_json(key, max_num):
    import importlib.util
    pwd = os.getcwd()
    spec = importlib.util.spec_from_file_location("syzbotCrawler", pwd+"/syzscope/modules/syzbotCrawler.py")
    foo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(foo)
    foo.Crawler()
    crawler = foo.Crawler(keyword=key, max_retrieve=max_num, debug=True)
    cases = crawler.gather_cases()
    with open(pwd+'/cases_{}.json'.format("-".join(key)), 'w') as f:
        for each in cases:
            #new_each = calculate_patch_info(each)
            #if new_each == None:
            #    continue
            json.dump(each, f)
            f.write('\n')
    return cases

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
    try:
        a = case['days_patch_merge']
    except:
        print(case['Title'])
    return case['days_patch_merge']

def percentage_of_each_bug(crashes):
    bug_types = ['use-after-free Write', 'use-after-free Read', 'out-of-bounds Write', 'out-of-bounds Read',
                 'invalid-free', 'null-ptr-deref', 'WARNING', 'INFO', 'general protection fault', 'KMSAN',
                 'possible deadlock',
                 'KCSAN', 'BUG', 'memory leak', 'inconsistent lock state', 'suspicious RCU usage', 'kernel-infoleak',
                 'divide error']
    n = {}
    rest = []
    print(len(crashes))
    for type in bug_types:
        n[type] = 0
    for each in crashes:
        found = False
        for type in bug_types:
            if type in each['Title']:
                n[type] += 1
                found = True
                break
        if not found:
            rest.append(each['Title'])
    for type in bug_types:
        print(type, n[type], str(n[type] / len(crashes) * 100) + "%")
    for each in rest:
        print(each)

def type_of_bug(title, bug_types):
    for each in bug_types:
        if each in title:
            return each
    return None

def get_median_average(sorted_cases, keyword, bug_name=None):
    d = 0
    n = 0
    p = {}
    unduplicated = []
    median = 0
    if bug_name == None:
        keys = []
    else:
        keys = bug_name.split(' && ')
    for i in range(0, len(sorted_cases)):
        if sorted_cases[i]['Patch'] not in p:
            same_type = True
            for j in range(0, len(keys)):
                key = keys[j]
                if key in sorted_cases[i]['Title']:
                    break
                if j == len(keys) - 1:
                    same_type = False
            if not same_type:
                continue
            n += 1
            d += sorted_cases[i][keyword]
            p[sorted_cases[i]['Patch']] = 1
            unduplicated.append(sorted_cases[i])
    median = unduplicated[len(unduplicated) // 2][keyword]
    average = d / n
    return median, average, unduplicated

def duplicated_warning():
    p = '/home/xzou017/projects/results_of_syzbot_analysis/WARNING_LATEST/'
    l = get_case_from_file(p+'/ConfirmedAbnormallyMemWrite', p)
    uni_l1 = unique(l)
    l = get_case_from_file(p+'/ConfirmedAbnormallyMemRead', p)
    uni_l2 = unique(l)
    uni_l2.extend(uni_l1)

    patch2case = {}
    #cases = save_cases_as_json([''], 999999)
    cases = load_cases_from_json(os.getcwd()+'/cases_.json')
    for each in cases:
        if 'Patch' not in each:
            continue
        patch = each['Patch']
        if patch not in patch2case:
            patch2case[patch] = []
        patch2case[patch].append(each)
    for each_hash in uni_l2:
        for each_case in cases:
            if each_hash == each_case['Hash']:
                if 'Patch' not in each_case:
                    continue
                patch = each_case['Patch']
                for dup in patch2case[patch]:
                    if 'use-after-free' in dup['Title'] or 'out-of-bounds' in dup or 'double-free' in dup:
                        print(each_hash, dup['Title'])

if __name__ == '__main__':
    #cases = save_cases_as_json([''], 999999)
    """
    cases = load_cases_from_json(os.getcwd()+'/cases_.json')
    meta = [30, 60, 90, 182, 365, 730, 1000,9999]
    index = 0
    for i in range(0, len(cases)):
        case = cases[i]
        reported_days = case['Reported']
        day = int(regx_get('(\d+)d', reported_days, 0))
        if day > meta[index]:
            print("{} days with {} bugs: {} bugs/day".format(day, i, round(i/day, 2)))
            if index+1 < len(meta):
                index += 1
    reported_days = cases[len(cases)-1]['Reported']
    day = int(regx_get('(\d+)d', reported_days, 0))
    print("{} days with {} bugs: {} bugs/day".format(day, len(cases), round(len(cases)/day, 2)))
    """
    base = '/home/xzou017/projects/crashReproduce/work/succeed'
    files = os.listdir(base)
    for each in files:
        r = get_hash_from_log(os.path.join(base, '{}/log'.format(each)))
        print(r)
    

    
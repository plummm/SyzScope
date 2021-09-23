import argparse, os, stat, sys
from queue import Empty
import json
import multiprocessing, threading
import gc

sys.path.append(os.getcwd())
from syzscope.modules import Crawler, Deployer
from subprocess import call
from syzscope.interface.utilities import urlsOfCases, urlsOfCases, FOLDER, CASE

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Analyze crash cases from syzbot\n'
                                                 'eg. python syzscope -i 7fd1cbe3e1d2b3f0366d5026854ee5754d451405\n'
                                                 'eg. python syzscope -k="slab-out-of-bounds Read" -k="slab-out-of-bounds Write"')
    parser.add_argument('-i', '--input', nargs='?', action='store',
                        help='The input should be a valid hash or a file contains multiple hashs. -u, -m ,and -k will be ignored if -i is enabled.')
    parser.add_argument('-u', '--url', nargs='?', action='store',
                        default="https://syzkaller.appspot.com/upstream/fixed",
                        help='Indicate an URL for automatically crawling and running.\n'
                             '(default value is \'https://syzkaller.appspot.com/upstream/fixed\')')
    parser.add_argument('-m', '--max', nargs='?', action='store',
                        default='9999',
                        help='The maximum of cases for retrieving\n'
                             '(By default all the cases will be retrieved)')
    parser.add_argument('-k', '--key', action='append',
                        help='The keywords for detecting cases.\n'
                             '(By default, it retrieve all cases)\n'
                             'This argument could be multiple values')
    parser.add_argument('-de', '--deduplicate', action='append',
                        help='The keywords for deduplicating.\n'
                             'eg. -de="use-after-free" will ignore cases that already had "use-after-free" contexts\n'
                             'This argument could be multiple values')
    parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                        default='1', help='The maximum of parallel processes\n'
                                        '(default valus is 1)')
    parser.add_argument('--force', action='store_true',
                        help='Force to run all cases even it has finished\n')
    parser.add_argument('--linux', nargs='?', action='store',
                        default='-1',
                        help='Indicate which linux repo to be used for running\n'
                            '(--parallel-max will be set to 1)')
    parser.add_argument('-r', '--replay', choices=['succeed', 'completed', 'incomplete', 'error'],
                        help='Replay crashes of each case in one directory')
    parser.add_argument('--ssh', nargs='?',
                        default='33777',
                        help='The default port of ssh using by QEMU\n'
                        '(default value is 33777)')
    parser.add_argument('--ignore', nargs='?', action='store',
                        help='A file contains cases hashs which are ignored. One line for each hash.')
    parser.add_argument('--ignore-batch', nargs='?', action='store',
                        help='A file contains cases hashs which are ignored. This argument will ignore all other cases share the same patch')
    parser.add_argument('--alert', nargs='*', action='store',
                        default=[''],
                        help='Set alert for specific crash description')
    parser.add_argument('-KF', '--kernel-fuzzing',
                        action='store_true',
                        help='Enable kernel fuzzing and reproducing the original impact')
    parser.add_argument('-RP', '--reproduce',
                        action='store_true',
                        help='Enable reproducing the original impact separatly')
    parser.add_argument('-SA', '--static-analysis',
                        action='store_true',
                        help='Enable static analysis separatly')
    parser.add_argument('-SE', '--symbolic-execution',
                        action='store_true',
                        help='Enable symbolic execution separatly')
    parser.add_argument('-DV', '--dynamic-validation',
                        action='store_true',
                        help='Enable symbolic execution separatly')
    parser.add_argument('--guided',
                        action='store_true',
                        help='Enable path guided symbolic execution')
    parser.add_argument('--use-cache',
                        action='store_true',
                        help='Read cases from cache, this will overwrite the --input feild')
    parser.add_argument('--gdb', nargs='?',
                        default='1235',
                        help='Default gdb port for attaching')
    parser.add_argument('--qemu-monitor', nargs='?',
                        default='9700',
                        help='Default port of qemu monitor')
    parser.add_argument('-M', '--max-compiling-kernel-concurrently', nargs='?',
                        default='-1',
                        help='maximum of kernel that compiling at the same time. Default is unlimited.')
    parser.add_argument('--filter-by-reported', nargs='?',
                        default='-1',
                        help='filter bugs by the days they were reported\n')
    parser.add_argument('--filter-by-closed', nargs='?',
                        default='-1',
                        help='filter bugs by the days they were closed\n')
    parser.add_argument('--timeout-kernel-fuzzing', nargs='?',
                        default='3',
                        help='Timeout for kernel fuzzing(by hour)\n'
                        'default timeout is 3 hour')
    parser.add_argument('--timeout-dynamic-validation', nargs='?',
                        help='The timeout(by second) of static analysis and symbolic execution\n'
                            'If you specify the timeout of static analysis or symbolic execution individually\n'
                            'the the rest time is for the other one\n'
                            'If you specify the timeout of both static analysis or symbolic execution'
                            'This arugment will be ignored'
                            'Default timeout is 60 mins')
    parser.add_argument('--timeout-static-analysis', nargs='?',
                        help='The timeout(by second) of static analysis\n'
                            'Default timeout is 30 mins')
    parser.add_argument('--timeout-symbolic-execution', nargs='?',
                        help='The timeout(by second) of symbolic execution\n'
                            'Default timeout is (timeout_dynamic_validation - timeout_static_analysis)')
    parser.add_argument('--get-hash', nargs='?',
                        help='Get the hash of cases\n'
                            'eg. work/completed')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    parser.add_argument('--be-bully', action='store_true',
                        help="Being a bully will kill the proc that occupies the port")
    parser.add_argument('--SE-PoC', nargs='?', action='store',
                        help='The path to a PoC that will be used by symbolic execution')
    parser.add_argument('--include-high-risk', action='store_true',
                        help='Include high risk bugs for analysis')
    parser.add_argument('--install-requirements', action='store_true',
                        help='Install required packages and compile essential tools')

    args = parser.parse_args()
    return args

def print_args_info(args):
    print("[*] hash: {}".format(args.input))
    print("[*] url: {}".format(args.url))
    print("[*] max: {}".format(args.max))
    print("[*] key: {}".format(args.key))
    print("[*] deduplicate: {}".format(args.deduplicate))
    print("[*] alert: {}".format(args.alert))

    try:
        int(args.ssh)
    except:
        print("[-] invalid argument value ssh: {}".format(args.ssh))
        os._exit(1)
    
    try:
        int(args.linux)
    except:
        print("[-] invalid argument value linux: {}".format(args.linux))
        os._exit(1)
    
    try:
        int(args.timeout_kernel_fuzzing)
    except:
        print("[-] invalid argument value time: {}".format(args.timeout_kernel_fuzzing))
        os._exit(1)

def check_kvm():
    proj_path = os.path.join(os.getcwd(), "syzscope")
    check_kvm_path = os.path.join(proj_path, "scripts/check_kvm.sh")
    st = os.stat(check_kvm_path)
    os.chmod(check_kvm_path, st.st_mode | stat.S_IEXEC)
    r = call([check_kvm_path], shell=False)
    if r == 1:
        exit(0)

def cache_cases(cases):
    work_path = os.getcwd()
    cases_json_path = os.path.join(work_path, "work/cases.json")
    with open(cases_json_path, 'w') as f:
        json.dump(cases, f)
        f.close()

def read_cases_from_cache():
    cases = {}
    work_path = os.getcwd()
    cases_json_path = os.path.join(work_path, "work/cases.json")
    if os.path.exists(cases_json_path):
        with open(cases_json_path, 'r') as f:
            cases = json.load(f)
            f.close()
    return cases

def deploy_one_case(index, args, hash_val):
    case = crawler.cases[hash_val]
    dp = Deployer(index=index, debug=args.debug, force=args.force, port=int(args.ssh), replay=args.replay, \
                linux_index=int(args.linux), time=int(args.timeout_kernel_fuzzing), kernel_fuzzing=args.kernel_fuzzing, reproduce= args.reproduce, alert=args.alert, \
                static_analysis=args.static_analysis, symbolic_execution=args.symbolic_execution, gdb_port=int(args.gdb), \
                qemu_monitor_port=int(args.qemu_monitor), max_compiling_kernel=int(args.max_compiling_kernel_concurrently), \
                timeout_dynamic_validation=args.timeout_dynamic_validation, timeout_static_analysis=args.timeout_static_analysis, \
                timeout_symbolic_execution=args.timeout_symbolic_execution, parallel_max=int(args.parallel_max), \
                guided=args.guided, be_bully=args.be_bully, se_poc=args.SE_PoC)
    dp.deploy(hash_val, case)
    del dp

def prepare_cases(index, args):
    while(1):
        lock.acquire(blocking=True)
        try:
            hash_val = g_cases.get(block=True, timeout=3)
            if hash_val in ignore:
                rest.value -= 1
                lock.release()
                continue
            print("Thread {}: run case {} [{}/{}] left".format(index, hash_val, rest.value-1, total))
            rest.value -= 1
            lock.release()
            x = multiprocessing.Process(target=deploy_one_case, args=(index, args, hash_val,), name="lord-{}".format(i))
            x.start()
            x.join()
            gc.collect()
            remove_using_flag(index)
        except Empty:
            lock.release()
            break
    print("Thread {} exit->".format(index))

def get_hash(path):
    ret = []
    log_path = os.path.join(path, "log")
    if os.path.exists(log_path):
        ret=urlsOfCases(path, CASE)
    else:
        ret=urlsOfCases(path, FOLDER)
    print("The hash of {}".format(path))
    for each in ret:
        print(each)

def remove_using_flag(index):
    project_path = os.getcwd()
    flag_path = "{}/tools/linux-{}/THIS_KERNEL_IS_BEING_USED".format(project_path,index)
    if os.path.isfile(flag_path):
        os.remove(flag_path)

def install_requirments():
    proj_path = os.path.join(os.getcwd(), "syzscope")
    requirements_path = os.path.join(proj_path, "scripts/requirements.sh")
    st = os.stat(requirements_path)
    os.chmod(requirements_path, st.st_mode | stat.S_IEXEC)
    return call([requirements_path], shell=False)

def check_requirements():
    tools_path = os.path.join(os.getcwd(), "tools")
    env_stamp = os.path.join(tools_path, ".stamp/ENV_SETUP")
    return os.path.isfile(env_stamp)

def build_work_dir():
    work_path = os.path.join(os.getcwd(), "work")
    os.makedirs(work_path, exist_ok=True)
    incomp = os.path.join(os.getcwd(), "incomplete")
    comp = os.path.join(os.getcwd(), "completed")
    os.makedirs(incomp, exist_ok=True)
    os.makedirs(comp, exist_ok=True)

def args_dependencies():
    if args.debug:
        print("debug mode runs on single thread")
        args.parallel_max = '1'
    if args.linux != '-1':
        print("specifying a linux repo runs on single thread")
        args.parallel_max = '1'

if __name__ == '__main__':
    args = args_parse()
    if args.key == None:
        args.key = ['']
    if args.deduplicate == None:
        args.deduplicate = []
    if args.install_requirements:
        if install_requirments() != 0:
            print("Fail to install requirements.")
        exit(0)
    elif not check_requirements():
        print("No essential components found. Install them by --install-requirements")
        exit(0)

    print_args_info(args)
    check_kvm()
    args_dependencies()

    if args.get_hash != None:
        get_hash(args.get_hash)
        sys.exit(0)

    ignore = []
    build_work_dir()
    manager = multiprocessing.Manager()
    if args.ignore != None:
        with open(args.ignore, "r") as f:
            text = f.readlines()
            for line in text:
                line = line.strip('\n')
                ignore.append(line)
    ignore_batch = []
    if args.ignore_batch != None:
        with open(args.ignore_batch, "r") as f:
            text = f.readlines()
            for line in text:
                line = line.strip('\n')
                ignore_batch.append(line)
    if args.input != None and args.use_cache:
        print("Can not use cache when specifying inputs")
        sys.exit(1)
    crawler = Crawler(url=args.url, keyword=args.key, max_retrieve=int(args.max), deduplicate=args.deduplicate, ignore_batch=ignore_batch,
        filter_by_reported=int(args.filter_by_reported), filter_by_closed=int(args.filter_by_closed), include_high_risk=args.include_high_risk, debug=args.debug)
    if args.replay != None:
        for url in urlsOfCases(args.replay):
            crawler.run_one_case(url)
    elif args.input != None:
        if len(args.input) == 40:
            crawler.run_one_case(args.input)
        else:
            with open(args.input, 'r') as f:
                text = f.readlines()
                for line in text:
                    line = line.strip('\n')
                    crawler.run_one_case(line)
    else:
        if args.use_cache:
            crawler.cases = read_cases_from_cache()
        else:
            crawler.run()
    if not args.use_cache:
        cache_cases(crawler.cases)
    if args.dynamic_validation:
        args.symbolic_execution = True
        args.static_analysis = True
    parallel_max = int(args.parallel_max)
    parallel_count = 0
    lock = threading.Lock()
    g_cases = manager.Queue()
    for key in crawler.cases:
        g_cases.put(key)
    #g_cases = manager.list([crawler.cases[x] for x in crawler.cases])
    l = list(crawler.cases.keys())
    total = len(l)
    rest = manager.Value('i', total)
    for i in range(0,min(parallel_max,total)):
        x = threading.Thread(target=prepare_cases, args=(i, args,), name="lord-{}".format(i))
        x.start()
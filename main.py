from syzbotCrawler import Crawler
from deploy import Deployer
from subprocess import call
from utilities import urlsOfCases

import argparse, os, stat
import threading, re

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Analyze crash cases from syzbot\n'
                                                 'eg. python main.py -i 7fd1cbe3e1d2b3f0366d5026854ee5754d451405\n'
                                                 'eg. python main.py -k "slab-out-of-bounds Read" "slab-out-of-bounds Write"')
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
    parser.add_argument('-k', '--key', nargs='*', action='store',
                        default=[''],
                        help='The keywords for detecting cases.\n'
                             '(By default, it retrieve all cases)\n'
                             'This argument could be multiple values')
    parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                        default='5', help='The maximum of parallel processes\n'
                                        '(default valus is 5)')
    parser.add_argument('--force', action='store_true',
                        help='Force to run all cases even it has finished\n')
    parser.add_argument('--linux', nargs='?', action='store',
                        default='-1',
                        help='Indicate which linux repo to be used for running\n'
                            '(--parallel-max will be set to 1)')
    parser.add_argument('-r', '--replay', choices=['succeed', 'completed', 'incomplete', 'error'],
                        help='Replay crashes of each case in one directory')
    parser.add_argument('-sp', '--syzkaller-port', nargs='?',
                        default='53777',
                        help='The default port that is used by syzkaller\n'
                        '(default value is 53777)')
    parser.add_argument('--ignore', nargs='?', action='store',
                        help='A file contains cases hashs which are ignored. One line for each hash.')
    parser.add_argument('--alert', nargs='*', action='store',
                        default=[''],
                        help='Set alert for specific crash description')
    parser.add_argument('-t', '--time', nargs='?',
                        default='8',
                        help='Time for each running(in hour)\n'
                        '(default value is 8 hour)')
    parser.add_argument('-ff', '--force-fuzz',
                        action='store_true',
                        help='Force to do fuzzing even detect write without mutating')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')

    args = parser.parse_args()
    return args

def print_args_info(args):
    print("[*] hash: {}".format(args.input))
    print("[*] url: {}".format(args.url))
    print("[*] max: {}".format(args.max))
    print("[*] key: {}".format(args.key))
    print("[*] alert: {}".format(args.alert))

def check_kvm():
    st = os.stat("scripts/check_kvm.sh")
    os.chmod("scripts/check_kvm.sh", st.st_mode | stat.S_IEXEC)
    r = call(['scripts/check_kvm.sh'], shell=False)
    if r == 1:
        exit(0)

def deploy_one_case(index):
    while(1):
        lock.acquire(blocking=True)
        l = list(crawler.cases.keys())
        if len(l) == 0:
            lock.release()
            break
        hash = l[0]
        case = crawler.cases.pop(hash)
        lock.release()
        if hash in ignore:
            continue
        print("Thread {}: run case {} [{}/{}] left".format(index, hash, len(l)-1, total))
        deployer[index].deploy(hash, case)
        remove_using_flag(index)
    print("Thread {} exit->".format(index))

def remove_using_flag(index):
    project_path = os.getcwd()
    flag_path = "{}/tools/linux-{}/THIS_KERNEL_IS_BEING_USED".format(project_path,index)
    if os.path.isfile(flag_path):
        os.remove(flag_path)

def install_requirments():
    st = os.stat("scripts/requirements.sh")
    os.chmod("scripts/requirements.sh", st.st_mode | stat.S_IEXEC)
    call(['scripts/requirements.sh'], shell=False)

def args_dependencies():
    if args.debug:
        args.parallel_max = '1'
    if args.linux != '-1':
        args.parallel_max = '1'

if __name__ == '__main__':
    args = args_parse()
    print_args_info(args)
    check_kvm()
    args_dependencies()

    ignore = []
    if args.ignore != None:
        with open(args.ignore, "r") as f:
            text = f.readlines()
            for line in text:
                line = line.strip('\n')
                ignore.append(line)

    crawler = Crawler(url=args.url, keyword=args.key, max_retrieve=int(args.max), debug=args.debug)
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
        crawler.run()
    install_requirments()
    deployer = []
    parallel_max = int(args.parallel_max)
    parallel_count = 0
    lock = threading.Lock()
    l = list(crawler.cases.keys())
    total = len(l)
    for i in range(0,min(parallel_max,len(crawler.cases))):
        deployer.append(Deployer(i, args.debug, args.force, int(args.syzkaller_port), args.replay, int(args.linux), int(args.time), args.force_fuzz, args.alert))
        x = threading.Thread(target=deploy_one_case, args=(i,))
        x.start()
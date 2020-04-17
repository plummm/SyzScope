from syzbotCrawler import Crawler
from deploy import Deployer
from subprocess import call

import argparse, os, stat
import threading

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Analyze crash cases from syzbot\n'
                                                 'eg. python main.py -i 7fd1cbe3e1d2b3f0366d5026854ee5754d451405\n'
                                                 'eg. python main.py -k "slab-out-of-bounds Read" "slab-out-of-bounds Write"')
    parser.add_argument('-i', '--input', nargs='?', action='store',
                        help='Directly run a case by it\'s hash. -u, -m ,and -k will be ignored if -i is enabled.')
    parser.add_argument('-u', '--url', nargs='?', action='store',
                        default="https://syzkaller.appspot.com/upstream/fixed",
                        help='Indicate an URL for automatically crawling and running.\n'
                             '(default value is \'https://syzkaller.appspot.com/upstream/fixed\')')
    parser.add_argument('-m', '--max', nargs='?', action='store',
                        default=30,
                        help='The maximum of cases for retrieving\n'
                             '(default value is 10)')
    parser.add_argument('-k', '--key', nargs='*', action='store',
                        default=['slab-out-of-bounds Read'],
                        help='The keywords for detecting cases.\n'
                             '(default value is \'slab-out-of-bounds Read\')\n'
                             'This argument could be multiple values')
    parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                        default=5, help='The maximum of parallel processes')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')

    args = parser.parse_args()
    return args

def print_args_info(args):
    print("[*] hash: {}".format(args.input))
    print("[*] url: {}".format(args.url))
    print("[*] max: {}".format(args.max))
    print("[*] key: {}".format(args.key))

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
            return
        hash = l[0]
        case = crawler.cases.pop(hash)
        lock.release()
        deployer[index].deploy(hash, case)

def install_packages():
    st = os.stat("scripts/install.sh")
    os.chmod("scripts/install.sh", st.st_mode | stat.S_IEXEC)
    call(['scripts/install.sh'], shell=False)

if __name__ == '__main__':
    args = args_parse()
    print_args_info(args)
    check_kvm()
    crawler = Crawler(url=args.url, keyword=args.key, max_retrieve=int(args.max), debug=args.debug)
    if args.input != None:
        crawler.run_one_case(args.input)
        args.parallel_max = 1
    else:
        crawler.run()
    install_packages()
    deployer = []
    parallel_max = args.parallel_max
    parallel_count = 0
    if args.debug:
        parallel_max = 1
    lock = threading.Lock()
    for i in range(0,min(parallel_max,int(args.max))):
        deployer.append(Deployer(i, args.debug))
        x = threading.Thread(target=deploy_one_case, args=(i,))
        x.start()
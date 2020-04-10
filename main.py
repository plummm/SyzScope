from syzbotCrawler import Crawler
from deploy import Deployer

import argparse

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Analyze crash cases from syzbot\n'
                                                 'eg. python main.py -i 7fd1cbe3e1d2b3f0366d5026854ee5754d451405 -m 5\n'
                                                 'eg. python main.py -k "slab-out-of-bounds Read" "slab-out-of-bounds Write"')
    parser.add_argument('-i', '--input', nargs='?', action='store',
                        help='Directly run a case by it\'s hash. -u/--url will be ignored if -i is enabled.')
    parser.add_argument('-u', '--url', nargs='?', action='store',
                        default="https://syzkaller.appspot.com/upstream/fixed",
                        help='Indicate an URL for automatically crawling and running. This argument will be ignored if -i/--input is enabled.\n'
                             '(default value is \'https://syzkaller.appspot.com/upstream/fixed\')')
    parser.add_argument('-m', '--max', nargs='?', action='store',
                        default=10,
                        help='The maximum of cases for running\n'
                             '(default value is 10)')
    parser.add_argument('-k', '--key', nargs='*', action='store',
                        default=['slab-out-of-bounds Read'],
                        help='The keywords for detecting cases.\n'
                             '(default value is \'slab-out-of-bounds Read\')\n'
                             'This argument could be multiple values')
    #parser.add_argument('--help', action='help')

    args = parser.parse_args()
    return args

def print_args_info(args):
    print("[*] hash: {}".format(args.input))
    print("[*] url: {}".format(args.url))
    print("[*] max: {}".format(args.max))
    print("[*] key: {}".format(args.key))

if __name__ == '__main__':
    args = args_parse()
    print_args_info(args)
    crawler = Crawler(url=args.url, keyword=args.key, max_retrieve=int(args.max))
    if args.input != None:
        crawler.retreive_case(args.input)
    else:
        crawler.run()
    deployer = Deployer()
    deployer.deploy(crawler.cases)
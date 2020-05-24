import requests
import logging
import os
import re

from bs4 import BeautifulSoup
from bs4 import element

syzbot_bug_base_url = "bug?id="
syzbot_host_url = "https://syzkaller.appspot.com/"
num_of_elements = 8

class Crawler:
    def __init__(self,
                 url="https://syzkaller.appspot.com/upstream/fixed",
                 keyword=['slab-out-of-bounds Read'],
                 max_retrieve=10, debug=False):
        self.url = url
        self.keyword = keyword
        self.max_retrieve = max_retrieve
        self.cases = {}
        self.patches = {}
        self.logger = None
        self.logger2file = None
        self.init_logger(debug)

    def init_logger(self, debug):
        handler = logging.FileHandler("{}/info".format(os.getcwd()))
        format =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(format)
        self.logger = logging.getLogger(__name__)
        self.logger2file = logging.getLogger("log2file")
        if debug:
            self.logger.setLevel(logging.DEBUG)
            self.logger2file.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
            self.logger2file.setLevel(logging.INFO)
        self.logger2file.addHandler(handler)

    def run(self):
        cases_hash = self.gather_cases()
        for hash in cases_hash:
            self.retreive_case(hash)

    def run_one_case(self, hash):
        self.logger.info("retreive one case: %s",hash)
        self.cases[hash] = {}
        self.retreive_case(hash)
    
    def get_patch_commit(self, hash):
        url = syzbot_host_url + syzbot_bug_base_url + hash
        req = requests.request(method='GET', url=url)
        soup = BeautifulSoup(req.text, "html.parser")
        try:
            fix = soup.body.span.contents[1]
            url = fix.attrs['href']
            m = re.search(r'id=(\w*)', url)
            if m != None and m.groups() != None:
                res = m.groups()[0]
        except:
            res=None
        return res
    
    def get_title_of_case(self, hash=None, text=None):
        if hash==None and text==None:
            self.logger.info("No case given")
            return None
        if hash!=None:
            url = syzbot_host_url + syzbot_bug_base_url + hash
            req = requests.request(method='GET', url=url)
            soup = BeautifulSoup(req.text, "html.parser")
        else:
            soup = BeautifulSoup(text, "html.parser")
        title = soup.body.b.contents[0]
        return title

    def retreive_case(self, hash):
        detail = self.request_detail(hash)
        if len(detail) < num_of_elements:
            self.logger.error("Failed to get detail of a case {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
            self.cases.pop(hash)
            return -1
        self.cases[hash]["commit"] = detail[0]
        self.cases[hash]["syzkaller"] = detail[1]
        self.cases[hash]["config"] = detail[2]
        self.cases[hash]["syz_repro"] = detail[3]
        self.cases[hash]["log"] = detail[4]
        self.cases[hash]["c_repro"] = detail[5]
        self.cases[hash]["time"] = detail[6]
        self.cases[hash]["manager"] = detail[7]
        self.cases[hash]["report"] = detail[8]

    def gather_cases(self):
        tables = self.__get_table(self.url)
        if tables == []:
            self.logger.error("error occur in gather_cases")
            return
        count = 0
        for table in tables:
            self.logger.info("table caption {}".format(table.caption.text))
            for case in table.tbody.contents:
                if type(case) == element.Tag:
                    title = case.find('td', {"class": "title"})
                    if title == None:
                        continue
                    for keyword in self.keyword:
                        if keyword in title.text:
                            commit_list = case.find('td', {"class": "commit_list"})
                            try:
                                patch_url = commit_list.contents[1].contents[1].attrs['href']
                                if patch_url in self.patches:
                                    break
                                self.patches[patch_url] = True
                            except:
                                # patch only works on fixed cases
                                pass
                            self.logger.debug("[{}] Find a suitable case: {}".format(count, title.text))
                            href = title.next.attrs['href']
                            hash = href[8:]
                            self.logger.debug("[{}] Fetch {}".format(count, hash))
                            self.cases[hash] = {}
                            count += 1
                    if count == self.max_retrieve:
                        break
        res = [x for x in self.cases]
        return res

    def request_detail(self, hash, index=1):
        self.logger.debug("\nDetail: {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
        url = syzbot_host_url + syzbot_bug_base_url + hash
        tables = self.__get_table(url)
        if tables == []:
            print("error occur in request_detail: {}".format(hash))
            self.logger2file.info("[Failed] {} error occur in request_detail".format(url))
            return []
        count = 0
        for table in tables:
            if table.caption.text.find('Crash') != -1:
                for case in table.tbody.contents:
                    if type(case) == element.Tag:
                        kernel = case.find('td', {"class": "kernel"})
                        if kernel.text != "upstream":
                            self.logger.debug("skip kernel: '{}'".format(kernel.text))
                            continue
                        count += 1
                        if count < index:
                            continue
                        try:
                            manager = case.find('td', {"class": "manager"})
                            manager_str = manager.text
                            time = case.find('td', {"class": "time"})
                            time_str = time.text
                            tags = case.find_all('td', {"class": "tag"})
                            m = re.search(r'id=([0-9a-z]*)', tags[0].next.attrs['href'])
                            commit = m.groups()[0]
                            self.logger.debug("Kernel commit: {}".format(commit))
                            m = re.search(r'commits\/([0-9a-z]*)', tags[1].next.attrs['href'])
                            syzkaller = m.groups()[0]
                            self.logger.debug("Syzkaller commit: {}".format(syzkaller))
                            config = syzbot_host_url + case.find('td', {"class": "config"}).next.attrs['href']
                            self.logger.debug("Config URL: {}".format(config))
                            repros = case.find_all('td', {"class": "repro"})
                            log = syzbot_host_url + repros[0].next.attrs['href']
                            self.logger.debug("Log URL: {}".format(log))
                            report = syzbot_host_url + repros[1].next.attrs['href']
                            self.logger.debug("Log URL: {}".format(report))
                            try:
                                syz_repro = syzbot_host_url + repros[2].next.attrs['href']
                                self.logger.debug("Testcase URL: {}".format(syz_repro))
                            except:
                                self.logger.info(
                                    "Repro is missing. Failed to retrieve case {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                                self.logger2file.info("[Failed] {} Repro is missing".format(url))
                                break
                            try:
                                c_repro = syzbot_host_url + repros[3].next.attrs['href']
                                self.logger.debug("C prog URL: {}".format(c_repro))
                            except:
                                c_repro = None
                                self.logger.info("No c prog found")
                        except:
                            self.logger.info("Failed to retrieve case {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            continue
                        return [commit, syzkaller, config, syz_repro, log, c_repro, time_str, manager_str, report]
                break
        self.logger2file.info("[Failed] {} fail to find a proper crash".format(url))
        return []

    def __get_table(self, url):
        self.logger.info("Get table from {}".format(url))
        req = requests.request(method='GET', url=url)
        soup = BeautifulSoup(req.text, "html.parser")
        tables = soup.find_all('table', {"class": "list_table"})
        if len(tables) == 0:
            print("Fail to retrieve bug cases from list_table")
            return []
        return tables

if __name__ == '__main__':
    crawler = Crawler()
    print(crawler.get_title_of_case("511d0a90ad65cf4ba840e4d1c2762326321bf62f"))
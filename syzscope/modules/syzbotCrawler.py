import requests
import logging
import os
import re

from syzscope.interface.utilities import request_get, extract_vul_obj_offset_and_size, regx_get
from bs4 import BeautifulSoup
from bs4 import element

syzbot_bug_base_url = "bug?id="
syzbot_host_url = "https://syzkaller.appspot.com/"
num_of_elements = 8

class Crawler:
    def __init__(self,
                 url="https://syzkaller.appspot.com/upstream/fixed",
                 keyword=[''], max_retrieve=10, filter_by_reported=-1, 
                 filter_by_closed=-1, include_high_risk=False, debug=False):
        self.url = url
        if type(keyword) == list:
            self.keyword = keyword
        else:
            print("keyword must be a list")
        self.max_retrieve = max_retrieve
        self.cases = {}
        self.patches = {}
        self.logger = None
        self.logger2file = None
        self.include_high_risk = include_high_risk
        self.init_logger(debug)
        self.filter_by_reported = filter_by_reported
        self.filter_by_closed = filter_by_closed

    def init_logger(self, debug):
        handler = logging.FileHandler("{}/info".format(os.getcwd()))
        format =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(format)
        self.logger = logging.getLogger(__name__)
        self.logger2file = logging.getLogger("log2file")
        if debug:
            self.logger.setLevel(logging.DEBUG)
            self.logger.propagate = True
            self.logger2file.setLevel(logging.DEBUG)
            self.logger2file.propagate = True
        else:
            self.logger.setLevel(logging.INFO)
            self.logger.propagate = False
            self.logger2file.setLevel(logging.INFO)
            self.logger2file.propagate = False
        self.logger2file.addHandler(handler)

    def run(self):
        cases_hash, high_risk_impacts = self.gather_cases()
        for each in cases_hash:
            if 'Patch' in each:
                patch_url = each['Patch']
                commit = regx_get(r"https:\/\/git\.kernel\.org\/pub\/scm\/linux\/kernel\/git\/torvalds\/linux\.git\/commit\/\?id=(\w+)", patch_url, 0)
                if commit in self.patches or \
                    (commit in high_risk_impacts and not self.include_high_risk):
                    continue
                self.patches[commit] = True
            if self.retreive_case(each['Hash']) != -1:
                self.cases[each['Hash']]['title'] = each['Title']
                if 'Patch' in each:
                    self.cases[each['Hash']]['patch'] = each['Patch']
        return

    def run_one_case(self, hash):
        self.logger.info("retreive one case: %s",hash)
        if self.retreive_case(hash) == -1:
            return
        self.cases[hash]['title'] = self.get_title_of_case(hash)
        patch = self.get_patch_of_case(hash)
        if patch != None:
            self.cases[hash]['patch'] = patch
    
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
    
    def get_patch_of_case(self, hash):
        patch = None
        url = syzbot_host_url + syzbot_bug_base_url + hash
        req = requests.request(method='GET', url=url)
        soup = BeautifulSoup(req.text, "html.parser")
        mono = soup.find("span", {"class": "mono"})
        if mono == None:
            return patch
        patch = mono.contents[1].contents[0]
        return patch


    def retreive_case(self, hash):
        self.cases[hash] = {}
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
        self.cases[hash]["vul_offset"] = detail[9]
        self.cases[hash]["obj_size"] = detail[10]

    def gather_cases(self):
        high_risk_impacts = {}
        res = []
        tables = self.__get_table(self.url)
        if tables == []:
            self.logger.error("error occur in gather_cases")
            return res, high_risk_impacts
        count = 0
        for table in tables:
            #self.logger.info("table caption {}".format(table.caption.text))
            for case in table.tbody.contents:
                if type(case) == element.Tag:
                    title = case.find('td', {"class": "title"})
                    if title == None:
                        continue
                    for keyword in self.keyword:
                        if 'out-of-bounds write' in title.text or \
                                'use-after-free write' in title.text:
                            commit_list = case.find('td', {"class": "commit_list"})
                            try:
                                patch_url = commit_list.contents[1].contents[1].attrs['href']
                                high_risk_impacts[patch_url] = True
                            except:
                                pass
                        if keyword in title.text or keyword=='':
                            crash = {}
                            commit_list = case.find('td', {"class": "commit_list"})
                            crash['Title'] = title.text
                            stats = case.find_all('td', {"class": "stat"})
                            crash['Repro'] = stats[0].text
                            crash['Bisected'] = stats[1].text
                            crash['Count'] = stats[2].text
                            crash['Last'] = stats[3].text
                            try:
                                crash['Reported'] = stats[4].text
                                if self.filter_by_reported > -1 and int(crash['Reported'][:-1]) > self.filter_by_reported:
                                    continue
                                patch_url = commit_list.contents[1].contents[1].attrs['href']
                                crash['Patch'] = patch_url
                                crash['Closed'] = stats[4].text
                                if self.filter_by_closed > -1 and int(crash['Closed'][:-1]) > self.filter_by_closed:
                                    continue
                            except:
                                # patch only works on fixed cases
                                pass
                            self.logger.debug("[{}] Find a suitable case: {}".format(count, title.text))
                            href = title.next.attrs['href']
                            hash_val = href[8:]
                            self.logger.debug("[{}] Fetch {}".format(count, hash_val))
                            crash['Hash'] = hash_val
                            res.append(crash)
                            count += 1
                            break
                    if count == self.max_retrieve:
                        break
        return res, high_risk_impacts

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
                            r = request_get(report)
                            report_list = r.text.split('\n')
                            offset, size = extract_vul_obj_offset_and_size(report_list)
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
                        return [commit, syzkaller, config, syz_repro, log, c_repro, time_str, manager_str, report, offset, size]
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
    pass
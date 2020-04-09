import requests

from bs4 import BeautifulSoup
from bs4 import element

syzbot_bug_base_url = "bug?id="
syzbot_host_url = "https://syzkaller.appspot.com/"

class Crawler:
    def __init__(self,
                 url="https://syzkaller.appspot.com/upstream/fixed",
                 keyword=['slab-out-of-bounds Read'],
                 max_retrieve=50):
        self.url = url
        self.keyword = keyword
        self.max_retrieve = max_retrieve
        self.cases = {}
        self.patches = {}

    def run(self):
        cases_hash = self.gather_cases()
        for hash in cases_hash:
            detail = self.request_detail(hash)
            if len(detail) < 4:
                print("Failed to get detail of a case {}".format(hash))
                return -1
            self.cases[hash]["commit"] = detail[0]
            self.cases[hash]["syzkaller"] = detail[1]
            self.cases[hash]["config"] = detail[2]
            self.cases[hash]["syz_repro"] = detail[3]

    def gather_cases(self):
        tables = self.__get_table(self.url)
        if tables == []:
            print("error occur in gather_cases")
            return
        count = 0
        table = tables[0]
        for case in table.tbody.contents:
            if type(case) == element.Tag:
                title = case.find('td', {"class": "title"})
                for keyword in self.keyword:
                    if keyword in title.text:
                        commit_list = case.find('td', {"class": "commit_list"})
                        patch_url = commit_list.contents[1].contents[1].attrs['href']
                        if patch_url in self.patches:
                            break
                        self.patches[patch_url] = True
                        count += 1
                        href = title.next.attrs['href']
                        hash = href[8:]
                        self.cases[hash] = {}
                if count == self.max_retrieve:
                    break
        res = [x for x in self.cases]
        return res

    def request_detail(self, hash):
        url = syzbot_host_url + syzbot_bug_base_url + hash
        tables = self.__get_table(url)
        if tables == []:
            print("error occur in request_detail")
            return
        for table in tables:
            if table.caption.text.find('Crash') != -1:
                for case in table.tbody.contents:
                    if type(case) == element.Tag:
                        tags = case.find_all('td', {"class": "tag"})
                        commit = tags[0].text
                        syzkaller = tags[1].text
                        config = syzbot_host_url + case.find('td', {"class": "config"}).next.attrs['href']
                        repros = case.find_all('td', {"class": "repro"})
                        syz_repro = syzbot_host_url + repros[2].next.attrs['href']
                        return [commit, syzkaller, config, syz_repro]
                break
        return []

    def __get_table(self, url):
        req = requests.request(method='GET', url=url)
        soup = BeautifulSoup(req.text, "html.parser")
        tables = soup.find_all('table', {"class": "list_table"})
        if len(tables) == 0:
            print("Fail to retrieve bug cases from list_table")
            return []
        return tables
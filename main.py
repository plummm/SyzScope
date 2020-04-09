from syzbotCrawler import Crawler
from deploy import Deployer

if __name__ == '__main__':
    crawler = Crawler(max_retrieve=5)
    crawler.run()
    deployer = Deployer()
    deployer.deploy(crawler.cases)
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl
import requests
import json


host = "https://192.168.1.1:8443" 
userName = ""
password = ""


blocklist_urls = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
  "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
  "http://sysctl.org/cameleon/hosts",
  "https://adblock.ee/list.php",
  "https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/KADhosts/hosts",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts",
  "https://v.firebog.net/hosts/static/w3kbl.txt",
  "https://adaway.org/hosts.txt",
  "https://v.firebog.net/hosts/AdguardDNS.txt",
  "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
  "https://v.firebog.net/hosts/Easylist.txt",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts",
  "https://v.firebog.net/hosts/Easyprivacy.txt",
  "https://v.firebog.net/hosts/Prigent-Ads.txt",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts",
  "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
  "https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",
  "https://v.firebog.net/hosts/Prigent-Malware.txt",
  "https://v.firebog.net/hosts/Prigent-Phishing.txt",
  "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt",
  "https://ransomwaretracker.abuse.ch/downloads/CW_C2_DOMBL.txt",
  "https://ransomwaretracker.abuse.ch/downloads/LY_C2_DOMBL.txt",
  "https://ransomwaretracker.abuse.ch/downloads/TC_C2_DOMBL.txt",
  "https://ransomwaretracker.abuse.ch/downloads/TL_C2_DOMBL.txt",
  "https://v.firebog.net/hosts/Shalla-mal.txt",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts",
  "https://dbl.oisd.nl/",
  "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
  "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
  "https://v.firebog.net/hosts/Admiral.txt",
  "https://urlhaus.abuse.ch/downloads/hostfile/",
  "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
  "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
  "https://phishing.army/download/phishing_army_blocklist_extended.txt",
  "https://v.firebog.net/hosts/Prigent-Crypto.txt",
  "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
  "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
  "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
  "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
  "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
  "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
  "https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt",
  "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
  "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
  "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
  "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
  "https://v.firebog.net/hosts/neohostsbasic.txt",
  "https://winhelp2002.mvps.org/hosts.txt",
  "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
  "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
  "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
  "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
]

whitelist_urls = [
  "https://raw.githubusercontent.com/juusujanar/adblock/master/adguard-whitelist.txt"
]

# Open TLSv1 Adapter
class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1_2)

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0'}     

s = requests.Session()
s.mount(host, MyAdapter())
x = s.post(host + "/control/login", json.dumps({"name": userName, "password" : password}), headers=headers, verify=False) # verify False ignores TLS cert validity
print(x.text)

for u in blocklist_urls:
	filterObj = json.dumps({'url':u, "name":u,"whitelist":False})
	print(filterObj)
	x = s.post(host + "/control/filtering/add_url", data = filterObj, headers=headers)
	print(x.text)


for u in whitelist_urls:
	filterObj = json.dumps({'url':u, "name":u,"whitelist":True})
	print(filterObj)
	x = s.post(host + "/control/filtering/add_url", data = filterObj, headers=headers)
	print(x.text)

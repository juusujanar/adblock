from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl
import requests
import json


host = "https://192.168.1.1:8443"
userName = ""
password = ""


blocklist_urls = {
  "sysctl.org": "http://sysctl.org/cameleon/hosts",
  "adaway.org": "https://adaway.org/hosts.txt",
  "oisd": "https://dbl.oisd.nl/",
  "quidsup notrack-blocklist": "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
  "quidsup notrack-malware": "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
  "frogeye firstparty trackers": "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
  "frogeye multiparty trackers": "https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt",
  "osint IT": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
  "yoyo.org": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
  "phishing.army": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
  "anudeepND adservers list": "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
  "bigdargon Vietnamese hosts": "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
  "crazy-max WindowsSpyBlocker": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
  "DandelionSprout AntiMalware": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt",
  "jdlingyu/ad-wars": "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
  "Perflyst Android Tracking": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
  "Perflyst and Dandelion Sprout's Smart-TV Blocklist": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
  "Dandelion Sprout's Game Console Adblock List": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt",
  "StevenBlack Unified hosts": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "disconnect.me ad": "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
  "disconnect.me malvertising": "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
  "disconnect.me tracking": "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
  "urlhaus.abuse.ch": "https://urlhaus.abuse.ch/downloads/hostfile/",
  "v.firebog.net AdguardDNS": "https://v.firebog.net/hosts/AdguardDNS.txt",
  "v.firebog.net Admiral": "https://v.firebog.net/hosts/Admiral.txt",
  "v.firebog.net Easylist": "https://v.firebog.net/hosts/Easylist.txt",
  "v.firebog.net Easyprivacy": "https://v.firebog.net/hosts/Easyprivacy.txt",
  "v.firebog.net neohostsbasic": "https://v.firebog.net/hosts/neohostsbasic.txt",
  "v.firebog.net Prigent-Ads": "https://v.firebog.net/hosts/Prigent-Ads.txt",
  "v.firebog.net Prigent-Crypto": "https://v.firebog.net/hosts/Prigent-Crypto.txt",
  "v.firebog.net Prigent-Malware": "https://v.firebog.net/hosts/Prigent-Malware.txt",
  "v.firebog.net RPiList-Malware": "https://v.firebog.net/hosts/RPiList-Malware.txt",
  "v.firebog.net RPiList-Phishing": "https://v.firebog.net/hosts/RPiList-Phishing.txt",
  "v.firebog.net w3kbl": "https://v.firebog.net/hosts/static/w3kbl.txt",
  "Winhelp2002": "https://winhelp2002.mvps.org/hosts.txt",
  "DeveloperDan Ads & Tracking": "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
}

whitelist_urls = {
  "Personal whitelist": "https://raw.githubusercontent.com/juusujanar/adblock/master/adguard-whitelist.txt"
}

class MyAdapter(HTTPAdapter):
  def init_poolmanager(self, connections, maxsize, block=False):
    self.poolmanager = PoolManager(num_pools=connections,
                                    maxsize=maxsize,
                                    block=block,
                                    ssl_version=ssl.PROTOCOL_TLSv1_2)


headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
           'Content-Type': 'application/json'}

s = requests.Session()
s.mount(host, MyAdapter())
print("Logging in")
# verify False ignores TLS cert validity
x = s.post(host + "/control/login",
           json.dumps({"name": userName, "password": password}), headers=headers, verify=True)
print(x.text)

for name, url in blocklist_urls.items():
    filterObj = json.dumps({'url': url, "name": name, "whitelist": False})
    print(filterObj)
    x = s.post(host + "/control/filtering/add_url",
               data=filterObj, headers=headers)
    print(x.text)


for name, url in whitelist_urls.items():
    filterObj = json.dumps({'url': url, "name": name, "whitelist": True})
    print(filterObj)
    x = s.post(host + "/control/filtering/add_url",
               data=filterObj, headers=headers)
    print(x.text)

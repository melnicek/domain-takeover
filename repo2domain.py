import json
import socket
import requests
import threading

REPOSITORIES = set()
DOMAINS = set()
VULNERABLE_DOMAINS = set()

r_lock = threading.Lock()
d_lock = threading.Lock()
vd_lock = threading.Lock()

PAGE = 0

def check_repo( repo ): 
    repository_name = repo["repository"]["full_name"]
    # print(repository_name)
    with r_lock:
        if repository_name in REPOSITORIES:
            return
        else:
            REPOSITORIES.add(repository_name)
    
    response = requests.get('https://raw.githubusercontent.com/{}/master/CNAME'.format(repository_name))
    if response.status_code == 200:
        domain = response.text.strip()

        with d_lock:
            if domain in DOMAINS:
                return
            else:
                DOMAINS.add(domain)

        try:
            addr = socket.gethostbyname("7331ffe7b3d6432162f4623942d6659c.{}".format(domain))
            with vd_lock:
                if addr in ["185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"] and not domain in VULNERABLE_DOMAINS:
                    # print("[+] https://github.com/{} -> https://{}".format(repository_name, domain))
                    VULNERABLE_DOMAINS.add(domain)
                    print("[.] repos={} domains={} vuln_domains={}".format(len(REPOSITORIES), len(DOMAINS), len(VULNERABLE_DOMAINS)), end="\r")
        except socket.gaierror:
            pass


PAGE = PAGE % 10 + 1
api = requests.get(
    "https://api.github.com/search/commits?q=Create+CNAME&sort=committer-date&order=desc&per_page=100&page={}".format(PAGE))
repos = []
try:
    repos = json.loads(api.text)["items"]
except:
    print(api.text)

threads = []

for repo in repos:
    threads.append(threading.Thread(target=check_repo, args=[repo]))

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()

print("[.] repos={} domains={} vuln_domains={}".format(len(REPOSITORIES), len(DOMAINS), len(VULNERABLE_DOMAINS)))



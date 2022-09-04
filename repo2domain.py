import json
import socket
import requests

REPOSITORIES = set()
DOMAINS = set()
VULNERABLE_DOMAINS = set()

PAGE = 0
while True:
    PAGE = PAGE % 10 + 1
    api = requests.get(
        "https://api.github.com/search/commits?q=Create+CNAME&sort=committer-date&order=desc&per_page=100&page={}".format(PAGE))
    repos = []
    try:
        repos = json.loads(api.text)["items"]
    except:
        print(api.text)
    for repo in repos:
        repository_name = repo["repository"]["full_name"]
        if not repository_name in REPOSITORIES:
            REPOSITORIES.add(repository_name)
            response = requests.get(
                'https://raw.githubusercontent.com/{}/master/CNAME'.format(repository_name))
            if response.status_code == 200:
                domain = response.text.strip()
                if not domain in DOMAINS:
                    DOMAINS.add(domain)
                    try:
                        addr = socket.gethostbyname(
                            "7331ffe7b3d6432162f4623942d6659c.{}".format(domain))
                        if addr in ["185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"] and not domain in VULNERABLE_DOMAINS:
                            print(
                                "[+] https://github.com/{} -> https://{}".format(repository_name, domain))
                            VULNERABLE_DOMAINS.add(domain)
                    except socket.gaierror:
                        pass
        print("[.] repos={} domains={} vuln_domains={}".format(
            len(REPOSITORIES), len(DOMAINS), len(VULNERABLE_DOMAINS)), end="\r")

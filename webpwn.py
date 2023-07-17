#!/usr/bin/env python3
# Collection of common pentest tools to get initial foothold into a company
# author: Mesut Cetin
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
from shutil import which
from subprocess import check_call
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
	print("No technology that's connected to the Internet is unhackable\n\n")

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
        if emailExists(email_pattern):
            found_email = True
            print(f"{Fore.GREEN}++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print(f"BOOM! SUCCESS: {Fore.YELLOW}{email_pattern}{Fore.GREEN}")
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
			fields = ('(1) - Subdomain enum using amass, subfinder, etc.\n'
				'(2) - Reverse whois lookup\n'
		  	   '(3) - Power enum with waybackurls and gau\n'
		  	   '(r) - return\n'
		  	  '(q) - to quit\n\n'
				  'Your choice: ')
			choice = input(fields)
			if choice == "1":
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
							threads_count = input("How fast do you want to scan? Provide the threads. Press enter for default value (10): ")
							domain_name = input("Which domain do you want to scan? (Example google.com):  ")
							if domain_name == "":
								print("No domain name provided..")
								print(Fore.RED + "Quitting..")
								print(Fore.RESET)
								break
							if threads_count == "":
								threads_count = 10
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
								sublist_args = "python ./tools/sublist3r.py -d %s -t %s | tee -a subdomains/tmp.txt" % (domain_name, threads_count)
								run_sublist = check_call(sublist_args, shell=True)
								turbo_args = "python ./tools/turbolist3r.py -d %s -t %s | tee -a subdomains/tmp.txt" % (domain_name, threads_count)
								run_turbo = check_call(turbo_args, shell=True)
								
								# clean up wordlist
								print("\n[+] Cleaning up the wordlist.\n")
								run_cleanup = subprocess.getoutput('cat subdomains/tmp.txt | grep "\." | grep -v "[-]" | grep -v "___" | cut -d "]" -f2 | sed "s/^[ \\\\t]*//" | sort -u > subdomains/domains.txt')
								delete_tmp_file = subprocess.getoutput('rm -rf subdomains/tmp.txt')	
								print(Fore.GREEN + "[+] Saved results to subdomains/domains.txt")
								print(Fore.RESET)								
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
			elif choice == "2":
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

			elif choice == "3":
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
								print(subprocess.getoutput('ntlmrecon --infile %s --outfile ntlmrecon/ntlm-endpoints.txt' % (existing_file)))
								print(Fore.GREEN + "[+] Saved results into ntlmrecon/ntlm-endpoints.txt")
								print(Fore.RESET)
					ntlmrecon_range=str(input("Do you want to scan a single IP/domain (IP), an IP range (R) or nothing more (N)? (IP/R/N): "))
					if ntlmrecon_range == "r" or ntlmrecon_range == "R":
						ip_range = str(input("Enter your IP range in CIDR notation (e.g. 193.168.2.2/24): "))
						print(subprocess.getoutput('ntlmrecon --input %s --outfile ntlmrecon/ntlm-endpoints.txt' % (ip_range)))
						print(Fore.GREEN + "[+] Saved results into ntlmrecon/ntlm-endpoints-range.txt")
						print(Fore.GREEN + "[+] Saved results into ntlmrecon/ntlm-endpoints-range.txt")
						print(Fore.RESET)
					else:
						pass
					if ntlmrecon_range == "IP" or ntlmrecon_range == "ip":
						ip_address=str(input("Enter your IP address or domain name (e.g. 193.168.2.2 or google.com): "))
						print(subprocess.getoutput('ntlmrecon --input %s --outfile ntlmrecon/ntlm-endpoints.txt' % (ip_address)))
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
	try:
		main_menu()
	except KeyboardInterrupt:
		print(Fore.RED+"\nKey event detected, closing..")
		exit(0)

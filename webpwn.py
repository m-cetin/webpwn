#!/usr/bin/env python3
# webpwn - collection of common pentest tools to get initial foothold into a company
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
import os
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
			 if j.startswith('https://www.xing.com/pages'):
				 global url
				 url = j
				 global key_word
				 key_word = keyword
				 break
			 else:
				 print(Fore.RED + "Company not found!")
				 print(Fore.RESET)
				 url = input("What is the XING url (e.g. https://www.xing.com/pages/COMPANYNAME): ")
				 break
	except HTTPError as err:
		if err.code == 429:
			print(Fore.RED + "[-] You are rate limited! Try changing your IP address or wait a few minutes and then retry!")
			print(Fore.RESET)
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
					name = link.text.split("???")[0].strip()

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
		os.popen("sed -i 's/??/oe/I' recon/fullname-emails.txt; sed -i 's/??/ae/I' recon/fullname-emails.txt; sed -i 's/??/ss/I' recon/fullname-emails.txt; sed -i 's/??/ue/I' recon/fullname-emails.txt 2>/dev/null")
		os.popen("sort -u --ignore-case recon/fullname-emails.txt -o recon/fullname-emails.txt 2>/dev/null")
		os.popen("cat recon/fullname-emails.txt | awk -F\".\" '{print substr($1,1,1),$2,$3}' OFS='.' > recon/emails.txt 2>/dev/null")
		os.popen("cat recon/fullname-emails.txt | awk -F\".\" '{print substr($1,1,1),$2,\".\"$3}' OFS='' > recon/fl-emails.txt 2>/dev/null")

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
		fields = ('Enter 1 - Email addresses with OSINT\n'
				'Enter 2 - Subdomain Enumeration\n'
		  	  'Enter q - to quit\n\n'
				  'Your choice: ')
		choice = input(fields)
		if choice == "1":
			xing_dumper()
			crosslinked(args)
			cleanup()

		elif choice == "2":
			print("boss")
		
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

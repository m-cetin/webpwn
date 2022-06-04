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
from googlesearch import search
from colorama import Fore, Style
from sys import exit
from bs4 import BeautifulSoup
from unidecode import unidecode
from taser import printx
from taser.logx import setup_fileLogger,setup_consoleLogger
from taser.proto.http import extract_webdomain,web_request,get_statuscode
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
            response2 = requests.post("https://login.xing.com/login/api/login", json=payload, cookies=response1.cookies, headers={"X-Csrf-Token": csrf1, "Content-Type": "application/json; charset=utf-8", "User-Agent": "Mozilla/5.0 (X11; Linux x86_x64) AppleWebKit/537.11 (KHTML, like Gecko)", "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*,q=0.8", "Accept-Charset":"ISO-8859-1,utf--8;q=0.7,*;q=0.3","Accept-Encoding":"none","Connection":"keep-alive","Accept-Language":"en-US,en;q=0.8"}, allow_redirects=False)
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

    msuffix = "@" + input("What is the domain name for the email (e.g. google.com): ")
    keyword = input("What is the name of the company you want to pwn (e.g. Google): ")
    for j in search(keyword+" xing",tld="co.in",num=5,stop=10,pause=1):
         progress_bar()
         if j.startswith('https://www.xing.com/pages'):
             global url
             url = j
             break
         else:
             print(Fore.RED + "Company not found!")
             print(Fore.RESET)
             url = input("What is the XING url (e.g. https://www.xing.com/pages/COMPANYNAME): ")
             break

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
            if userXing == 0 or passXing == 0:
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
                print(Fore.GREEN + "+++++++++++++++++++++++++++++++++++++++++++++")
                print(Fore.GREEN + "             FOUND NEW EMAILS: ",dump_count)      
                print(Fore.GREEN + "+++++++++++++++++++++++++++++++++++++++++++++")
                print(Fore.RESET)

            except:
                # likely authorization error due to incorrect 'login' cookie
                # otherwise the script is broken or the api has been changed
                print()
                #print("[!] Authentication required. Login failed!")

                #print("[debug] " + str(e))
        else:
            print()
            print("[!] Invalid URL provided.")
            print("[i] Example URL: 'https://www.xing.com/pages/appleretaildeutschlandgmbh'")

# main menu for selections
def main_menu():
	while True:
		print(Fore.YELLOW + "--------------------------------------------")
		print("  Main Menu. Please choose your selection!")
		print("--------------------------------------------")
		print(Fore.RESET)
		fields = ('Enter 1 - Email addresses with OSINT\n'
                'Enter 2 - Subdomain Enumeration\n'
		  	  'Enter q - to quit\n'
		          'Your choice: ')
		choice = input(fields)
		if choice == "1":
			print()
			xing_dumper() # entweder xingdumper oder crosslinked als auswahl
                        # crossLinked() -> Funktion für crosslinked
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

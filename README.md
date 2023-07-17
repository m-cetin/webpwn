# WebPwn - A Comprehensive Toolkit for Penetration Testers

WebPwn is an advanced and all-inclusive collection of tools specifically designed to assist penetration testers in obtaining a solid initial foothold into targeted systems. This powerful toolkit encompasses a wide array of functionalities, including but not limited to email address collection, subdomain enumeration, vulnerability scanning, and exploitation techniques. It is essential to note that WebPwn is intended solely for legal and ethical purposes within the field of penetration testing. Its application for any illegal activities is strictly prohibited.

By utilizing WebPwn, penetration testers can enhance their capabilities and streamline their assessment process, ensuring thorough and effective security evaluations. Whether you are conducting web application assessments, network penetration tests, or vulnerability analyses, WebPwn offers a comprehensive suite of tools to facilitate your objectives.

Please remember to exercise responsible usage and adhere to applicable laws and regulations while utilizing WebPwn. Our aim is to provide a valuable resource to penetration testers, fostering a safer and more secure digital landscape.

# Tool Requirements (Linux-only)

General recommendations:

+ Install Go and place Go binaries in the "tools" folder.
+ Clone the entire repository.

For full functionality of the email gathering tool, you will need:

+ 1 XING account.

Although it may work without an account, we strongly recommend using one. Creating a temporary account for this purpose is suggested.

# Installation

To install all requirements, simply do:

`git clone https://github.com/m-cetin/webpwn; cd webpwn`

`pip3 install -r requirements.txt`

# Usage

Just run:

`python3 webpwn.py`

The main menu will guide you through.

# What you can do

## Menu 1) - E-Mail Gathering
Gathering emails from Xing and LinkedIn. Enter your XING credentials, when asked. 

![image](https://github.com/m-cetin/webpwn/assets/102237861/bbef7ae8-56ce-4254-a96b-b1d2e5742454)

The mails are saved under `/recon` in different formats. `fullname-emails.txt` has the format {firstname}.{lastname}@company.com, `emails.txt` has the format {f}.{lastname}@company.com, and other common mail pattern you can find there. There's also an option to bruteforce names with X certain letters, for example adm@company.com, etc.

## Menu 1b) - E-Mail convention check
Enter the full name of the target person and their domain (@domain.com), to check against Microsoft Azure, if the email exists. German umlauts (ä,ö,ü and ß) are automatically converted to their according usable form (ä -> ae, etc.). Furthermore, hyphe (-) signs work as well. If someone has the name "Anna-Lena Schmidt", versions like a-l.schmidt@company.com and similiar are being considered. 

![image](https://github.com/m-cetin/webpwn/assets/102237861/4db52e31-225c-4b14-8bbb-ae8640e9685b)

## Menu 2 - Subdomain Enumeration

### Option 1): 
Combination of the most commonly used tools to do subdomain enumeration.

![image](https://github.com/m-cetin/webpwn/assets/102237861/9b202680-f761-4c7e-a73b-42faba813400)

Results are saved under `subdomains/domains.txt`. Can be further used with `httpx` to check if they are alive.

### Option 2): 
Coming soon. Hopefully. 

### Option 3): 
Enumerate your target with waybackurls and gau to get endpoints from the past. 

![image](https://github.com/m-cetin/webpwn/assets/102237861/447cb472-69a7-4b05-bea9-90f2c1b40e12)

They'll be saved separately under `subdomains/old_domains.txt`. 

## Menu 3 - Enumerate NTLM endpoints with NTLMRecon
Checking common NTLM endpoints to do password spraying attacks. You can either use the previously created `domains.txt` or specify your own IP address, domain, a full range or just skip it. This is basically just the tool NTLMRecon, since I'm using it regularly.

![image](https://github.com/m-cetin/webpwn/assets/102237861/c853648c-56d3-4697-b6dc-6a191108c2ac)

## Menu 4 - SQL Mass Injection
When you want to really test every parameter for SQL injections, some "mass" scanning might be useful. I've basically just took sqlmap with the ability to use custom flags. When scrolling a lot through a web page, you should have a huge Burp history file. Click on it, select "Show only in scope", mark all requests and save them as XML file. Then simply provide this file to the tool, to scan through everything and anything.

![image](https://github.com/m-cetin/webpwn/assets/102237861/783429be-7884-4653-a00b-93117e127e36)

I usually use `--tamper=space2comment,between` as extra flag. This might take a while to run through. Let it run in the background and enjoy your SQL injections once identified.

# Note
This tool is still in development and will probably further advanced. If you have any feedback or issues you experienced while using it, please let me know, so I can adjust it. I build it initially for myself to ease the usage of a lot of tools. 

# Credits
Google Dorking tools:
- [Pagodo](https://github.com/opsdisk/pagodo) by [opsdisk](https://github.com/opsdisk)

Recon (email gathering) tools being used:
- [XingDumper](https://github.com/l4rm4nd/XingDumper) by [l4rm4nd](https://github.com/l4rm4nd)
- [CrossLinked](https://github.com/m8r0wn/CrossLinked) by [m8r0wn](https://github.com/m8r0wn)

Subdomain Enumeration tools:
- [amass](https://github.com/OWASP/Amass) by [OWASP](https://github.com/OWASP)
- [Subfinder](https://github.com/projectdiscovery/subfinder) by [projectdiscovery](https://github.com/projectdiscovery)
- [Sublist3r](https://github.com/aboul3la/Sublist3r) by [aboul3la](https://github.com/aboul3la)
- [Turbolist3r](https://github.com/fleetcaptain/Turbolist3r) by [fleetcaptain](https://github.com/fleetcaptain)
- [assetfinder](https://github.com/tomnomnom/assetfinder) by [tomnomnom](https://github.com/tomnomnom)
- [knockknock](https://github.com/harleo/knockknock) by [harleo](https://github.com/harleo)

Back to the future enumeration tools:
- [waybackurls](https://github.com/tomnomnom/waybackurls) by [tomnomnom](https://github.com/tomnomnom)
- [gau](https://github.com/lc/gau) by [lc](https://github.com/lc)

NTLM recon tool:
- [NTLMRecon](https://github.com/pwnfoo/NTLMRecon) by [pwnfoo](https://github.com/pwnfoo)

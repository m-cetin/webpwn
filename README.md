# Pwning systems - the easy way

"Webpwn" is a collection of commonly used tools to get initial foothold into a targets system. It aims to help penetration testers with collecting email addresses, enumerating subdomains, scanning and exploiting vulnerabilities and a lot more.

# Requirements

Tested on Linux. Go needs to be installed and the go binaries are needed within the "tools" folder. Make sure to clone the whole respository.

# Installation

`git clone https://github.com/m-cetin/webpwn; cd webpwn`

`pip3 install -r requirements.txt`

# Usage

`python3 webpwn.py`

The main menu will guide you through.

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

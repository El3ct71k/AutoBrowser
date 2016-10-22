AutoBrowser 4.0
===============
AutoBrowser is a tool written in python for penetration testers.
The purpose of this tool is to create report and screenshots of http/s based ports on the network.
It analyze Nmap Report or scan with Nmap,
Check the results with http/s request on each host using headless web browser,
Grab a screenshot of the response page content.
* This tool is designed for IT professionals to perform penetration testing to scan and analyze NMAP results.
[Proof of concept video (From version: 2.0)](https://www.youtube.com/watch?v=iiexvh3KLvE&feature=youtu.be)


Documentation:
==============
*positional arguments:
****analyze** - _Analyze and browse (Require argument: nmap report location)_
****scan** - _Scan and browse (Require argument: target host or file)_


*optional arguments:
****-h, --help** - _show this help message and exit_
****-p PROJECT, --project PROJECT** - _project name (folder which contain all the data. default: project)_
****-t TIMEOUT, --timeout TIMEOUT** - _http request timeout period_
****-w MAX_WORKERS, --max-workers MAX_WORKERS** - _Max worker processes (Default: 4)_
****--useragent USERAGENT** - _Set specific user agent_
****--java-enabled** - _Display Java enviroment_
****--verbose** - _Show all checks verbosly_
****--proxy PROXY** - _Relay connections through HTTP/socks5 proxy (Example: socks5://127.0.0.1:8080)_
****--proxy-auth PROXY_AUTH** - _Set proxy credentials. (Example: username:password)_

Examples:
===============
**Delimiting the values on the CLI arguments it must be by double quotes only!**
* Get the argument details of `scan` method:
`python AutoBrowser.py scan --help`
* Scan with Nmap, checks the results and create folder by name project_name verbosely with 10 workers:
`python AutoBrowser.py scan "192.168.1.1/24" -a="-sT -sV -T3" -p project_name --workers=10` 

* Scan a host list via Nmap(like -iL Nmap flag), checks the results and create folder by name project_name and enabling java environment:
`python AutoBrowser.py scan file_path.txt -a="-sT -sV -T3" -p project_name --verbose --java-enabled`

* Get the argument details of `analyze` method:
`python AutoBrowser.py analyze --help`
* Analyzing Nmap XML report and create folder by name report_analyze trough a Proxy:
`python AutoBrowser.py analyze nmap_file.xml --project report_analyze --proxy="socks5://127.0.0.1:8080"`

* Analyzing Nmap XML report and create folder by name report_analyze trough a Proxy with credentials:
`python AutoBrowser.py analyze nmap_file.xml --project report_analyze --proxy="socks5://127.0.0.1:8080" --proxy-auth="username:password"`

* Analyzing Nmap XML report and create folder by name report_analyze with specify user agent:
`python AutoBrowser.py analyze nmap_file.xml --project report_analyze --proxy="socks5://127.0.0.1:8080" --user-agent="My New UserAgent"`

Requirements:
===============
###Linux Installation:
1. sudo apt-get install python-pip python2.7-dev libxext-dev python-qt4 qt4-dev-tools build-essential nmap
2. sudo pip install -r requirements.txt

###MacOSx Installation:
1. Install Xcode Command Line Tools (AppStore)
2. `ruby -e "$(curl -fsSL https://raw.github.com/mxcl/homebrew/go)"`
3. brew install pyqt nmap
4. sudo easy_install pip
5. sudo pip install -r requirements.txt

###Windows Installation:
1. Install [setuptools](http://www.lfd.uci.edu/~gohlke/pythonlibs/#setuptools)
2. Install [pip](http://www.lfd.uci.edu/~gohlke/pythonlibs/#pip)
3. Install [PyQt4](http://www.lfd.uci.edu/~gohlke/pythonlibs/#pyqt)
4. install [Nmap](http://nmap.org/download.html)
4. Open Command Prompt(cmd) as Administrator -> Goto python folder -> Scripts (cd c:\Python27\Scripts)
5. pip install -r (Full Path To requirements.txt)

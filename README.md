AutoBrowser 3.0
===========
AutoBrowser is a tool written in python for penetration testers.
The purpose of this tool is to create report and screenshots of http/s based ports on the network.
It analyze Nmap Report or scan with Nmap,
Check the results with http/s request on each host using headless web browser,
Grab a screenshot of the response page content.
* This tool is designed for IT professionals to perform penetration testing to scan and analyze NMAP results.
[Proof of concept video (From version: 2.0)](https://www.youtube.com/watch?v=iiexvh3KLvE&feature=youtu.be)

Examples:
===============
* Get the argument details of `scan` method:
`python AutoBrowser.py scan --help`
* Scan with Nmap and Checks the results and create folder by name project_name:
`python AutoBrowser.py scan '192.168.1.1/24' -a='-sT -sV -T3' -p project_name`
* Get the argument details of `analyze` method:
`python AutoBrowser.py analyze --help`
* Analyzing Nmap XML report and create folder by name report_analyze:
`python AutoBrowser.py analyze nmap_file.xml --project report_analyze`

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

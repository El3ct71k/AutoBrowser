#!/usr/bin/env python
#-*- coding:utf-8 -*-
########################################################
# Name: autoBrowser Screenshot
# Credits: Avi Orenstien, aviorenstein@gmail.com
# Site: http://nimrodlevy.co.il
__author__ = 'El3ct71k'
__license__ = 'GPL v3'
__version__ = '2.0'
__email__ = 'El3ct71k@gmail.com'
########################################################


from sys import argv
from os import path, makedirs
from docopt import docopt
from re import match
from urlparse import urlparse
from lxml import etree
import requests, logging, ConfigParser
import concurrent.futures
from browsersLib import browsersLib


class AutoBrowsers:
    def __init__(self):
        #Docopt parser
        __doc__ = """
AutoBrowser Screenshot {version}
Usage:
    {prog} regular -f <FILE> -p <PROJECT> -b <BROWSER> [-d <DRIVER>] -t <TIMEOUT> [-v]
    {prog} nmap -f <FILE> -p <PROJECT> -b <BROWSER> [-d <DRIVER>] -t <TIMEOUT> [-v]
    {prog} -c <CONFIGFILE>
    {prog} (-h | --help)
    {prog} --version

Description:
    AutoBrowser Screenshot

    AutoBrowser screenshot is a tool written in python language that used for penetration testing.
    The purpose of this tool is to parse nmap (Port scanner) results or just a simple text file
    that contain ip addresses and ports (for example 127.0.0.1:31337)
    and send a http/s request to each live host with his open port number using popular Web Browsers such as:
    * Internet Explorer
    * Mozilla Firefox
    * Google Chrome
    * Safari
    AutoBrowser grabs a screenshot of the response page content.
    This tool is designed for IT professionals to perform penetration testing and analyzing NMAP results.
    The tool can analyze text files as well as links to separate lines.
    This tool checks whether a specific port address is tested (tested in HTTP and in HTTPS)
    so they can make their test which make our lives easier (no hard work!).


Options:
    -f <FILE> --file <FILE>                 File name
    -p <PROJECT> --project <PROJECT>        Project name
    -b <BROWSER> --browser <BROWSER>        Choosing a browser
    -d <DRIVER> --driver <DRIVER>           Choosing a driver (must in Internet Explorer and Chrome)
    -t <TIMEOUT> --timeout <TIMEOUT>        Timeout of URLS
    -c <CONFIGFILE> --config <CONFIGFILE>   Imports the settings from configuration file
    -v --verbose                            Verbose level
    -h --help                               Displays the documentation of the AutoBrowser tool
    --version                               Displays the version.

Types of browsers:
    ie                                      Internet Explorer
    chrome                                  Google Chrome
    firefox                                 Mozilla FireFox (without using a driver)
    safari                                  Safari

Drivers Folder:
    Internet Explorer                       IEDriverServer.exe
    Google Chrome                           chromedriver.exe
    Safari                                  selenium-server-standalone-2.39.0.jar

A list of links to download drivers:
    Internet Explorer, Safari               https://code.google.com/p/selenium/downloads/list?can=1
    Google Chrome                           http://chromedriver.googlecode.com/


Example:
    Analysis a NMAP report(XML file) named: nmap.xml, a project by the name: El3ct71k.
    Using Internet Explorer browser and using by driver in the following location: DriversIEDriverServer.exe
    in a maximum of 3 seconds timeout per request (HTTP/HTTPS):

      {prog} nmap -f nmap.xml  -p El3ct71k -b ie -d Drivers/IEDriverServer.exe -t 3

    Analysis a regular file(TXT file) named: file.txt, a project by the name: myfavoritelinks.
    Using Mozilla Firefox browser in a maximum of 3 seconds timeout per request(HTTP/HTTPS)
    and generates detailed report:

      {prog} regular -f links.txt  -p myfavoritelinks -b firefox -t 3 -v

    Imports the settings from configuration file:

      {prog} -c configFiles/autoBrowserRegularExample.conf

    Show currently version:

      {prog} --version                            Display the version

[~] Built by El3ct71k
""".format(prog=path.basename(argv[0]), version=__version__)
        self.arguments = docopt(__doc__, version="AutoBrowser Screenshot: %s" % __version__)
        self.logger = self.createLogger() #Setting the logger
        self.links = list()
        self.urlstested = list()
        self.whitelist = list()
        #Disable `requests` logging
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.propagate = False
        if self.arguments['--config']:
            if path.isfile(self.arguments['--config']):
                try:
                    config = ConfigParser.ConfigParser()
                    config.read(self.arguments['--config'])
                    isNmap = lambda x: x=='nmap' and True or False
                    self.stack = {
                        'isNmap'    :   isNmap(config.get('autoBrowser', 'type', 0)),
                        'file'      :   config.get('autoBrowser', 'file', 0),
                        'project'   :   config.get('autoBrowser', 'project', 0),
                        'browser'   :   config.get('autoBrowser', 'browser', 0).lower(),
                        'driver'    :   config.get('autoBrowser', 'driver', 0),
                        'timeout'   :   config.get('autoBrowser', 'timeout', 0),
                        'verbose'   :   config.get('autoBrowser', 'verbose', 0),
                        'whitelist' :   self.whitelist
                    }
                except ConfigParser.MissingSectionHeaderError as msg:
                    self.logger.info("The config file you selected is not a valid")
                    exit(1)

            else:
                self.logger.info('The config file not exist')
                exit(1)
        else:
            self.stack = {
                    'isNmap'    :   self.arguments['nmap'],
                    'file'      :   self.arguments['--file'],
                    'project'   :   self.arguments['--project'],
                    'browser'   :   self.arguments['--browser'].lower(),
                    'driver'    :   self.arguments['--driver'],
                    'timeout'   :   self.arguments['--timeout'],
                    'verbose'   :   self.arguments['--verbose'],
                    'whitelist' :   self.whitelist
                }

        self.Controller()


    def createLogger(self):
        #Logging format
        logging.basicConfig(
                            format='[%(asctime)s] %(message)s',
                            datefmt='%d-%m-%Y %H:%M',
                            )
        #Create logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        return logger


    def nmapParser(self, file):
        try:
            tree = etree.parse(file) #Parses XML code from an XML file
            for host in tree.iter('host'): #Import all the hosts
               ip = host.iter('address').next().get("addr") #Import the first address(1. IP Address 2. MAC Address, we wiil use the IP Address)
               for ports in host.iter("port"): #Import all the ports
                   port = ports.get("portid")
                   if ports.get("protocol") == "udp"  or ports.iter("state").next().get("state") == "closed": #Checks whether the protocol is TCP and the state of the socket is open
                       continue
                   else:
                        self.links.append(str("http://"+ip+":"+port).strip())
                        self.links.append(str("https://"+ip+":"+port).strip())
        except etree.XMLSyntaxError as msg:
            self.logger.info(msg.message)
            exit(1)


    def fileParser(self, file): #Import a URLS from regular file
        with open(file, 'r') as urls:
            for url in (l.strip() for l in urls):
                self.links.append(url)


    def checkURLS(self, url, timeout): #Checks the URLS of links array, whether the links are live or not and if the status code isn't 404 error page
        self.urlstested.append(url)
        if str(self.stack['verbose']).lower()=='true':
            self.logger.info("Trying to connect to: %s" % url)
        req = requests.get(url, timeout=int(self.stack['timeout'])) #Create a HTTP/HTTPS request
        if(req.status_code != 404):
            if url not in self.whitelist:
                self.whitelist.append(url) #If the status code isn't 404, it appends an URL to the whitelist variable
                self.logger.info("[%s] exists" % url)


    def Worker(self):
        '''
            This function checks the type of parser the file you choose (parses a NMAP file or regular file)
            Then the function divides the work between 50 workers and the workers call `checkURLs` function to checks a HTTP/HTTPS requests
            Finally, it calls to autoBrowsing function from BrowsersLib library and creates a whitelist file with the findings
        '''
        try:
            if self.stack['isNmap']:
                self.nmapParser(self.stack['file'])
            else:
                self.fileParser(self.stack['file'])
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor: #Create a 50 worker pool
                checkmyurls = {executor.submit(self.checkURLS, link, self.stack['timeout']): link for link in self.links} #call `checkURLS` function
                for future in concurrent.futures.as_completed(checkmyurls):
                    checkmyurls[future]
                    try:
                        if link not in self.urlstested:
                            self.checkURLS(link, self.stack['timeout'])
                    except:
                        continue

        finally:
           if self.whitelist:
                self.stack['whitelist'] = self.whitelist
                browsersLib.autoBrowsing(self.stack, self.logger)
                browsersLib.createWhiteLinksFile(self.stack['project'], self.whitelist, self.logger)
           else:
                self.logger.info("No good results")


    def Controller(self):
        try:
            if not match(r'^\w+$', self.stack['project']): #Checks if it does not contain special characters
                self.logger.info("Project name must be numbers or/and english characters")
                exit(1)
            self.logger.info("[~] AutoBrowser Screenshot %s" % __version__)
            if path.isdir(self.stack['project']): #if the project directory does not exist, we create a new directory for the project, else, we use with the directory exists
                self.logger.info('Use with %s project ' % self.stack['project'])
            else:
                makedirs(self.stack['project'])
                self.logger.info('Create %s project ' % self.stack['project'])
            self.Worker()
        except IOError as msg:
            self.logger.info(msg)
        finally:
            self.logger.info('[~] Done!')
            self.logger.info("[~] Built by El3ct71k")


if __name__ == '__main__':
    AutoBrowsers()
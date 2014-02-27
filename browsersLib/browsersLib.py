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

from urlparse import urlparse
from selenium import webdriver
from selenium.common import exceptions


def browsers(stack, logger): #Chooses a browser and if necessary, puts a driver file
    if(stack['browser'] == "firefox"):
        logger.info('Open FireFox browser')
        profile = webdriver.FirefoxProfile()
        profile.accept_untrusted_certs = True
        browser = webdriver.Firefox()
    elif(stack['browser'] == "chrome"):
        if stack['driver']:
            logger.info('Open Google Chrome browser')
            browser = webdriver.Chrome(stack['driver'])
        else:
            logger.info("Please choose a driver for Google Chrome")
            exit(1)
    elif(stack['browser'] == "safari"):
        if stack['driver']:
            logger.info('Open Safari browser')
            browser = webdriver.Safari(stack['driver'])
        else:
            logger.info("Please choose a driver for Safari")
    elif stack['browser'] == "ie":
        if stack['driver']:
            logger.info('Open Internet Explorer browser')
            browser = webdriver.Ie(stack['driver'])
        else:
            logger.info("Please choose a driver for Internet Explorer")
            exit(1)
    else:
        logger.info("The browser you selected does not exist in the browsers list")
        exit(1)
    return browser


def autoBrowsing(stack, logger):
    try:
        browser = browsers(stack, logger) #Opens the user selected browser
        picnumber = 1
        for link in stack['whitelist']:
            if urlparse(link).scheme: #Checks what scheme the URLs are (HTTP, HTTPS and etc)
                try:
                    #Accesses the links, takes a screenshot and saves it
                    browser.get(link)
                    location = urlparse(link).netloc.split(":")[0]
                    browser.save_screenshot(stack['project']+'/'+stack['browser']+'-'+location+"-"+str(picnumber)+'.jpg')
                    logger.info('['+link+']Success!')
                    picnumber += 1
                except:
                    continue
            else:
                logger.info('['+link+']You must specify scheme!')
        browser.quit()
    except Exception as msg:
        logger.info(msg)


def createWhiteLinksFile(project, whitelist, logger):
        try:
            fp = open(project+"/whitelist.txt", 'a+') #Create a `whitelist.txt` file in the project directory
            urldata = str()
            for whitelink in whitelist:
                urldata += whitelink+"\n" #Appends the good results to the whitelist file
            fp.write(urldata)
            fp.close
        finally:
            logger.info("Whitelist of good links saved in: %s/whitelist.txt succsufully!" % project)
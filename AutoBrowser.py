#!/usr/bin/env python
from __future__ import print_function
########################################################
__author__ = ['Nimrod Levy', 'Tomer Zait']
__license__ = 'GPL v3'
__version__ = '3.0-dev'
__email__ = ['El3ct71k@gmail.com', 'Realgam3@gmail.com']
########################################################

import grequests
from os import path, makedirs
from functools import partial
from argparse import ArgumentParser
from ghost.ghost import Ghost, QSize
from nmap import PortScannerAsync, PortScanner
from multiprocessing import freeze_support, Pool


def generate_async_requests(host, ports, url_list, project, timeout=10):
    for port in ports:
        for http_type in ('http', 'https'):
            yield grequests.get(
                '%s://%s:%d/' % (http_type, host, port),
                timeout=timeout,
                verify=False,
                callback=partial(callback_response, url_list, project=project, timeout=timeout),
            )


def callback_exception(request, exception):
    print("[AutoBrowser] [%s] Request failed" % request.url)


def callback_response(url_list, response, project, timeout=10, **kwargs):
    request = response.request
    capture_name = '%s.png' % request.url.replace('/', '').replace(':', '-')

    print("[AutoBrowser] [%s] Request Succeed" % request.url)
    url_list.append(request.url)

    # Create Ghost Object And Set Size
    ghost = Ghost(
        wait_timeout=timeout,
        download_images=True,
        cache_dir=None,
    )
    ghost.webview.resize(QSize(1280, 720))
    ghost.page.setViewportSize(QSize(1280, 720))
    # Open URL
    ghost.open(request.url)
    # Make Screen Capture
    ghost.capture_to("{dir}/{name}".format(dir=project, name=capture_name))



def callback_result(host, scan_result, project, timeout=10):
    url_list = []


    ports = scan_result['scan'][host]['tcp']
    print("[AutoBrowser] Nmap results: \n"
          "[AutoBrowser] Host: %s" % host)
    for port, details in ports.items():
        version = (details['version']) if details['version'] else 'unknown'
        service = (details['product']) if details['product'] else 'unknown'
        print("[AutoBrowser] Port: %s" % port, end='\t')
        print("State: %s" % details['state'], end='\t')
        print("Service: %s" % service, end='\t')
        print("Version: %s" % version, end='\n')
    print("[AutoBrowser] Browser results:")
    grequests.map(
        requests=generate_async_requests(host, ports, url_list, project, timeout=timeout),
        size=10,
        exception_handler=callback_exception,
    )
    with open('links.txt', 'w') as links_file:
        for url in url_list:
            links_file.write(url+"\n")
    print("[AutoBrowser] The links that worked at the browser were saved in a `links.txt` file.\n"
            "[AutoBrowser] Finished.")


def analyze_and_browse(nmap_report, project='project', timeout=10):
    scanner = PortScanner()
    results = scanner.analyse_nmap_xml_scan(open(nmap_report).read())

    pool = Pool()
    pool.map(
        partial(callback_result, scan_result=results, project=project, timeout=timeout),
        (host_ip for host_ip in results['scan'])
    )


def scan_and_browse(target, nmap_args='-sS -sV', project='project', timeout=10):
        scanner = PortScannerAsync()
        scanner.scan(
            hosts=target,
            arguments=nmap_args,
            callback=partial(callback_result, project=project, timeout=timeout)
        )
        while scanner.still_scanning():
            scanner.wait(2)


if __name__ == '__main__':
    freeze_support()
    parser = ArgumentParser(prog=path.basename(__file__))
    subparsers = parser.add_subparsers()

    # Report Parser
    parser_report = subparsers.add_parser('analyze', help='Analyze and browse')
    parser_report.add_argument(
        "nmap_report",
        help="nmap report(xml file) to analyze",
        default=None,
    )
    parser_report.add_argument(
        "-p", "--project",
        help="Name of the project folder which contain all the data [ Default: project ]",
        type=str,
        default="project"
    )
    parser_report.add_argument(
        "-t", "--timeout",
        help="http request timeout period",
        type=int,
        default=10,
    )

    # Scan Parser
    parser_scan = subparsers.add_parser('scan', help='Scan and browse')
    parser_scan.add_argument(
        "target",
        help="hosts for scan (example: 127.0.0.1, 127.0.0.1/24)",
        default=None,
    )
    parser_scan.add_argument(
        "-a", "--nmap-args",
        help="nmap args for scan",
        default="-sS -sV"
    )
    parser_scan.add_argument(
        "-p", "--project",
        help="Name of the project folder which contain all the data [ Default: project ]",
        default="project"
    )
    parser_scan.add_argument(
        "-t", "--timeout",
        help="http request timeout period",
        type=int,
        default=10,
    )

    args = vars(parser.parse_args())
    if not path.exists(args['project']):
        makedirs(args['project'])
    if 'nmap_report' in args:
        analyze_and_browse(**args)
    else:
        scan_and_browse(**args)
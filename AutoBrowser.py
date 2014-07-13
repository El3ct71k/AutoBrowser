#!/usr/bin/env python
########################################################
__author__ = ['Nimrod Levy', 'Tomer Zait']
__license__ = 'GPL v3'
__version__ = '3.0-dev'
__email__ = ['El3ct71k@gmail.com', 'Realgam3@gmail.com']
########################################################


import grequests
from pprint import pprint
from functools import partial
from argparse import ArgumentParser
from ghost.ghost import Ghost, QSize
from nmap import PortScannerAsync, PortScanner
from multiprocessing import freeze_support, Pool


def generate_async_requests(host, ports, url_list, timeout=10):
    for port in ports:
        for http_type in ('http', 'https'):
            yield grequests.get(
                '%s://%s:%d/' % (http_type, host, port),
                timeout=timeout,
                verify=False,
                callback=partial(callback_response, url_list, timeout=timeout),
            )


def callback_exception(request, exception):
    print("[%s] Request failed" % request.url)


def callback_response(url_list, response, timeout=10, **kwargs):
    request = response.request
    capture_name = '%s.png' % request.url.replace('/', '').replace(':', '-')

    print('[%s] Request Succeed' % request.url)
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
    ghost.capture_to(capture_name)


def callback_result(host, scan_result, timeout=10):
    url_list = []

    print('------------------')
    print('Host: %s' % host)

    ports = scan_result['scan'][host]['tcp']
    print('Ports: ')
    pprint(ports)

    print('HTTP/S: ')
    grequests.map(
        requests=generate_async_requests(host, ports, url_list, timeout=timeout),
        size=10,
        exception_handler=callback_exception,
    )

    print('URL List: ')
    print(url_list)


def analyze_and_browse(nmap_report, timeout=10):
    scanner = PortScanner()
    results = scanner.analyse_nmap_xml_scan(open(nmap_report).read())

    pool = Pool()
    pool.map(
        partial(callback_result, scan_result=results, timeout=timeout),
        (host_ip for host_ip in results['scan'])
    )


def scan_and_browse(target, nmap_args='-sS -sV', timeout=10):
        scanner = PortScannerAsync()
        scanner.scan(
            hosts=target,
            arguments=nmap_args,
            callback=partial(callback_result, timeout=timeout)
        )
        while scanner.still_scanning():
            scanner.wait(2)


if __name__ == '__main__':
    freeze_support()
    parser = ArgumentParser(prog='Auto Browser')
    subparsers = parser.add_subparsers()

    # Report Parser
    parser_report = subparsers.add_parser('analyze', help='Analyze and browse')
    parser_report.add_argument(
        "nmap_report",
        help="nmap report(xml file) to analyze",
        default=None,
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
        "-t", "--timeout",
        help="http request timeout period",
        type=int,
        default=10,
    )

    args = vars(parser.parse_args())
    if 'nmap_report' in args:
        analyze_and_browse(**args)
    else:
        scan_and_browse(**args)
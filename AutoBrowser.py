#!/usr/bin/env python
########################################################
__author__ = ['Nimrod Levy', 'Tomer Zait']
__license__ = 'GPL v3'
__version__ = '3.0-dev'
__email__ = ['El3ct71k@gmail.com', 'Realgam3@gmail.com']
########################################################

from pprint import pprint
from os import path, mkdir
from functools import partial
from collections import defaultdict
from argparse import ArgumentParser
from nmap import PortScannerYield, PortScanner
from multiprocessing import freeze_support, Pool
from ghost.ghost import Ghost, QSize, TimeoutError


def capture_url(port_tuple, project='project', timeout=10):
    host, port, port_details = port_tuple

    # Create Ghost Object And Set Size
    ghost = Ghost(
        wait_timeout=timeout,
        download_images=True,
        cache_dir=None,
    )
    ghost.webview.resize(QSize(1280, 720))
    ghost.page.setViewportSize(QSize(1280, 720))

    # Try To Open URL
    page = None
    for http_type in ('http', 'https'):
        request_url = '%s://%s:%d/' % (http_type, host, port)
        try:
            page = ghost.open(request_url)[0]
        except TimeoutError:
            pass

        if page:
            # Make Screen Capture
            capture_name = '%s-%s-%d.png' % (http_type, host, port)
            ghost.capture_to(path.join(project, capture_name))
            return host, port, port_details, request_url
    return host, port, port_details, None


def create_report(ports_generator, project='project', timeout=10, pool_size=None):
    if not path.exists(project):
        mkdir(project)

    pool_map = Pool(pool_size).imap(
        func=partial(capture_url, project=project, timeout=timeout),
        iterable=ports_generator,
    )

    report = defaultdict(dict)
    for host, port, port_details, request_url in pool_map:
        report[host][port] = {
            'port_details': port_details,
            'request_url': request_url,
        }
    pprint(dict(report))


def get_ports_decorator(get_ports_function):
    def get_ports_decorated(*args, **kwargs):
        for host, scan_result in get_ports_function(*args, **kwargs):
            if host not in scan_result['scan']:
                continue

            for port, port_details in scan_result['scan'][host]['tcp'].items():
                yield host, port, port_details
    return get_ports_decorated


@get_ports_decorator
def get_ports_from_report(nmap_report):
    scanner = PortScanner()
    scan_result = scanner.analyse_nmap_xml_scan(open(nmap_report).read())
    for host in scan_result['scan']:
        yield host, scan_result


def analyze_and_browse(nmap_report=None, project='project', timeout=10, pool_size=None):
    return create_report(
        ports_generator=get_ports_from_report(nmap_report),
        project=project,
        timeout=timeout,
        pool_size=pool_size
    )


@get_ports_decorator
def get_ports_from_scan(target, nmap_args='-sS -sV'):
    scanner = PortScannerYield()
    for host, scan_result in scanner.scan(hosts=target, arguments=nmap_args):
        yield host, scan_result


def scan_and_browse(target=None, nmap_args='-sS -sV', project='project', timeout=10, pool_size=None):
    print project
    return create_report(
        ports_generator=get_ports_from_scan(target, nmap_args),
        project=project,
        timeout=timeout,
        pool_size=pool_size
    )


def add_global_arguments(*parsers):
    for parser in parsers:
        parser.add_argument(
            "-p", "--project",
            help="project name (folder which contain all the data) [default: project]",
            type=str,
            default="project"
        )
        parser.add_argument(
            "-t", "--timeout",
            help="http request timeout period",
            type=int,
            default=10,
        )


if __name__ == '__main__':
    freeze_support()
    parser_main = ArgumentParser(prog=path.basename(__file__))
    subparsers = parser_main.add_subparsers()

    # Report Parser
    parser_report = subparsers.add_parser('analyze', help='Analyze and browse')
    parser_report.add_argument(
        "nmap_report",
        help="nmap report(xml file) to analyze",
        default=None,
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

    # Add Global Arguments to parsers
    add_global_arguments(parser_scan, parser_report)

    sys_args = vars(parser_main.parse_args())
    if 'nmap_report' in sys_args:
        exit(analyze_and_browse(**sys_args))
    exit(scan_and_browse(**sys_args))
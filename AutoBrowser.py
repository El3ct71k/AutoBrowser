#!/usr/bin/env python
########################################################
__author__ = ['Nimrod Levy', 'Tomer Zait']
__license__ = 'GPL v3'
__version__ = '3.0'
__email__ = ['El3ct71k@gmail.com', 'Realgam3@gmail.com']
########################################################

import re
import sys
import json
import logging
import exceptions
from os import path, mkdir
from functools import partial
from collections import defaultdict
from argparse import ArgumentParser
from nmap import PortScannerYield, PortScanner
from multiprocessing import freeze_support, Pool
from ghost.ghost import Ghost, QSize, TimeoutError

# Global Variable
LOGGER = logging.getLogger('AutoBrowsers')


def configure_logger():
    """
        This function is responsible to configure logging object.
    """
    # Check if logger exist
    if ('LOGGER' not in globals()) or (not LOGGER):
        raise Exception('Logger does not exists, Nothing to configure...')

    # Set logging level
    LOGGER.setLevel(logging.INFO)

    # Create console handler
    formatter = logging.Formatter(
        fmt='[%(asctime)s] %(message)s',
        datefmt='%d-%m-%Y %H:%M'
    )
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    LOGGER.addHandler(ch)


def capture_url(port_tuple, useragent, proxy=None, proxy_auth=None, check_certificates=False,
                java_enabled=False, project='project', timeout=10):
    """
    This function is responsible to create a screen capture from ip and port.
    The procedure of this function creates a URL which consists from ip:port,
    If the url is valid, it opens headless browser and capture the page.
    Finally, it returns tuple with the current details (host, port, details, url).
    :param port_tuple: Tuple of ports.
    :param project: Project name. Default is 'project'
    :param timeout:How long to wait on page load. Default is 10 secs.
    """
    # Extract The Port Tuple
    host, port, details = port_tuple
    # Crate New Port Details Dictionary
    port_details = {
        'state': details['state'].upper(),
        'service': details['name'].upper(),
        'product': "{product_name} {product_version}".format(
            product_name=details['product'],
            product_version=details['version'],
        ).strip()
    }

    # Create Ghost Object And Set Size
    ghost = Ghost()
    session = ghost.start(wait_timeout=timeout, user_agent=useragent, java_enabled=java_enabled, ignore_ssl_errors=check_certificates)
    session.page.setViewportSize(QSize(1280, 720))
    if proxy is not None:
        proxy_regex = re.search(r"(?P<type>socks5|http)://(?P<host>\d+(?:\.\d+){3}):(?P<port>\d+)", proxy)
        if proxy_regex:
            if proxy_auth is not None:
                proxy_auth_regex = re.search(r"(?P<username>.*):(?P<password>.*)", proxy_auth)
                if proxy_auth_regex:
                    session.set_proxy(type_=proxy_regex.group("type"), host=proxy_regex.group("host"), port=int(proxy_regex.group("port")), user=proxy_auth_regex.group("username"), password=proxy_auth_regex.group("password"))
                else:
                    LOGGER.warning("Proxy credential invalid. (Example: username:password)")
                    exit(1)
            else:
                session.set_proxy(type_=proxy_regex.group("type"), host=proxy_regex.group("host"), port=int(proxy_regex.group("port")))
        else:
            LOGGER.warning("Proxy details invalid. (Example: socks5://127.0.0.1:8080")
            exit(1)

    # Try To Open URL
    page = None
    for http_type in ('http', 'https'):
        request_url = '%s://%s:%d/' % (http_type, host, port)
        try:
            page = session.open(request_url)[0]
        except TimeoutError:
            pass

        if page:
            # Make a Screen Capture
            capture_name = '%s-%s-%d.png' % (http_type, host, port)
            session.capture_to(path.join(project, capture_name))
            return host, port, port_details, request_url
    return host, port, port_details, 'Not HTTP/S Service'


def browse_async(ports_generator, check_certificates, java_enabled, useragent, proxy, proxy_auth=None,
                 project='project',timeout=10, pool_size=None):
    """
    This function is responsible to create a async processes with the relevant Nmap report details.
    it calls to capture_url function and creates a dict variable with the details.
    Finally it create a Json file with all the relevant details(host, port, state, product and url).
    """
    # Report Variable
    report = defaultdict(dict)
    # Create Project Folder If Not Exist
    if not path.exists(project):
        mkdir(project)

    try:
        pool_map = Pool(pool_size).imap(
            func=partial(capture_url, proxy=proxy, proxy_auth=proxy_auth, project=project, timeout=timeout, check_certificates=check_certificates, java_enabled=java_enabled, useragent=useragent),
            iterable=ports_generator,
        )

        LOGGER.warning("AutoBrowser Start")
        # Import details from the pool and records on the logger
        for host, port, port_details, request_url in pool_map:
            LOGGER.info("[{ip}]: {port}({state}): {product}({name}) - {url}".format(
                ip=host,
                port=port,
                state=port_details['state'],
                product=port_details['product'],
                name=port_details['service'],
                url=request_url
            ))

            port_details['url'] = request_url
            report[host][port] = port_details
    except Exception, error:
        LOGGER.error("Error: %s" % error)
        return 1
    # Create a json file with the details.
    project_path = path.join(project, 'report.json')
    with open(project_path, 'w') as report_file:
        report_file.write(json.dumps(report, indent=4))
        report_file.flush()
    LOGGER.warning("AutoBrowser Finished (Report in: %s)" % path.abspath(project_path))
    return 0


def get_ports_from_report(nmap_report):
    """
        This function is responsible to take XML file and generate the report details.
    """
    scanner = PortScanner()
    try:
        scan_result = scanner.analyse_nmap_xml_scan(open(nmap_report).read())
        for host in scan_result['scan']:
            try:
                for port, port_details in scan_result['scan'][host]['tcp'].items():
                    yield host, port, port_details
            except exceptions.KeyError:
                pass
    except Exception, error:
        LOGGER.error("Error: %s" % error)
        exit(1)


def analyze_and_browse(useragent, proxy, proxy_auth, nmap_report=None, project='project', timeout=10, pool_size=None, check_certificates=False, java_enabled=False):
    """
        This function start the analyze procedure.
    """
    # Configure Logger
    configure_logger()
    return browse_async(
        ports_generator=get_ports_from_report(nmap_report),
        project=project,
        timeout=timeout,
        pool_size=pool_size,
        check_certificates=check_certificates,
        java_enabled=java_enabled,
        useragent=useragent,
        proxy=proxy,
        proxy_auth=proxy_auth
    )


def get_ports_from_scan(target, nmap_args):
    """
        This function is responsible to run a Nmap scan
        The procedure of this function is gets all the information from the scan results.
        Finally, it create a generator with the details(host, port, port_details)
    """
    scanner = PortScannerYield()
    try:
        # Create the scan and divide the results to variables.
        for host, scan_result in scanner.scan(hosts=target, arguments=nmap_args):
            if host not in scan_result['scan']:
                continue
            for port, port_details in scan_result['scan'][host]['tcp'].items():
                yield host, port, port_details
    except Exception, error:
        LOGGER.error("Error: %s" % error)
        exit(1)

def scan_and_browse(target, useragent, proxy=None, proxy_auth=None, check_certificates=False,
                    java_enabled=False, nmap_args='-sS -sV', project='project', timeout=10, pool_size=None):
    """
        This function start the scan procedure.
    """
    # Configure Logger
    configure_logger()
    if proxy is not None:
        proxy_regex = re.search(r"(?P<type>socks5|http)://(?P<host>\d+(?:\.\d+){3}):(?P<port>\d+)", proxy)
        if proxy_regex:
            nmap_args = "{arguments} --proxies={type}://{host}:{port}".format(arguments=nmap_args,
                                                                    type=proxy_regex.group("type"),
                                                                     host=proxy_regex.group("host"),
                                                                     port=proxy_regex.group("port"))
            if proxy_auth is not None:
                proxy_auth_regex = re.search(r"(?P<username>.*):(?P<password>.*)", proxy_auth)
                if proxy_auth_regex:
                    nmap_args = "{arguments} --proxy-auth={username}:{password}".format(arguments=nmap_args, username=proxy_auth_regex.group("username"), password=proxy_auth_regex.group("password"))
                else:
                    LOGGER.warning("Proxy credential invalid. (Example: username:password)")
                    exit(1)
        else:
            LOGGER.error("Proxy details invalid. (Example: socks5://127.0.0.1:8080")
    return browse_async(
        ports_generator=get_ports_from_scan(target, nmap_args),
        project=project,
        timeout=timeout,
        pool_size=pool_size,
        check_certificates=check_certificates,
        java_enabled=java_enabled,
        useragent=useragent,
        proxy=proxy,
        proxy_auth=proxy_auth
    )


def add_global_arguments(*parsers):
    """
        This function add a global arguments to the argument parser.
    """
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

        parser.add_argument(
            "--check-certificates",
            help="Check if the server certificate against the available certificate authorities.",
            action='store_true',
        )

        parser.add_argument(
            "--useragent",
            help="Set specific user agent",
            default='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 " +\
                    "(KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2'
        )

        parser.add_argument(
            "--java-enabled",
            help="Display Java enviroment",
            action='store_true',
        )

        parser.add_argument(
            "--proxy",
            help="Relay connections through HTTP/socks5 proxy (Example: socks5://127.0.0.1:8080)",
            default=None,
        )

        parser.add_argument(
            "--proxy-auth",
            help="Set proxy credentials. (Example: username:password)",
            default=None,
        )


if __name__ == '__main__':
    # Initialzing base handlers
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

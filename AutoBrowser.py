#!/usr/bin/env python
########################################################
__author__ = ['Nimrod Levy', 'Tomer Zait']
__license__ = 'GPL v3'
__version__ = 'v4.0'
__email__ = ['El3ct71k@gmail.com', 'Realgam3@gmail.com']
########################################################

import os
import re
import sys
import json
import time
import logging
from os import path, mkdir
from argparse import ArgumentParser
from collections import defaultdict
from colorlog import ColoredFormatter
from nmap import PortScannerYield, PortScanner
from multiprocessing import Process, JoinableQueue
from ghost.ghost import Ghost, QSize, TimeoutError, HttpResource

# Global Variable
LOGGER = None

#################


def configure_logger():
    """
        This function is responsible to configure logging object.
    """

    global LOGGER
    LOGGER = logging.getLogger("Autobrowser")
    # Set logging level
    LOGGER.setLevel(logging.DEBUG)

    # Create console handler
    log_colors = {
        'DEBUG': 'bold_blue',
        'INFO': 'green',
        'WARNING': 'purple',
        'ERROR': 'red',
        'CRITICAL': 'bold_yellow',
    }
    formatter = "%(log_color)s[%(asctime)s] - %(message)s%(reset)s"
    formatter = ColoredFormatter(formatter, datefmt='%d-%m-%Y %H:%M', log_colors=log_colors)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    LOGGER.addHandler(ch)


class KeyboardInterruptError(Exception):
    pass


def configure_proxy(session, proxy, proxy_auth):
    """
    This function is responsible to forward requests over Proxy.
    :param session: Ghost session
    :param proxy: Proxy details (IP, PORT)
    :param proxy_auth: Proxy credentials (USERNAME, PASSWORD)
    :return:
    """
    if isinstance(proxy, tuple):
        protocol_type, host, port = proxy
        if isinstance(proxy_auth, tuple):
            username, password = proxy_auth
            session.set_proxy(
                type_=protocol_type, host=host, port=int(port), user=username, password=password
            )
        else:
            session.set_proxy(type_=protocol_type, host=host, port=int(port))
    return session


def browser_process(queue, report_queue, useragent, proxy=None, proxy_auth=None,
                java_enabled=False, project='project', timeout=10, verbose=False):

    """
        This function is responsible to create a hidden browser with seperate process, navigating over URLS from queue and taking a screen captures.
        The procedure of this function creates a URL which consists from ip:port,
        If the url is valid, it opens headless browser and capture the page.
        Finally, it push a tuple with: host, port, details, url to the report queue.

       :param queue: Queue of Tuple of ports.
       :param report_queue: report queue
       :param useragent: Specify User Agent.
       :param proxy:
       :param proxy_auth:
       :param java_enabled:
       :param project: Project name. Default is 'project'
       :param timeout: How long to wait on page load. Default is 10 secs.
       :param verbose:
       :return:
    """
    configure_logger()
    try:

        # Create Ghost Object And Set Size
        ghost = Ghost()
        session = ghost.start(wait_timeout=int(timeout), user_agent=useragent, java_enabled=java_enabled,
                              ignore_ssl_errors=True)
        session = configure_proxy(session, proxy, proxy_auth)

        session.page.setViewportSize(QSize(1280, 720))

        # Extract The Port Tuple
        while not queue.empty():
            port_tuple = queue.get()
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
            is_webapp = False
            # Try To Open URL
            for protocol_type in ['http', 'https']:
                request_url = '%s://%s:%d/' % (protocol_type, host, port)
                capture_name = '%s-%s-%d.png' % (protocol_type, host, port)
                capture_name = path.join(project, capture_name)
                try:
                    page = session.open(request_url)[0]
                    if isinstance(page, HttpResource):
                        # Make a Screen Capture
                        page_content = str(page.content)
                        session.capture_to(capture_name)
                        title = str(re.findall(r"<title>(.*)</title>", page_content, re.DOTALL)[0])
                        port_details['url'] = request_url
                        port_details['page_title'] = title.replace("\r", '').replace("\n", '')
                        page_title = title if title != '' else "No title"
                        LOGGER.info("[{url}] {product}({name}) - {title}".format(
                            product=port_details['product'],
                            name=port_details['service'],
                            url=request_url,
                            title=page_title
                        ))
                        is_webapp = True
                        break

                except TimeoutError:
                    continue
                except IndexError:
                    continue
                except Exception as e:
                    LOGGER.error("Error: %s" % str(e))
                    continue

            if not is_webapp:
                port_details['url'] = "Not HTTP/S Service"
                if verbose:
                    LOGGER.debug("Host: {host}:{port} is not HTTP/S Service".format(
                        host=host,
                        port=port,
                    ))

            report_queue.put((host, port, port_details))
            queue.task_done()
        ghost.exit()
    except KeyboardInterrupt:
        raise KeyboardInterruptError()
    except Exception as e:
        LOGGER.error("Error: %s" % str(e))


def generate_report(project, report_queue):
    """
    This function is responsible to generate report from the queue report.
    :param project: Project name. Default is 'project'
    :param report_queue: Queue report
    :return:
    """
    LOGGER.warning("Generating report...")
    report = defaultdict(dict)
    while not report_queue.empty():
        report_details = report_queue.get()
        host, port, port_details = report_details
        report[host][port] = port_details
        report_queue.task_done()

    project_path = path.join(project, 'report.json')
    with open(project_path, 'w') as report_file:
        report_file.write(json.dumps(report, indent=4))
        report_file.flush()

    LOGGER.warning("AutoBrowser Finished (Report in: %s)" % path.abspath(project_path))


def browse_async(ports_generator, java_enabled, useragent, max_workers=4, proxy=None, proxy_auth=None,
                 project='project', timeout=10, verbose=False):
    """
        This function is responsible to create a async processes managed by queue and push Nmap results to the queue.
        :param ports_generator: The returns report from Nmap scan(object}
        :param java_enabled:
        :param useragent:
        :param max_workers:
        :param proxy:
        :param proxy_auth:
        :param project:
        :param timeout:
        :param verbose:
        :return:
    """
    # Create Project Folder If Not Exist
    if not path.exists(project):
        mkdir(project)

    try:

        queue = JoinableQueue()
        report_queue = JoinableQueue()
        number_services = 0
        for port_tuple in ports_generator:
            number_services += 1
            queue.put(port_tuple)
        if number_services == 0:
            LOGGER.error("Empty results")
            exit()
        LOGGER.info("Analyzing results..")
        workers_num = number_services if number_services <= max_workers else max_workers
        LOGGER.warning("Total workers: %d" % workers_num)
        for w in range(workers_num):
            p = Process(target=browser_process, args=(queue, report_queue, useragent, proxy, proxy_auth, java_enabled, project, timeout, verbose))
            p.daemon = True
            p.start()
        try:
            queue.join()
            # Create a json file with the details.
            generate_report(project, report_queue)
            report_queue.join()
        except (KeyboardInterruptError, KeyboardInterrupt):
            LOGGER.error("Autobrowser aborted.")
            exit()

    except Exception as e:
        LOGGER.error("Error: %s" % str(e))
        return 1
    return 0


def get_ports_from_report(nmap_report):
    """
    This function is responsible to make a generator object from Nmap report
    :param nmap_report: Nmap report location
    :return:
    """

    scanner = PortScanner()
    try:
        scan_result = scanner.analyse_nmap_xml_scan(open(nmap_report.strip('"')).read())
        for host in scan_result['scan']:
            try:
                LOGGER.info("%s - Total ports to browse: %d" % (host, len(scan_result['scan'][host]['tcp'])))
                for port, port_details in scan_result['scan'][host]['tcp'].items():
                    try:
                        yield host, port, port_details
                    except IndexError:
                        pass
            except KeyError:
                pass
    except Exception as e:
        LOGGER.error("Error: %s" % e)
        raise StopIteration


def analyze_and_browse(useragent, proxy, proxy_auth, max_workers, nmap_report=None, project='project', timeout=10, java_enabled=False, verbose=False):
    """
        This function start the analyze procedure.
        :param useragent:
        :param proxy:
        :param proxy_auth:
        :param max_workers:
        :param nmap_report:
        :param project:
        :param timeout:
        :param java_enabled:
        :param verbose:
        :return:
    """
    if not os.path.exists(nmap_report):
        LOGGER.error("Nmap report not found.")
        return

    return browse_async(
        ports_generator=get_ports_from_report(nmap_report),
        project=project, timeout=timeout, max_workers=max_workers,
        java_enabled=java_enabled, useragent=useragent,
        proxy=proxy, proxy_auth=proxy_auth, verbose=verbose
    )


def get_ports_from_scan(target, nmap_args):
    """
        This function is responsible to scanning ports via Nmap and return generator object with the results.
        :param target: IP/HOST or file location.
        :param nmap_args: Nmap args(For example: -F)
        :return:
    """
    scanner = PortScannerYield()
    try:
        # Create the scan and divide the results to variables.
        for host, scan_result in scanner.scan(hosts=target, arguments=nmap_args):
            try:
                if host not in scan_result['scan']:
                    continue
                LOGGER.info("%s - Total ports to browse: %d" % (host, len(scan_result['scan'][host]['tcp'])))
                for port, port_details in scan_result['scan'][host]['tcp'].items():
                    try:
                        yield host, port, port_details
                    except IndexError:
                        pass
            except KeyError:
                pass
    except Exception as e:
        LOGGER.error("Error: %s" % e)
        exit(1)


def scan_and_browse(target, useragent, max_workers, proxy=None, proxy_auth=None,
                    java_enabled=False, nmap_args='-sS -sV', project='project', timeout=10, verbose=False):
    """
        This function start the scan procedure.
        :param target:
        :param useragent:
        :param max_workers:
        :param proxy:
        :param proxy_auth:
        :param java_enabled:
        :param nmap_args:
        :param project:
        :param timeout:
        :param verbose:
        :return:
    """
    if os.path.exists(target):
        with open(target) as target_obj:
            target = str(target_obj.read()).replace("\n", " ")
    LOGGER.info("Scaning..")
    return browse_async(
        ports_generator=get_ports_from_scan(target, nmap_args),
        project=project,
        timeout=timeout, max_workers=max_workers,
        java_enabled=java_enabled,
        useragent=useragent,
        proxy=proxy,
        proxy_auth=proxy_auth,
        verbose=verbose
    )


def add_global_arguments(*parsers):
    """
        This function add a global arguments to the "argument parser" object.
        :param parsers:
        :return:
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
            "-w", "--max-workers",
            help="Max worker processes (Default: 4)",
            type=int,
            default=4,
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
            "--verbose",
            help="Show all checks verbosly",
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


def init_parsers():
    """
    This function is responsible to initialize the argument parser.
    :return:
    """
    parser_main = ArgumentParser(prog=path.basename(__file__), version=__version__)
    subparsers = parser_main.add_subparsers()

    # Report Parser
    parser_report = subparsers.add_parser('analyze', help='Analyze and browse')
    parser_report.add_argument(
        "nmap_report",
        help="nmap report(xml file) to analyze (full path example: \"your path\report.xml\"",
        default=None,
    )

    # Scan Parser
    parser_scan = subparsers.add_parser('scan', help='Scan and browse')
    parser_scan.add_argument(
        "target",
        help="hosts for scan (example: 127.0.0.1, 127.0.0.1/24) or file (ip/hosts file.txt) seperated with new lines.",
        default=None,
    )
    parser_scan.add_argument(
        "-a", "--nmap-args",
        help="nmap args for scan",
        default="-sS -sV"
    )

    # Add Global Arguments to parsers
    add_global_arguments(parser_scan, parser_report)
    return parser_main


def check_settings(sys_args):
    """
        This function is responsible to check if proxy if the proxy configure with valid details.
        :param sys_args: argument dict from argparser.
        :return:
    """

    java_flag = "Yes" if sys_args['java_enabled'] else "No"
    verbose = "Yes" if sys_args['verbose'] else "No"
    if sys_args['proxy']:

        if "nmap_args" in sys_args and "target" in sys_args:
            if "--proxies" not in sys_args['nmap_args']:
                LOGGER.error("To scan the network with Nmap, please use --proxies flag trough Nmap arguments.")
        proxy_regex = re.search(r"(?P<type>socks5|http)://(?P<host>\d+(?:\.\d+){3}):(?P<port>\d+)", sys_args['proxy'])
        if proxy_regex:
            LOGGER.critical(
                "Proxy: On | Protocol: {protocol_type} | IP: {ip} | Port: {port}| Enable java: {java_flag}"
                " | Verbose: {verbose}".format(
                    protocol_type=proxy_regex.group("type"),
                    ip=proxy_regex.group("host"),
                    port=proxy_regex.group("port"),
                    java_flag=java_flag,
                    verbose=verbose

                ))
            sys_args['proxy'] = (proxy_regex.group("type"), proxy_regex.group("host"), proxy_regex.group("port"))
            if sys_args['proxy_auth'] is not None:
                proxy_auth_regex = re.search(r"(?P<username>.*):(?P<password>.*)", sys_args['proxy_auth'])
                if proxy_auth_regex:
                    sys_args['proxy_auth'] = (proxy_auth_regex.group("username"), proxy_auth_regex.group("password"))
                else:
                    LOGGER.error("Proxy credential invalid. (Example: username:password)")
                    exit(-1)
        else:
            LOGGER.error("Proxy details invalid. (Example: socks5://127.0.0.1:8080")
            exit(-1)

    else:
        LOGGER.critical(
            "Proxy: Off | Enable java: {java_flag}| Verbose: {verbose}".format(
                java_flag=java_flag,
                verbose=verbose

            ))
    return sys_args


def main(sys_args):
    sys_args = check_settings(sys_args)
    ft = time.time()
    LOGGER.debug("AutoBrowser {ver} Start".format(ver=__version__))
    if 'nmap_report' in sys_args:
        analyze_and_browse(**sys_args)
    else:
        scan_and_browse(**sys_args)
    LOGGER.info("Running time: %s seconds.\n" % (time.time() - ft))


if __name__ == '__main__':
    parser_main = init_parsers()
    configure_logger()
    sys_args = vars(parser_main.parse_args())
    main(sys_args)

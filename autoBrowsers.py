#!/usr/bin/env python
########################################################
__author__ = ['Nimrod Levy', 'Tomer Zait']
__license__ = 'GPL v3'
__version__ = '2.0'
__email__ = ['El3ct71k@gmail.com', 'Realgam3@gmail.com']
########################################################


import nmap
import grequests
from os import path
from ghost import Ghost
from pprint import pprint
from functools import partial
from multiprocessing import freeze_support, Pool


TIMEOUT = 10


def generate_async_requests(host, ports, url_list):
    # Create Ghost Object
    ghost = Ghost(
        wait_timeout=TIMEOUT,
        download_images=True,
        display=True,
        cache_dir=None,
        viewport_size=(1280, 720),
    )
    ghost.webview.hide()

    # Create Response Handler
    response_handler = partial(callback_response, ghost, url_list)

    for port in ports:
        for http_type in ('http', 'https'):
            yield grequests.get(
                '%s://%s:%d/' % (http_type, host, port),
                timeout=TIMEOUT,
                verify=False,
                callback=response_handler,
            )


def callback_exception(request, exception):
    print("[%s] Request failed" % request.url)


def callback_response(ghost, url_list, response, **kwargs):
    request = response.request
    capture_name = '%s.png' % request.url.replace('/', '').replace(':', '-')

    print('[%s] Request Succeed' % request.url)
    url_list.append(request.url)

    ghost.open(request.url)
    ghost.capture_to(
        path=capture_name,
    )


def callback_result(host, scan_result):
    url_list = []

    print('------------------')
    print('Host: %s' % host)

    ports = scan_result['scan'][host]['tcp']
    print('Ports: ')
    pprint(ports)

    print('HTTP/S: ')
    grequests.map(
        requests=generate_async_requests(host, ports, url_list),
        size=10,
        exception_handler=callback_exception,
    )

    print('URL List: ')
    print(url_list)


def get_hosts_from_xml(results):
    for host_ip in results['scan']:
        yield host_ip


def analyze_nmap_file(xml_file):
    if not path.exists(xml_file):
        print("nmap XML file not exists")
        exit(-1)
    nma = nmap.PortScanner()
    # Add to arg parse
    p = Pool(processes=10)
    with open(xml_file) as nmap_results:
        results = nma.analyse_nmap_xml_scan(nmap_results.read())
        partial_callback_result = partial(callback_result, scan_result=results)
    p.map(partial_callback_result, get_hosts_from_xml(results))

def main():
    freeze_support()
    import_from_file = 'test.xml'
    if import_from_file:
        analyze_nmap_file(import_from_file)
    else:
        nma = nmap.PortScannerAsync()
        nma.scan(hosts='192.168.1.0/31', arguments='-sSV', callback=callback_result)
        while nma.still_scanning():
            nma.wait(2)

if __name__ == '__main__':
    main()
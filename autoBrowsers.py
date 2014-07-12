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
from multiprocessing import freeze_support


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

if __name__ == '__main__':
    freeze_support()

    nma = nmap.PortScanner()
    # Add to arg parse
    import_from_file = 'test.xml'
    if import_from_file:
        if not path.exists(import_from_file):
            print("nmap XML file not exists")
            exit(-1)
        with open(import_from_file) as nmap_results:
            results = nma.analyse_nmap_xml_scan(nmap_results.read())
            for host_ip in results['scan']:
                callback_result(host_ip, results)

    else:
        nma = nmap.PortScannerAsync()
        nma.scan(hosts='192.168.1.0/31', arguments='-sSV', callback=callback_result)
        while nma.still_scanning():
            nma.wait(2)
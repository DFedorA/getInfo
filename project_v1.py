import requests
import argparse
import socket
from threading import Thread
from queue import Queue


def request(url, parameters):
    try:
        return requests.request(method='GET', url="http://" + url, params=parameters)

    except requests.exceptions.ConnectionError:
        pass


def determining_file_system(queue, target_url):
    while not queue.empty():
        word = queue.get_nowait()
        test_url = target_url + '/' + word
        response = request(test_url, '')
        if response:
            print(f'[+] Discovered URL --> {response.url}\n'
                  f'[+] Status code --> {response.status_code}\n')
        queue.task_done()


def determining_subdomains(queue, target_url):
    while not queue.empty():
        word = queue.get_nowait()
        test_url = word + '.' + target_url
        response = request(test_url, '')
        if response:
            print(f'[+] Discovered subdomain --> {test_url}\n')
        queue.task_done()


def determining_portscan(target_ip, thread_count, port_count):
    queue = Queue()
    for port in range(1, port_count):
        queue.put(port)
    for x in range(thread_count):
        thread = Thread(target=portscan, args=(queue, target_ip))
        thread.daemon = True
        thread.start()
    queue.join()


def run_test_url_with_parameters(queue, url, mass_parameters):
    while not queue.empty():
        line = queue.get_nowait()
        for i in range(0, len(mass_parameters)):
            head, sep, tail = mass_parameters[i].partition('=')
            mass_parameters[i] = head + sep + line
        str_parameters = "&".join(str(x) for x in mass_parameters)
        response = request(url, str_parameters)
        print_result(response, False)
        queue.task_done()


def print_result(result, first_start_mode):
    global initial_length
    if len(result.content) != initial_length or first_start_mode:
        if result.status_code == 200 or result.status_code == 302 or result.status_code == 302 or result.status_code == 201:
            print('----------- Current state -----------\n'
                  f'[+] Discovered URL --> {result.url}\n'
                  f'[+] Status code --> {result.status_code}\n'
                  f'[+] Response content length --> {len(result.content)}\n'
                  '--------------------------------------\n')
        else:
            print('----------- Current state -----------\n'
                  f'[-] Possible problems with the request'
                  f'[-] Status code --> {result.status_code}\n'
                  f'[+] URL --> {result.url}\n'
                  f'[+] Response content length --> {len(result.content)}\n'
                  '--------------------------------------\n')


def distribution_thread_and_launch(target_url, thread_count, payload, function):
    queue = Queue()
    with open(payload, "r") as wordlist_file:
        for line in wordlist_file:
            queue.put(line.strip())
    for i in range(thread_count):
        thread = Thread(target=function, args=(queue, target_url))
        thread.daemon = True
        thread.start()
    queue.join()


def test_url_with_parameters(target_url, thread_count, payload):
    global initial_length
    str_parameters = target_url.split('?', 1)[1].strip()
    mass_parameters = str_parameters.split('&')
    url = target_url.split('?', 1)[0].strip()
    if url.find("*") != -1:
        url = url.replace("*", "")
    if str_parameters.find("*") != -1:
        str_parameters = str_parameters.replace("*", "")

    response = request(target_url, str_parameters)
    initial_length = len(response.content)
    print_result(response, True)
    queue = Queue()

    with open(payload, "r") as wordlist_file:
        for line in wordlist_file:
            queue.put(line.strip())
    for i in range(thread_count):
        thread = Thread(target=run_test_url_with_parameters, args=(queue, url, mass_parameters))
        thread.daemon = True
        thread.start()
    queue.join()


def portscan(queue, ip):
    while not queue.empty():
        port = queue.get_nowait()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            con = s.connect((ip, port))
            print(f'[+] Port: {port} --> service name: {socket.getservbyport(port, "tcp")}')
            con.close()
            queue.task_done()
        except:
            queue.task_done()


initial_length = 0
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Videos to images')
    parser.add_argument('--url', type=str, help='Input URL address', required=True)
    parser.add_argument('--threads', type=int, help='Input number of threads')
    parser.add_argument('--payload', type=str, help="Input path to your file with user payloads")
    parser.add_argument('-js', action='store_true', help='Flag for finds javascript files')
    parser.add_argument('-php', action='store_true', help='Flag for finds php files')
    parser.add_argument('-index', action='store_true', help='Flag for finds index files')
    parser.add_argument('-subdomain', action='store_true', help="Flag for finds subdomains")
    parser.add_argument('-params', action='store_true', help="Flag for enumerate query params")
    parser.add_argument('--port', type=int, help="Flag for to get working ports")

    args = parser.parse_args()
    if args.url == None:
        print("{}Input URL address in format example.com")
        exit()
    if args.threads == None:
        args.threads = 25
    elif args.threads != None:
        threads = args.threads

    url = args.url
    if args.port != None:
        DNS_record = socket.gethostbyname(url)
        print(f'Host: {DNS_record} ({url})')
        print('Protocol : tcp')
        determining_portscan(DNS_record, args.threads, args.port)
    else:
        if args.params:
            args.payload = 'query'
            test_url_with_parameters(url, args.threads, args.payload)
        elif args.subdomain:
            args.payload = 'subdomains'
            distribution_thread_and_launch(url, args.threads, args.payload, determining_subdomains)
        else:
            if args.payload == None:
                if args.js:
                    args.payload = 'js-wordlist'
                elif args.php:
                    args.payload = 'php-wordlist'
                elif args.index:
                    args.payload = 'dir-wordlist'
                else:
                    args.payload = 'general-wordlist'
            distribution_thread_and_launch(url, args.threads, args.payload, determining_file_system)

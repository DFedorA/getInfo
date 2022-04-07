import argparse
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from queue import Queue
from threading import Thread

import requests
from fake_useragent import UserAgent
from xmltodict import parse

ua = UserAgent()


def request(url, parameters=''):
    try:
        if url.find('http://') == -1 and url.find('https://') == -1:
            url = "https://" + url
        return requests.request(method='GET', url=url, params=parameters,
                                allow_redirects=False), False
    except requests.exceptions.ConnectionError:
        return None, None
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': ua.random})
                return urllib.request.urlopen(req), True
            except urllib.error.HTTPError:
                pass
        else:
            return None, None


def check_wordpress(target_url, thread_count, payload):
    print("[+] Running WordPress version detector\n")

    response, main_mode = request(target_url)
    if main_mode:
        content = response.read().decode(response.headers.get_content_charset())
    else:
        content = str(response.text)

    if response is not None:
        match = re.search(r'WordPress ([0-9]+\.[0-9]+\.?[0-9]*)', content)
        if match:
            print(f'[+] Wordpress version --> {match.group(1)}\n')
            distribution_thread_and_launch(target_url, thread_count, payload, determining_file_system)
            return True
        else:
            print("[+] Couldn't get Wordpress version\n")
            return False
    else:
        print("[+] Couldn't get Wordpress version\n")
        return False


def check_joomla(target_url, thread_count, payload):
    print("[+] Running Joomla version detector\n")

    app_xml_header = "application/xml"
    text_xml_header = "text/xml"
    language_file = "/language/en-GB/en-GB.xml"
    manifest_file = "/administrator/manifests/files/joomla.xml"

    response, main_mode = request(target_url + language_file)
    if main_mode:
        content = response.read().decode(response.headers.get_content_charset())
        status_code = response.getcode()
    else:
        content = response.content
        status_code = response.status_code

    if response is not None and (status_code == 200 and app_xml_header or text_xml_header in response.headers):
        data = parse(content)
        version = data["metafile"]["version"]
        print(f'[+] Joomla version --> {version}\n')
        distribution_thread_and_launch(target_url, thread_count, payload, determining_file_system)
        return True
    response, main_mode = request(target_url + manifest_file)
    if main_mode:
        content = response.read().decode(response.headers.get_content_charset())
        status_code = response.getcode()
    else:
        content = response.content
        status_code = response.status_code
    if response is not None and (status_code == 200 and app_xml_header or text_xml_header in response.headers):
        data = parse(content)
        version = data["extesion"]["version"]
        print(f'[+] Joomla version --> {version}\n')
        distribution_thread_and_launch(target_url, thread_count, payload, determining_file_system)
        return True
    print("[+] Couldn't get Joomla version\n")
    return False


def check_cloudflare(target_url):
    print("[+] Running Cloudflare detector\n")

    response, main_mode = request(target_url)
    if main_mode:
        content = response.read().decode(response.headers.get_content_charset())
    else:
        content = response.content.decode('utf-8')
    verification = False
    for header in response.headers.items():
        if header[0].lower() == "cf-ray":
            verification = True
            break
        if re.search(r'__cfduid=|cloudflare-nginx|cloudflare[-]', header[1], re.I) is not None:
            verification = True
            break
    if verification is False:
        if re.search(r'CloudFlare Ray ID:|var CloudFlare=', content) is not None:
            verification = True
    if verification:
        print('CloudFlare Web Application Firewall (CloudFlare)')


def check_aws(target_url):
    print("[+] Running AWS detector\n")

    response, main_mode = request(target_url)
    for header in response.headers.items():
        if re.search(r'\bAWS', header[1], re.I) is not None:
            print("Amazon Web Services Web Application Firewall (Amazon)")


def check_django(target_url):
    print("[+] Running Django detector\n")

    response, main_mode = request(target_url)
    verification = False
    for header in response.headers.items():
        if re.search("wsgiserver/", header[1]) is not None:
            verification = True
            break
        if re.search("python/", header[1]) is not None:
            verification = True
            break
        if re.search("csrftoken=", header[1]) is not None:
            verification = True
            break
    if verification:
        print("Django (Python Framework)")


def determining_file_system(queue, target_url):
    while not queue.empty():
        word = queue.get_nowait()
        if word[0] == '/':
            test_url = target_url + word
        else:
            test_url = target_url + '/' + word
        response, main_mode = request(test_url)
        if response:
            if main_mode:
                status_code = response.getcode()
            else:
                status_code = response.status_code
            if status_code == 200:
                print(f'[+] Discovered URL --> {response.url}\n'
                      f'[+] Status code --> {status_code}\n')
        queue.task_done()


def determining_subdomains(queue, target_url):
    while not queue.empty():
        word = queue.get_nowait()
        test_url = word + '.' + target_url
        response, main_mode = request(test_url)
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
        response, main_mode = request(url, str_parameters)
        print_result(response, main_mode, False)
        queue.task_done()


def print_result(result, mode, first_start_mode):
    global initial_length
    if mode:
        content = result.read().decode(result.headers.get_content_charset())
        status_code = result.getcode()
    else:
        content = result.content
        status_code = result.status_code
    if len(content) != initial_length or first_start_mode:
        if status_code == 200 or status_code == 302 or status_code == 302 or status_code == 201:
            print('----------- Current state -----------\n'
                  f'[+] Discovered URL --> {result.url}\n'
                  f'[+] Status code --> {status_code}\n'
                  f'[+] Response content length --> {len(content)}\n'
                  '--------------------------------------\n')
        else:
            print('----------- Current state -----------\n'
                  f'[-] Possible problems with the request\n'
                  f'[-] Status code --> {status_code}\n'
                  f'[+] URL --> {result.url}\n'
                  f'[+] Response content length --> {len(content)}\n'
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

    response, main_mode = request(target_url, str_parameters)
    if main_mode:
        content = response.read().decode(response.headers.get_content_charset())
    else:
        content = response.content
    initial_length = len(content)
    print_result(response, main_mode, True)
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
    parser = argparse.ArgumentParser(description='Gathering information before pentest')
    parser.add_argument('--url', type=str, help='Input URL address', required=True)
    parser.add_argument('--threads', type=int, help='Input number of threads')
    parser.add_argument('--payload', type=str, help="Input path to your file with user payloads")
    parser.add_argument('-js', action='store_true', help='Flag for finds javascript files')
    parser.add_argument('-php', action='store_true', help='Flag for finds php files')
    parser.add_argument('-index', action='store_true', help='Flag for finds index files')
    parser.add_argument('-subdomain', action='store_true', help="Flag for finds subdomains (ex: site.com)")
    parser.add_argument('-params', action='store_true', help="Flag for enumerate query params")
    parser.add_argument('--port', type=int, help="Flag for to get working ports (ex: site.com)")
    parser.add_argument('-ws', action='store_true', help='Flag for detect wordpress (cms)')
    parser.add_argument('-jm', action='store_true', help='Flag for detect joomla (cms)')
    parser.add_argument('-django', action='store_true', help='Flag for detect django (framework)')
    parser.add_argument('-cloudflare', action='store_true', help='Flag for detect cloudflare (waf)')
    parser.add_argument('-aws', action='store_true', help='Flag for detect aws (waf)')

    args = parser.parse_args()
    if args.url is None:
        print("{}Input URL address in format example.com")
        exit()
    if args.threads is None:
        args.threads = 25
    elif args.threads is not None:
        threads = args.threads

    url = args.url
    if url.endswith('/') and args.params is False:
        url = url.strip('/')

    if args.aws:
        check_aws(url)
    if args.cloudflare:
        check_cloudflare(url)
    if args.django:
        check_django(url)
    if args.jm:
        if args.payload is None:
            args.payload = 'wordlists/urls-joomla'
        check_joomla(url, args.threads, args.payload)
    if args.ws:
        if args.payload is None:
            args.payload = 'wordlists/urls-wordpress'
        check_wordpress(url, args.threads, args.payload)
    if args.port is not None:
        DNS_record = socket.gethostbyname(url)
        print(f'Host: {DNS_record} ({url})')
        print('Protocol : tcp')
        determining_portscan(DNS_record, args.threads, args.port)
    else:
        if args.params:
            args.payload = 'wordlists/query'
            print("[+] Running enumerate query params\n")
            test_url_with_parameters(url, args.threads, args.payload)
        elif args.subdomain:
            args.payload = 'wordlists/subdomains'
            print("[+] Running determining subdomains\n")
            distribution_thread_and_launch(url, args.threads, args.payload, determining_subdomains)
        else:
            if args.payload is None:
                if args.js:
                    args.payload = 'wordlists/js-wordlist'
                elif args.php:
                    args.payload = 'wordlists/php-wordlist'
                elif args.index:
                    args.payload = 'wordlists/dir-wordlist'
                else:
                    args.payload = 'wordlists/general-wordlist'
            print("[+] Running determining file system\n")
            distribution_thread_and_launch(url, args.threads, args.payload, determining_file_system)

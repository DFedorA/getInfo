from xmltodict import parse
from modules.FileSystemSubdomains import *

def check_wordpress(target_url, thread_count, payload):
    print("[+] Running WordPress version detector\n")

    response, main_mode = request(target_url, 'GET')
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

    response, main_mode = request(target_url + language_file, 'GET')
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
    response, main_mode = request(target_url + manifest_file, 'GET')
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

    response, main_mode = request(target_url, 'GET')
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

    response, main_mode = request(target_url, 'GET')
    for header in response.headers.items():
        if re.search(r'\bAWS', header[1], re.I) is not None:
            print("Amazon Web Services Web Application Firewall (Amazon)")


def check_django(target_url):
    print("[+] Running Django detector\n")

    response, main_mode = request(target_url, 'GET')
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


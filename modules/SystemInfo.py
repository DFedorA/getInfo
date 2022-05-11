from xmltodict import parse
from modules.FileSystemSubdomains import *
import json


def check_wordpress(target_url, thread_count, payload, ntls):
    print("[+] Running WordPress version detector\n")
    response, main_mode = request(target_url + '/', 'GET', ntls)
    if response is not None:
        if main_mode:
            content = response.read().decode(response.headers.get_content_charset())
        else:
            content = str(response.text)
        match = re.search(r'WordPress ([0-9]+\.[0-9]+\.?[0-9]*)', content)
        if match:
            print(f'[+] Wordpress version --> {match.group(1)}\n')
            get_wordpress_cve(match.group(1),ntls)
            print("[+] Running determining file system\n")
            distribution_thread_and_launch(target_url, thread_count, payload, determining_file_system, ntls)
            return True
        else:
            print("[+] Couldn't get Wordpress version\n")
            return False
    else:
        print("[+] Couldn't get Wordpress version\n")
        return False


def get_wordpress_cve(version, ntls):
    cve_url = f'https://www.wpvulnerability.net/core/{version}/'
    response, main_mode = request(cve_url, 'GET', ntls)
    if main_mode:
        content = response.read().decode(response.headers.get_content_charset())
    else:
        content = str(response.text)
    json_content = json.loads(content)
    if len(json_content['data']['vulnerability']) > 0:
        print("[+] Found vulnerabilities\n")
        for item in json_content['data']['vulnerability']:
            print(f'[+] Name --> {item["source"][0]["name"]}\n'
                  f'[+] Link --> {item["source"][0]["link"]}\n'
                  '--------------------------------------\n')

def check_joomla(target_url, thread_count, payload, ntls):
    print("[+] Running Joomla version detector\n")
    app_xml_header = "application/xml"
    text_xml_header = "text/xml"
    language_file = "/language/en-GB/en-GB.xml"
    manifest_file = "/administrator/manifests/files/joomla.xml"

    response, main_mode = request(target_url + '/' + language_file, 'GET', ntls)
    if main_mode:
        status_code = response.getcode()
    else:
        status_code = response.status_code

    if response is not None and (status_code == 200 and app_xml_header or text_xml_header in response.headers):
        if main_mode:
            content = response.read().decode(response.headers.get_content_charset())
        else:
            content = response.content
        data = parse(content)
        version = data["metafile"]["version"]
        print(f'[+] Joomla version --> {version}\n')
        get_joomla_cve(version, ntls)
        print("[+] Running determining file system\n")
        distribution_thread_and_launch(target_url, thread_count, payload, determining_file_system, ntls)
        return True
    response, main_mode = request(target_url + manifest_file, 'GET', ntls)
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
        get_joomla_cve(version, ntls)
        print("[+] Running determining file system\n")
        distribution_thread_and_launch(target_url, thread_count, payload, determining_file_system,ntls)
        return True
    print("[+] Couldn't get Joomla version\n")
    return False


def get_joomla_cve(version, ntls):
    cve_url = f'https://services.nvd.nist.gov/rest/json/cpes/1.0?cpeMatchString=cpe:/a:joomla:joomla%21:{version}&addOns=cves'
    response, main_mode = request(cve_url, 'GET', ntls)
    if main_mode:
        content = response.read().decode(response.headers.get_content_charset())
    else:
        content = str(response.text)
    json_content = json.loads(content)
    if len(json_content['result']['cpes']) > 0:
        print("[+] Found vulnerabilities\n")
        print('CVE: ', str(json_content['result']['cpes'][0]['vulnerabilities']))


def check_cloudflare(target_url, ntls):
    print("[+] Running Cloudflare detector\n")

    response, main_mode = request(target_url, 'GET', ntls)
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


def check_aws(target_url, ntls):
    print("[+] Running AWS detector\n")

    response, main_mode = request(target_url, 'GET', ntls)
    for header in response.headers.items():
        if re.search(r'\bAWS', header[1], re.I) is not None:
            print("Amazon Web Services Web Application Firewall (Amazon)")


def check_django(target_url, ntls):
    print("[+] Running Django detector\n")

    response, main_mode = request(target_url, 'GET', ntls)
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

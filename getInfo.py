import argparse
from art import tprint
from datetime import datetime

from modules.Parameters import test_url_with_parameters
from modules.Port import determining_portscan
from modules.SystemInfo import *
from modules.CrawlURL import run_crawl_url

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gathering information before pentest')
    parser.add_argument('--url', type=str, help='Input URL address', required=True)
    parser.add_argument('--threads', type=int, help='Input number of threads')
    parser.add_argument('--payload', type=str, help="Input path to your file with user payloads")
    parser.add_argument('--filter', type=int, help="Input path to filer status (ex: 301)")
    parser.add_argument('--anomaly', type=int, help="Input path to enter a range of anomalies")
    parser.add_argument('--method', type=str, help='Input method (GET,POST), default:GET')
    parser.add_argument('--sitemap', type=int, help='Input to get a sitemap from the links, sitemap - number of '
                                                    'links, (ex: https://site.com)')
    parser.add_argument('-port', action='store_true', help="Flag for to get working ports and possible OS (ex: "
                                                           "site.com) (Nmap)")
    parser.add_argument('-ntls', action='store_true', help='Flag for selection http or https, default:https')
    parser.add_argument('-js', action='store_true', help='Flag for finds javascript files')
    parser.add_argument('-php', action='store_true', help='Flag for finds php files')
    parser.add_argument('-index', action='store_true', help='Flag for finds index files')
    parser.add_argument('-subdomain', action='store_true', help="Flag for finds subdomains (ex: site.com)")
    parser.add_argument('-params', action='store_true', help="Flag for enumerate query params")
    parser.add_argument('-ws', action='store_true', help='Flag for detect wordpress (cms), plugins, CVE for version')
    parser.add_argument('-jm', action='store_true', help='Flag for detect joomla (cms), plugins, CVE for version')
    parser.add_argument('-django', action='store_true', help='Flag for detect django (framework)')
    parser.add_argument('-cloudflare', action='store_true', help='Flag for detect cloudflare (waf)')
    parser.add_argument('-aws', action='store_true', help='Flag for detect aws (waf)')
    parser.add_argument('-graph', action='store_true', help='Flag for creation and output graph internal links')

    start_time = datetime.now()
    tprint('getInfo')
    logging.basicConfig(format="%(message)s", level=logging.INFO)

    args = parser.parse_args()
    if args.url is None:
        print("{}Input URL address in format example.com")
        exit()
    if args.ntls:
        args.ntls = 'http'
    if args.threads is None:
        args.threads = 350
    elif args.threads is not None:
        threads = args.threads
    if args.filter is None:
        args.filter = False
    if args.anomaly is None:
        args.anomaly = False
    if args.method is None:
        args.method = ''

    url = args.url
    if url.endswith('/') and args.params is False:
        url = url.strip('/')

    if args.aws:
        check_aws(url, args.ntls)
    elif args.cloudflare:
        check_cloudflare(url, args.ntls)
    elif args.django:
        check_django(url, args.ntls)
    elif args.jm:
        if args.payload is None:
            args.payload = 'wordlists/urls-joomla'
        check_joomla(url, args.threads, args.payload, args.ntls)
    elif args.ws:
        if args.payload is None:
            args.payload = 'wordlists/urls-wordpress'
        check_wordpress(url, args.threads, args.payload, args.ntls)
    else:
        if args.port:
            determining_portscan(url)
        else:
            if args.sitemap is not None:
                run_crawl_url(url, args.sitemap, args.graph)
            else:
                if args.params:
                    args.payload = 'wordlists/query'
                    print("[+] Running enumerate query params\n")
                    test_url_with_parameters(url, args.threads, args.payload, args.filter, args.anomaly, args.method,
                                             args.ntls)
                elif args.subdomain:
                    args.payload = 'wordlists/subdomains'
                    print("[+] Running determining subdomains\n")
                    distribution_thread_and_launch(url, args.threads, args.payload, determining_subdomains, args.ntls)
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
                    distribution_thread_and_launch(url, args.threads, args.payload, determining_file_system, args.ntls)

    print('Lead time:', datetime.now() - start_time)

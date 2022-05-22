from socket import gethostbyname
import nmap3


def determining_portscan(url):
    target_ip = get_dns_info(url)
    nmap = nmap3.Nmap()
    os_results = nmap.nmap_os_detection(target_ip)
    print('OS')
    for result in os_results[target_ip]['osmatch']:
        print(f'[+] Accuracy --> {result["accuracy"]} Name --> {result["name"]}')
    print('--------------------------------------\n')
    print('Ports')
    for result in os_results[target_ip]['ports']:
        print(
            f'[+] Protocol --> {result["protocol"]} Port --> {result["portid"]} Service --> {result["service"]["name"]}')


def get_dns_info(url):
    dns = gethostbyname(url)
    print(f'Host: {dns} ({url})')
    return dns

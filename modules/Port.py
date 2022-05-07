from queue import Queue
from threading import Thread
import socket
import logging

def determining_portscan(target_ip, thread_count, port_count):
    queue = Queue()
    for port in range(1, port_count):
        queue.put(port)
    for x in range(thread_count):
        thread = Thread(target=portscan, args=(queue, target_ip))
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
            logging.info(f'[+] Port: {port} --> service name: {socket.getservbyport(port, "tcp")}')
            con.close()
            queue.task_done()
        except:
            queue.task_done()


def get_dns_info(url):
    dns = socket.gethostbyname(url)
    print(f'Host: {dns} ({url})')
    print('Protocol : tcp')
    return dns

import requests
import urllib.error
import urllib.parse
import urllib.request
from queue import Queue
from threading import Thread
from fake_useragent import UserAgent

ua = UserAgent()


def request(url, method, ntls, parameters='', filter=False, data=''):
    try:
        if url.find('http://') == -1 and url.find('https://') == -1:
            if ntls == 'http':
                url = "http://" + url
            else:
                url = "https://" + url

        res = requests.request(method=method, url=url, params= parameters, data=data,
                               allow_redirects=False)
        if res.status_code == 403:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': ua.random})
                res = urllib.request.urlopen(req)
                if filter is False:
                    return res, True
                elif res.status_code == filter:
                    return res, True
                else:
                    return None, None
            except urllib.error.HTTPError:
                return None, None
        else:
            if filter is False:
                return res, False
            elif res.status_code == filter:
                return res, False
            else:
                return None, None
    except requests.exceptions.ConnectionError:
        return None, None


def distribution_thread_and_launch(target_url, thread_count, payload, function, ntls):
    queue = Queue()
    with open(payload, "r") as wordlist_file:
        for line in wordlist_file:
            queue.put(line.strip())
    for i in range(thread_count):
        thread = Thread(target=function, args=(queue, target_url, ntls))
        thread.daemon = True
        thread.start()
    queue.join()

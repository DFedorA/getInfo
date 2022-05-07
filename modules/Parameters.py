import logging
from modules.Requests import *

initial_length = 0
not_found_length = 0

def print_current_result(result):
    len_content = len(result.content)
    status_code = result.status_code
    time = result.elapsed
    print('----------- Current state -----------\n'
          f'[+] URL --> {result.url}\n'
          f'[+] Status code --> \033[32m{status_code}\033[0m\n'
          f'[+] Response time --> {time}\n'
          f'[+] Response content length --> {len_content}\n'
          '--------------------------------------\n')


def print_not_found_result(result):
    len_content = len(result.content)
    status_code = result.status_code
    time = result.elapsed
    print('----------- Not found-----------\n'
          f'[+] URL --> {result.url}\n'
          f'[+] Status code --> \033[31m{status_code}\033[0m\n'
          f'[+] Response time --> {time}\n'
          f'[+] Response content length --> {len_content}\n'
          '--------------------------------------\n')


def print_result(result, filter, anomaly):
    global initial_length, not_found_length
    len_content = len(result.content)
    status_code = result.status_code
    time = result.elapsed
    if len_content != initial_length and len_content != not_found_length:
        if filter is False:
            status = status_code == 200 or status_code == 302 or status_code == 201
        else:
            status = filter
        if anomaly <= abs(initial_length - len_content):
            if status:
                logging.info(f'[+] URL --> {result.url}\n'
                             f'[+] Status code --> \033[32m{status_code}\033[0m\n'
                             f'[+] Response time --> {time}\n'
                             f'[+] Response content length --> {len_content}\n'
                             '--------------------------------------\n')
            else:
                logging.info(
                    f'[-] Possible problems with the request\n'
                    f'[+] URL --> {result.url}\n'
                    f'[-] Status code --> {status_code}\n'
                    f'[+] Response content length --> {len_content}\n'
                    '--------------------------------------\n')


def test_url_with_parameters(target_url, thread_count, payload, filter, anomaly, method):
    global initial_length, not_found_length
    str_parameters = target_url.split('?', 1)[1].strip()
    mass_parameters = str_parameters.split('&')
    url = target_url.split('?', 1)[0].strip()
    if url.find("*") != -1:
        url = url.replace("*", "")

    response, main_mode = request(target_url, method, '', filter)
    content = response.content
    initial_length = len(content)
    print_current_result(response)

    not_found_url = 2 * target_url.split('?')[0]
    response, main_mode = request(not_found_url, method, '', filter)
    content = response.content
    not_found_length = len(content)
    print_not_found_result(response)

    queue = Queue()
    with open(payload, "r") as wordlist_file:
        for line in wordlist_file:
            queue.put(line.strip())
    for i in range(thread_count):
        thread = Thread(target=run_test_url_with_parameters,
                        args=(queue, url, mass_parameters, filter, anomaly, method))
        thread.daemon = True
        thread.start()
    queue.join()

def run_test_url_with_parameters(queue, url, mass_parameters, filter, anomaly, method):
    while not queue.empty():
        line = queue.get_nowait()
        for i in range(0, len(mass_parameters)):
            head, sep, tail = mass_parameters[i].partition('=')
            mass_parameters[i] = head + sep + line
        str_parameters = "&".join(str(x) for x in mass_parameters)
        response, main_mode = request(url, method, str_parameters)
        print_result(response, filter, anomaly)
        queue.task_done()

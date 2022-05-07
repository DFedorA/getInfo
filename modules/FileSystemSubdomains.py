import logging
import re
import warnings
from colorama import init
from modules.Requests import *

init(autoreset=True)
warnings.simplefilter("ignore", UserWarning)
from bs4 import BeautifulSoup as bs


def determining_subdomains(queue, target_url):
    while not queue.empty():
        word = queue.get_nowait()
        test_url = word + '.' + target_url
        response, main_mode = request(test_url, 'GET')
        if response:
            logging.info(f'[+] Discovered subdomain --> {test_url}\n')
        queue.task_done()


def parameter_search(text, test_url):
    re_input_names = re.compile(r'''(?i)<input.+?name=["']?([^"'\s>]+)''')
    re_input_ids = re.compile(r'''(?i)<input.+?id=["']?([^"'\s>]+)''')
    re_action = re.compile(r'''(?i)<form.+?action=["']?([^"'\s>]+)''')
    re_method = re.compile(r'''(?i)<form.+?method=["']?([^"'\s>]+)''')
    try:
        soup = bs(text, "lxml")
        forms = soup.find_all('form')
        info_form = []
        for form in forms:
            form = str(form)
            potential_params = []
            input_names = re_input_names.findall(form)
            potential_params += input_names

            input_ids = re_input_ids.findall(form)
            potential_params += input_ids
            if len(potential_params) != 0:
                method = re_method.findall(form)
                action = re_action.findall(form)
                info_form.append({'method': method, 'action': action, 'potential_params': potential_params})
        if len(info_form) != 0:
            with open("data_found_pages", "a") as file:
                file.write(str({f'{test_url}': info_form}) + '\n')
    except (AttributeError, KeyError) as e:
        pass


def determining_file_system(queue, target_url):
    while not queue.empty():
        word = queue.get_nowait()
        if word[0] == '/':
            test_url = target_url + word
        else:
            test_url = target_url + '/' + word
        response, main_mode = request(test_url, 'GET')
        try:
            if response.status_code == 508:
                logging.info(f'[+] Resource Limit Is Reached\n'
                             f'[+] Reduce the number of threads  \n'
                             f'[+] Press to exit: Ctrl + Pause  \n'
                             f'[+] Status code -->\033[31m {response.status_code} \033[0m\n'
                             '--------------------------------------\n')
                return
        except:
            pass
        if response:
            if main_mode:
                status_code = response.getcode()
                content = response.read().decode(response.headers.get_content_charset())
            else:
                status_code = response.status_code
                content = response.text
            if status_code == 200 or status_code == 302 or status_code == 201:
                parameter_search(content, response.url)
                if status_code == 200:
                    logging.info(f'[+] Discovered URL --> {response.url}\n'
                                 f'[+] Status code -->\033[32m {status_code} \033[0m\n'
                                 '--------------------------------------\n')
                else:
                    logging.info(f'[+] Discovered URL --> {response.url}\n'
                                 f'[+] Status code -->\033[33m {status_code} \033[0m\n'
                                 '--------------------------------------\n')
        queue.task_done()

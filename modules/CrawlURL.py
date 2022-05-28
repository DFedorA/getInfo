import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from threading import Timer
import json
import networkx as nx
import matplotlib.pyplot as plt

internal_urls_set = set()
external_urls_set = set()
internal_urls = {}
total_urls_visited = 0
t = None


def print_manager(max_urls):
    global t
    t = Timer(1, print_manager, [max_urls])
    t.start()
    print(
        f'[+] Total internal links --> {len(internal_urls_set)} Total external links --> {len(external_urls_set)} Total '
        f'URLs --> {len(external_urls_set) + len(internal_urls_set)} Total crawled URLs --> {total_urls_visited}')
    if total_urls_visited >= max_urls:
        t.cancel()
        return


def get_all_website_links(url):
    urls = set()
    domain_name = urlparse(url).netloc
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            continue
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if not bool(urlparse(href).netloc) and bool(urlparse(href).scheme):
            continue
        if href in internal_urls:
            item = internal_urls.get(href)
            item.append(url)
            internal_urls[href] = item
            continue
        if href in internal_urls_set:
            continue
        if domain_name not in href:
            if href not in external_urls_set:
                external_urls_set.add(href)
            continue
        urls.add(href)
        internal_urls_set.add(href)
        internal_urls[href] = [url]

    return urls


def add_edge(f_item, s_item, graph=None):
    graph.add_edge(f_item, s_item)
    graph.add_edge(s_item, f_item)


def crawl(url, max_urls):
    global total_urls_visited
    total_urls_visited += 1
    links = get_all_website_links(url)
    for link in links:
        if total_urls_visited > max_urls:
            break
        crawl(link, max_urls)


def run_crawl_url(url, max_urls, graph):

    print_manager(max_urls)
    crawl(url, max_urls)
    domain_name = urlparse(url).netloc

    with open(f'{domain_name}_dependent_internal_links', "w") as f:
        f.write(json.dumps(internal_urls))

    with open(f'{domain_name}_internal_links', "w") as f:
        for internal_link in internal_urls_set:
            f.write(internal_link + '\n')

    with open(f'{domain_name}_external_links', "w") as f:
        for external_link in external_urls_set:
            f.write(external_link + '\n')
    t.cancel()
    if graph:
        graph = nx.Graph()
        for item in internal_urls_set:
            graph.add_node(urlparse(item).path)

        for item in internal_urls:
            iter = internal_urls.get(item)
            for elem in iter:
                add_edge(urlparse(item).path, urlparse(elem).path, graph=graph)
        nx.draw_circular(graph,
                         node_color='white',
                         node_size=1000,
                         with_labels=True,
                         node_shape="o")
        plt.show()

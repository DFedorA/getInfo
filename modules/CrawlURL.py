import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from threading import Timer

internal_urls = set()
external_urls = set()
total_urls_visited = 0


def print_manager(max_urls):
    t = Timer(1, print_manager, [max_urls])
    t.start()
    print(
        f'\r[+] Total internal links --> {len(internal_urls)} Total external links --> {len(external_urls)} Total '
        f'URLs --> {len(external_urls) + len(internal_urls)} Total crawled URLs --> {total_urls_visited} \r')
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
            continue
        if domain_name not in href:
            if href not in external_urls:
                external_urls.add(href)
            continue
        urls.add(href)
        internal_urls.add(href)
    return urls


def crawl(url, max_urls):
    global total_urls_visited
    total_urls_visited += 1
    links = get_all_website_links(url)
    for link in links:
        if total_urls_visited > max_urls:
            break
        crawl(link, max_urls)


def run_crawl_url(url, max_urls):
    print_manager(max_urls)
    crawl(url, max_urls)
    domain_name = urlparse(url).netloc

    with open(f"{domain_name}_internal_links", "w") as f:
        for internal_link in internal_urls:
            print(internal_link.strip(), file=f)

    with open(f"{domain_name}_external_links", "w") as f:
        for external_link in external_urls:
            print(external_link.strip(), file=f)

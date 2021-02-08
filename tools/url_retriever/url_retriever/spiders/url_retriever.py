# -*- coding: utf-8 -*-

import scrapy
import os
import re


class UrlRetriever(scrapy.Spider):
    name = "url_retriever"

    # Remove duplicates from a list
    def remove_duplicates(data_list):
        seen = {}
        return [seen.setdefault(x, x) for x in data_list if x not in seen]

    # Store final URLs
    post_urls = os.path.join(os.getcwd(), 'URLs/post_urls.txt')
    https_urls = os.path.join(os.getcwd(), 'URLs/https_urls.txt')

    # Open list of URLs from file
    with open('URLs/urls.txt') as f:
        # Process the URLs, ensuring they are in the correct format
        start_urls = [url.strip() and url.rstrip() for url in f.readlines()]

    # Ensure URL begins with a protocol
    for url in range(len(start_urls)):
        if not start_urls[url].startswith(('http://', 'https://')):
            start_urls[url] = 'http://' + start_urls[url]

    # Remove any duplicates
    start_urls = remove_duplicates(start_urls)

    # Delete files if they already exists
    if os.path.exists(post_urls):
        os.remove(post_urls)
    if os.path.exists(https_urls):
        os.remove(https_urls)

    # Crawl each of the URLs, catching errors where they occur
    def start_requests(self):
        for url in self.start_urls:
            yield scrapy.Request(url, callback=self.parse, errback=self.handle_failed_connections, dont_filter=True)

    # Handle any connection related errors
    def handle_failed_connections(self, failure):
        pass

    def parse(self, response):
        url = response.url

        # If the hostname wasn't found, virginmedia (my ISP) search for it
        # Need to log the failed URL and skip any further processing
        if re.search(r"advancedsearch2\.virginmedia\.com", url):
            pass
        else:
            # Save the final URL
            new_url = url.strip('/')
            with open(self.post_urls, 'a+') as f:
                with open(self.https_urls, 'a+') as f2:
                    # Don't store HTTPS URLs as we won't able to map redirections
                    if not re.search(r"^https\:\/\/", new_url, re.I):
                        f.write(new_url + '\n')
                    else:
                        f2.write(new_url + '\n')

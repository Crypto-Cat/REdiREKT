import re


# Remove duplicates from a list
def remove_duplicates(data_list):
    seen = {}
    return [seen.setdefault(x, x) for x in data_list if x not in seen]


def clean_urls(urls):
    clean_urls = []
    for url in urls:
        stripped_url = (re.search(r"((https?://)?(www\.)?([a-z0-9\-\.\:]+))", url, flags=re.I))
        clean_urls.append(stripped_url.group(1))
    return clean_urls


# Open list of URLs from file
with open('post_urls.txt') as f:
    # Process the URLs, ensuring they are in the correct format
    urls = [url.strip() and url.strip("/") and url.rstrip() for url in f.readlines()]
    urls = clean_urls(urls)
    urls = remove_duplicates(urls)

    # Print to new file
    with open('clean_urls.txt', 'w') as f2:
        for url in urls:
            f2.write(url + '\n')
import logging
import re
import math
from collections import Counter
import tldextract  # https://github.com/john-kurkowski/tldextract
from anytree import Node
from map_redirections import clean_url
import csv


def calc_entropy(string):
    p, lns = Counter(string), float(len(string))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())


def build_http_entry(entry, whitelisted_sites, classification, logger):
    # Print out the log values if needed (not yet sorted or parsed)
    for item in entry.items():
        logger.debug("{0}".format(item))
    logger.debug("")

    # Added to prevent NoneType error
    if not entry['uri']:
        entry['uri'] = ''

    # Build up the HTTP features object
    http_features_entry = {
        'uid': entry['uid'],  # Do I need this for anything?
        'ts': entry['ts'],
        'domain': clean_url(entry['host']),  # Actual string probably not needed for ML, can discard later
        'domain_len': len(entry['host']),
        'domain_entropy': calc_entropy(entry['host']),  # This is normally a 3.x value, is this OK? What about scaling
        'tld': (tldextract.extract(entry['host'])).suffix,  # Need one-hot encode?
        'uri': entry['uri'],  # Actual string probably not needed for ML, can discard later
        'uri_len': len(entry['uri']),
        'uri_entropy': calc_entropy(entry['uri']),
        'uri_ch_slash': str(entry['uri']).count('/'),
        'uri_ch_amp': str(entry['uri']).count('&'),
        'uri_ch_dash': str(entry['uri']).count('-'),
        'uri_ch_plus': str(entry['uri']).count('+'),
        # Need one-hot encode? Or maybe just have a GET/POST feature seperately (but then what about PUT etc)? Is it even a useful feature?
        'req_type': entry['method'],
        'resp_code': entry['status_code'],  # Need one-hot encode?
        'mime_type': entry['resp_mime_types'],
        'content_type': 'unknown',  # Not always present
        'response_len': entry['response_body_len'],
        'content_redirs': []  # Hold info about content-based redirs for later
    }

    # Remove the quotes and square brackets from mime_type
    if http_features_entry['mime_type']:
        http_features_entry['mime_type'] = http_features_entry['mime_type'][0]

    # Add referrer header if it wasn't a whitelisted site
    if 'referrer' in entry:
        if entry['referrer']:
            http_features_entry['referrer'] = clean_url(entry['referrer'])

    # Get useful server header values
    if entry['server_header_names']:
        if "LOCATION" in entry['server_header_names']:
            location_index = (entry['server_header_names']).index("LOCATION")
            # Add location header if it wasn't a whitelisted site
            if classification == 0 or not re.search(whitelisted_sites, entry['server_header_values'][location_index]):
                if entry['server_header_values'][location_index] != "(empty)":
                    if re.search(r"(((https?:\/\/)|www\.)|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))", entry['server_header_values'][location_index]):
                        http_features_entry['location'] = clean_url(entry['server_header_values'][location_index])
        if "CONTENT-TYPE" in entry['server_header_names']:  # Compare this with mime_type? :)
            location_index = (entry['server_header_names']).index("CONTENT-TYPE")
            http_features_entry['content_type'] = (entry['server_header_values'][location_index]).split(";", 1)[0]

    return http_features_entry


def build_redir_entry(entry, http_features, whitelisted_sites, classification):
    # If the redirection isn't to a benign site
    if classification == 0 or (not re.search(whitelisted_sites, entry['redir_url']) and not re.search(whitelisted_sites, entry['url'])):
        # Build up a redirection object, similar to HTTP entries
        redir_features_entry = {
            'ts': entry['ts'],
            'url': entry['url'],
            'redir_url': entry['redir_url'],
            'redir_type': entry['redir_type'],
        }

        # Find the HTTP entry with matching UID to the redirect
        for _, v in http_features.items():
            for d in v:
                # If the UID + Domain match the current entry (and the redir occured on/after the time the URL was visited)
                # Note redir_features entry 'ts' is that of the website which held the JS/HTML/iFrame (d['ts'] is the redirected url)
                if d['domain'] == redir_features_entry['redir_url'] and redir_features_entry['ts'] <= d['ts']:
                    # Update redir features entry with correct timestamp and uid
                    new_redir_features_entry = redir_features_entry
                    new_redir_features_entry['ts'] = d['ts']
                    # If we don't already have a redir_type (note there could be multiple)
                    if not new_redir_features_entry in d['content_redirs']:
                        # Update the HTTP entry with the correct redirect type
                        temp_entry = d['content_redirs']
                        temp_entry.append(new_redir_features_entry)
                        d.update({'content_redirs': temp_entry})
                        return http_features

    # If it was too a benign site, don't store it
    return http_features

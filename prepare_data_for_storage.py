from anytree import Node, PreOrderIter
import ipaddress


def process_content_type(current_feature_entry, features_to_store):
    # Content types to map
    content_types = {
        'bytes_shockwave_total': ['application/x-shockwave-flash', 'application/shockwave-flash'],
        'bytes_x-dosexec_total': ['application/x-dosexec', 'application/x-msdos-program', 'application/x-msdownload', 'application/octet-stream'],
        'bytes_java_total': ['application/java-archive', 'application/x-java-archive', 'application/java', 'application/x-java-jnlp-file'],
        'bytes_silverlight_total': ['application/x-silverlight-app'],
        'bytes_javascript_total': ['application/javascript', 'application/x-javascript', 'text/javascript'],
        'bytes_xml_total': ['application/xml', 'text/xml'],
        'bytes_zip_total': ['application/zip', 'application/x-gzip'],
        'bytes_image_total': ['image/png', 'image/jpeg', 'image/gif', 'image/bmp', 'image/x-ms-bmp', 'image/x-icon', 'image/webp'],
        'bytes_html_total': ['text/html']
    }

    # Counter of number of bytes seen
    content_type_bytes = {}
    for k in content_types:
        content_type_bytes[k] = 0

    # Loop through each HTTP entry for this domain
    for index, response_len in enumerate(features_to_store['response_len']):
        content_type_and_mime = []

        # If content_type header was present, add to list
        if features_to_store['content_type'][index] != 'unknown':
            content_type_and_mime.append(features_to_store['content_type'][index])

        # Add mime_type to list
        content_type_and_mime.append(features_to_store['mime_type'][index])

        # Flag to determine if we've found content type
        content_type_found = False

        # Loop through content type keys
        for k in content_types:
            # Loop through values for content type key
            for v in content_types[k]:
                # Loop through content_type and mime values
                for item in content_type_and_mime:
                    # If they match, increment counter and break out of all loops
                    if item == v:
                        content_type_bytes[k] += response_len
                        content_type_found = True
                        break
                if content_type_found:
                    break
            if content_type_found:
                break

    # Update current features entry
    for k in content_type_bytes:
        current_feature_entry[k] = content_type_bytes[k]

    return current_feature_entry


def process_redir_data(node, current_feature_entry):
    # Redirection types
    redir_types = {
        'Referrer': 'redir_referrer',
        'Location': 'redir_location',
        'HTML': 'redir_html',
        'JavaScript': 'redir_js',
        'iFrame': 'redir_iframe',
        'Subdomain': 'redir_subdomain',
        'Concat': 'redir_concat',
        'Base64': 'redir_base64',
        'Unknown': 'redir_unknown',
    }

    # Process each redirection type
    for key, value in redir_types.items():
        if not node.is_root:
            if key in node.redirs:
                current_feature_entry[value] = 1
            else:
                current_feature_entry[value] = 0
        else:
            current_feature_entry[value] = 0

    # Store redirection timing
    current_feature_entry['redir_time'] = 0
    if not node.is_root:
        if node.seconds:
            current_feature_entry['redir_time'] = node.seconds
    return current_feature_entry


def build_url_features(node, features_to_store):
    # Put our data into a single entry (per URL in chain)
    current_feature_entry = {}

    # Average features
    features_to_average = [
        'domain_len',
        'domain_entropy',
        'uri_len',
        'uri_entropy',
        'uri_ch_slash',
        'uri_ch_amp',
        'uri_ch_dash',
        'uri_ch_plus',
        'response_len']

    for feature in features_to_average:
        try:
            current_feature_entry[feature + '_avg'] = sum(features_to_store[feature]) / len(features_to_store[feature])
        except ZeroDivisionError:
            current_feature_entry[feature + '_avg'] = 0

    # Sum features
    features_to_sum = ['response_len', 'uri_ch_slash', 'uri_ch_amp', 'uri_ch_dash', 'uri_ch_plus']

    for feature in features_to_sum:
        current_feature_entry[feature + '_total'] = sum(features_to_store[feature])

    # Count how many bytes are delivered + map content type e.g. exe, pdf, shockwave, java, javascript
    current_feature_entry = process_content_type(current_feature_entry, features_to_store)

    # Average content-type features
    features_to_average = [
        'bytes_shockwave_total', 'bytes_x-dosexec_total', 'bytes_java_total', 'bytes_silverlight_total', 'bytes_javascript_total', 'bytes_xml_total', 'bytes_zip_total',
        'bytes_image_total', 'bytes_html_total'
    ]

    for feature in features_to_average:
        try:
            current_feature_entry[feature[:-5] + 'avg'] = (current_feature_entry[feature] / current_feature_entry['response_len_total'])
        except ZeroDivisionError:
            current_feature_entry[feature[:-5] + 'avg'] = 0

    # Process redirection data
    current_feature_entry = process_redir_data(node, current_feature_entry)

    # How to process TLD? Could be many possibilities - maybe One-Hot-Encode later
    if features_to_store['tld'] and features_to_store['tld'][0] != "":
        current_feature_entry['tld'] = features_to_store['tld'][0]
    else:
        current_feature_entry['tld'] = 'n/a'

    # Was the domain an IP?
    try:
        ipaddress.ip_address(node.name)
        current_feature_entry['domain_is_ip'] = 1
    except ValueError as e:
        current_feature_entry['domain_is_ip'] = 0

    return current_feature_entry


def build_chain_features(redir_chain, http_feature_list):
    redir_chain_url_features = []
    # For each URL in the redirection chain
    redir_no = 0
    for node in PreOrderIter(redir_chain.root):
        # If we aren't missing the compromised host
        if node.name != '[missing]':
            request_no = 0  # Track number of requests to each domain

            # Deal with non-standard ports
            domain = node.name
            port = "80"
            if ':' in domain:
                domain, port = domain.split(":")

            # We want to sum/average/count these fields
            features_to_store = {
                'domain_len': [],
                'domain_entropy': [],
                'tld': [],  # How to process
                'uri': [],  # How to process
                'uri_len': [],
                'uri_entropy': [],
                'uri_ch_slash': [],
                'uri_ch_amp': [],
                'uri_ch_dash': [],
                'uri_ch_plus': [],
                'mime_type': [],  # How to process
                'content_type': [],  # How to process
                'response_len': [],  # How to process
                # 'req_type': [],  # How to process
                # 'resp_code': [] # How to process
            }

            # Aggregate features across HTTP entries
            for feature_list in http_feature_list:
                for entry in feature_list:
                    # Ensure the domain matches the URL we're processing
                    if entry['domain'] == domain:
                        # Found another request to the same domain
                        request_no += 1
                        # For each of the features we want to collect
                        for key, _ in features_to_store.items():
                            # If the entry exists
                            if key in entry:
                                # Append it for further processing
                                features_to_store[key].append(entry[key])

            # Build a single entry with all the data aggregated/summed/averaged etc
            current_feature_entry = build_url_features(node, features_to_store)

            # Sequence / redir number
            current_feature_entry['redir_no'] = redir_no
            redir_no += 1

            # Node depth
            current_feature_entry['node_depth'] = node.depth

            # Number of requests to this domain
            current_feature_entry['requests_no'] = request_no

            # See if port was standard
            if port == "80":
                current_feature_entry['port_80'] = 1
            else:
                current_feature_entry['port_80'] = 0

            # Add the entry to our list (one entry for each URL in chain)
            redir_chain_url_features.append(current_feature_entry)

    return redir_chain_url_features

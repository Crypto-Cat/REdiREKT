import re
from anytree import Node, RenderTree, search
import tldextract


def extract_redir_chain(http_entries):
    final_redir_list = []
    new_http_entries = []
    # If there is more than x (15) mins between HTTP requests, we should seperate into sessions
    # This means if the user visits the same URL that he visited 15 minutes ago, it will be in a seperate chain
    # Note that the x parameter should be determined by experience / trial and error
    sessions = extract_sessions(http_entries)

    # For each 15 minute sessions
    for _, session in enumerate(sessions):
        # Keep track of URLs and map redirections that occur
        url_list = []
        redir_chain_list = []
        # Get each URL in the PCAP
        for entry in session:
            # Make sure this URL isn't already present
            if not any(entry['domain'] in url for url in url_list):
                url_list.append({entry['domain']: entry['ts']})

        # Process each URL
        for initial_url in url_list:
            for url, ts in initial_url.items():
                # If this URL has been redirected to in a previous chain, skip it
                if not is_url_processed(url, redir_chain_list):
                    # Otherwise, build a redirection map for this URL
                    redir_chain_list, session = process_entry_url(session, redir_chain_list, url_list, url, ts)

        # Make a list of all chains with only one URL (prepare for subdomain redirection checking)
        single_url_chains = []
        for node in redir_chain_list:
            if node.height <= 1:
                single_url_chains.append(node)
                redir_chain_list.remove(node)

        # Lastly, process subdomain redirects...
        # Any URLs in a single chain that weren't seen in other chains but a URL with the same domain was seen in another chain
        # We add the subdomain before/after the other subdomain (depending on which was accessed first)
        new_redir_list = []
        for chain in redir_chain_list:
            new_node, single_url_chains = subdomain_redirects(chain.root, single_url_chains, session)
            new_redir_list.append(new_node)

        # Add single URL chains to our new chain list (without duplicating URLs that were in single chain but have been marked as subdomain redirections)
        new_redir_list += single_url_chains

        # Make sure each node is root or we'll have problems when printing
        for node in new_redir_list:
            node.parent = None
            node = calculate_timings(node, session)

        # Add this sessions redirection chains to the total list
        final_redir_list += new_redir_list
        new_http_entries += session

    return final_redir_list, new_http_entries


def extract_sessions(http_entries):
    sessions = []
    start_pos = 0

    for current_pos in range(len(http_entries) - 1):
        # Get the difference between time of previous request and current request
        difference = (http_entries[current_pos + 1]['ts'] - http_entries[current_pos]['ts']).total_seconds()
        # Is there more than 15 minutes between the requests?
        if difference >= (15 * 60):
            # Extract subset
            subset = http_entries[start_pos:current_pos]
            # Add it to the list
            sessions.append(subset)
            # Update the start position
            start_pos = current_pos

    # If we extracted subsets, we need to grab the final one
    if start_pos != 0:
        subset = http_entries[start_pos:]
        sessions.append(subset)
    # Otherwise, there was only one session
    else:
        sessions.append(http_entries)

    return sessions


def calculate_timings(tree, session):
    # Convert timestamps into seconds
    for _, _, node in RenderTree(tree):
        if not node.is_root:
            ts = None
            for entry in session:
                if entry['domain'] == node.parent.name:
                    ts = entry['ts']
                elif entry['domain'] == node.name:
                    break
            if ts:
                seconds = round((node.temp_ts - ts).total_seconds(), 3)
            else:
                seconds = round((node.temp_ts - node.parent.temp_ts).total_seconds(), 3)

            if seconds > 0:
                node.seconds = seconds
            else:
                node.seconds = 0

    # Delete the old timestamps
    del tree.temp_ts
    for node in tree.descendants:
        del node.temp_ts

    return tree


def is_url_processed(url, redir_chain):
    # Check if URL already exists in list of redirection chains
    for node in redir_chain:
        result = search.findall(node, filter_=lambda node: node.name in (url))
        if len(result) > 0:
            return True
    return False


def process_entry_url(http_entries, redir_chain_list, url_list, initial_url, ts):
    # Define our initial node
    root_node = Node(initial_url, redirs="", temp_ts=ts)

    # Get our initial list of http redirections
    root_node, _, http_entries = level_extract(http_entries, root_node, root_node, 0)

    # Fill in "Unknown" for any redirects that we couldn't identify a source for
    for descendant in root_node.root.descendants:
        # But has no known redirects
        if len(descendant.redirs) == 0:
            descendant.redirs.append("Unknown")

    # We don't want to model root node redirs
    del root_node.root.redirs

    # Add this redirection list to a larger list
    redir_chain_list.append(root_node)

    return redir_chain_list, http_entries


def subdomain_redirects(root_node, single_url_chains, http_entries):
    found = False

    # If there are redirections in the chain
    if root_node.height > 0:
        # If there are any URLs that were visited
        for leaf in root_node.leaves:
            for node in single_url_chains:
                # Extract domains
                parsed_url = tldextract.extract(node.name)
                parsed_leaf = tldextract.extract(leaf.name)
                # Make sure domain matches and subdomain doesn't
                if parsed_url.domain == parsed_leaf.domain and parsed_url.subdomain != parsed_leaf.subdomain:
                    for entry in http_entries:
                        # If we haven't already found the redirection
                        if not found:
                            # If the HTTP entry domain matches the single URL chain and it was visited before the leaf but after the leaf's parent
                            if entry['domain'] == node.name and entry['ts'] < leaf.temp_ts and entry['ts'] > leaf.parent.temp_ts:
                                # Add it before the leaf
                                Node(node.name, redirs=["Subdomain"], temp_ts=entry['ts'], parent=leaf.parent, children=[leaf])
                                found = True
                                single_url_chains.remove(node)
                            # If the HTTP entry domain matches the single URL chain and it was visited after the leaf
                            elif entry['domain'] == node.name and entry['ts'] > leaf.temp_ts:
                                # Add it to the leaf
                                Node(node.name, redirs=["Subdomain"], temp_ts=entry['ts'], parent=leaf)
                                found = True
                                single_url_chains.remove(node)

    return root_node, single_url_chains


def level_extract(http_entries, root_node, current_node, pos):
    # Loop through entries, looking for the first redirection
    for index, entry in enumerate(http_entries, start=pos):
        # Make sure referrer header isn't blank
        if 'referrer' in entry:
            if entry['referrer']:
                # Make sure referrer header matches current node in redirection chain
                if re.search(current_node.name, entry['referrer']):
                    # Make sure the redirection is to a new domain
                    if not re.search(entry['domain'], entry['referrer']):
                        # Store the redirection type, this is a useful feature
                        entry['redir_type'] = 'Referrer'
                        # Add this new domain to the redir_tree
                        root_node = add_node(http_entries, root_node, current_node, entry['redir_type'], entry['domain'], entry['ts'], index)
        # If there was no change in referrer header, check location
        if 'location' in entry:
            # If location is blank, there's no third party redirection
            if entry['location']:
                # If the currently processed node is equal to the domain in the HTTP entry
                if re.search(current_node.name, entry['domain']):
                    # Was there was a redirection via location header?
                    if not current_node.name == entry['location']:
                        # Make sure the potential redirected URL was actually visited
                        if any(d['domain'] == entry['location'].split(':')[0] for d in http_entries):
                            # Store the redirection type, this is a useful feature
                            entry['redir_type'] = 'Location'
                            # Need to find the correct timestamp
                            ts = ""
                            for temp_entry in http_entries:
                                if ts == "":
                                    if temp_entry['ts'] >= entry['ts']:
                                        if re.search(temp_entry['domain'], entry['location']):
                                            ts = temp_entry['ts']
                            # If we failed to find the correct timestamp
                            if ts == "":
                                ts = entry['ts']
                            # Add this new domain to the redir_tree
                            root_node = add_node(http_entries, root_node, current_node, entry['redir_type'], entry['location'], ts, index)
        # Process content-based redirections
        for redir_entry in entry['content_redirs']:
            # Make sure the redirect URL is populated
            if redir_entry['redir_url']:
                # Make sure the redir_entry has the same URL as the current node
                if redir_entry['url'] == current_node.name:
                    # URLs containing 5 or less characters can be discarded as error
                    if len(redir_entry['redir_url']) > 5:
                        # Make sure the potential redirect was visited after the current node
                        if redir_entry['ts'] >= current_node.temp_ts:
                            # Make sure the potential redirected URL was actually visited
                            if any(d['domain'] == redir_entry['redir_url'] for d in http_entries):
                                # Make sure the redirection is to a new domain
                                if not re.search(redir_entry['redir_url'], redir_entry['url']):
                                    # Add the redirect to the tree
                                    root_node = add_node(http_entries, root_node, current_node, redir_entry['redir_type'], redir_entry['redir_url'], redir_entry['ts'], index)

    return root_node, current_node, http_entries


def update_node_redir_types(redir_type, existing_redir_types, existing_url):
    # Update the redirect types for this URL if more than one was found
    if redir_type != "Unknown":
        if not redir_type in existing_redir_types:
            existing_redir_types.append(redir_type)
    return existing_redir_types


def add_node(http_entries, root_node, current_node, redir_type, new_node_url, ts, index):

    # Create an empty node (we'll populate it if the node hasn't already been added to tree)
    new_node = None

    # Loop through siblings of the current node
    for sibling in current_node.siblings:
        # If the sibling URL matches the URL we are trying to add
        if sibling.name == new_node_url:
            sibling.parent = current_node
            current_node.redirs = update_node_redir_types(redir_type, current_node.redirs, current_node.name)
            return root_node

    # If the new URL is equal to the root URL
    if root_node.root.name == new_node_url:
        current_node = root_node.root
        return root_node

    # Ensure this node hasn't already been added
    for item in root_node.root.descendants:
        # If this item name is the same as the new redir URL + the items parent name is the same as current node URL
        if item.name == new_node_url and item.parent.name == current_node.name:
            current_node = item
            # Update the redirect types for this URL
            item.redirs = update_node_redir_types(redir_type, item.redirs, item.name)
            return root_node

    # If a node of the same URL has been added (but not the same parent), don't update redirections
    for item in root_node.root.descendants:
        if item.name == new_node_url:
            current_node = item
            return root_node

    # I guess node hasn't been added.. Let's add it!

    # Don't add "Unknown", we'll do that later if we fail to find any other redirection types
    if redir_type != "Unknown":
        new_node = Node(new_node_url.lower(), redirs=[redir_type], temp_ts=ts, parent=current_node)
    else:
        new_node = Node(new_node_url.lower(), redirs=[], temp_ts=ts, parent=current_node)

    # Set the current node to equal the new node
    current_node = new_node

    # Recursively execute this function
    root_node, current_node, http_entries = level_extract(http_entries, root_node, current_node, index)

    return root_node


def clean_url(url):
    if url != "":
        stripped_url = (re.search(r"(https?://)?(www\.)?([a-z0-9\-\.\:]+)", url, flags=re.I))
        cleaned_url = ""
        try:
            cleaned_url = stripped_url.group(3).lower()
            if cleaned_url.endswith(':80'):
                cleaned_url = cleaned_url.rstrip(':80')
        except:
            print('Failed to clean: ' + url)
        return cleaned_url

import csv
import re

from anytree import Node, search
from anytree.importer import DictImporter
from anytree.exporter import DictExporter
from collections import OrderedDict
from store_data import add_to_test_cases
from build_data import build_http_entry, build_redir_entry
from print_output import print_tree
from map_redirections import extract_redir_chain, clean_url

dict_exporter = DictExporter(dictcls=OrderedDict, attriter=sorted)
dict_importer = DictImporter()


def extract_http_features(http_log, redir_log, statistics, whitelisted_sites, classification, logger):
    sorted_http_list = {}
    http_features = {}
    redir_chain_map_list = []

    # Store all HTTP feature values we need for later
    for entry in http_log:
        # If there is a hostname
        if entry._asdict()['host']:
            # If the URL isn't whitelisted
            if classification == 0 or not re.search(whitelisted_sites, entry._asdict()['host']):
                # Build up a HTTP entry in the format we want
                http_features_entry = build_http_entry(entry._asdict(), whitelisted_sites, classification, logger)
                # Track the source IP
                src_ip = str(entry._asdict()['id_orig_h'])
                # If the IP hasn't been seen before, add it to dictionary
                if not src_ip in http_features:
                    http_features[src_ip] = []
                    sorted_http_list[src_ip] = []
                # Add the HTTP log entry above to list
                http_features[src_ip].append(http_features_entry)

    # If the content-based redirection log isn't empty
    if redir_log:
        # Store the feature values for the content-based redirections
        for entry in redir_log:
            # If there was redirection URL
            if entry._asdict()['redir_url']:
                # Build up a redir entry in the format we want
                http_features = build_redir_entry(entry._asdict(), http_features, whitelisted_sites, classification)

    # Extract redirection chains for each source IP
    for ip, feature_list in http_features.items():
        # Get a map of redirection chains
        redir_chain_map, feature_list = extract_redir_chain(feature_list)

        # Print out redirection chains
        logger.info("Source IP: {0}\n".format(ip))
        logger.info("Redirection Chains:\n")
        # Here, we could do our conversion to URL
        for item in redir_chain_map:
            print_tree(item, logger)
        logger.info("")

        # Add the sorted HTTP features and redirection maps to lists
        redir_chain_map_list.append(redir_chain_map)
        sorted_http_list[ip].append(feature_list)

    return sorted_http_list, redir_chain_map_list


def extract_malicious_chain(pcap_name, redir_chain_map_list, whitelisted_sites, logger):
    # Load the CSV file with labelled comprimised site and EK page
    csv_file = csv.reader(open('mal_data/verify.csv', "r"), delimiter=",")
    compromised_site = None
    ek_page = None

    # Find the row in CSV file with current PCAP name
    for row in csv_file:
        if row[0] == pcap_name:
            if len(row) > 2:
                compromised_site = clean_url(row[1])
                ek_page = clean_url(row[2])
            else:
                print("Error: Provide C + EK values to extract malicious chain\n")
                # Print out possible suggestions (just helps speed up initial sample data input)
                for chain_map in redir_chain_map_list:
                    for chain in chain_map:
                        if chain.root.height >= 1:
                            print("Potentially: " + chain.root.name + "," + chain.leaves[0].name + "\n")
            break

    # If it wasn't found, return
    if not compromised_site or not ek_page:
        print("Failed to find data for " + pcap_name + " in verify.csv")
        return
    else:
        # Search for the matching redirection chain
        for redir_chain_map in redir_chain_map_list:
            for redir_chain in redir_chain_map:
                found = False
                # Assign the first node as root
                root = redir_chain.root
                # While the root node isn't the compromised site, increment
                if not root.name == compromised_site:
                    for item in root.descendants:
                        if item.name == compromised_site:
                            root = item
                            found = True
                else:
                    found = True
                # If there are multiple sites browsed to before the compromised site in the page, we must remove parents
                root.parent = None
                # If we were able to find the root name
                if found:
                    # Find all the paths to the EK page from the compromised site
                    result = search.findall_by_attr(root, ek_page, name='name', maxlevel=None, mincount=None, maxcount=None)
                    # If we find potential malicious chains
                    if result:
                        # We need to choose one, probably the longest chain..
                        malicious_redir = result[0]
                        for item in result:
                            if item.depth > malicious_redir.depth:
                                malicious_redir = item

                        # Strip off any siblings of compromised host if it was present
                        if not re.search(r"missingC", pcap_name):
                            stripped_malicious_redir = extract_chain(malicious_redir, ek_page)
                        else:
                            stripped_malicious_redir = malicious_redir

                        # Remove any whitelisted domains
                        for node in stripped_malicious_redir.root.descendants:
                            if re.search(whitelisted_sites, node.name):
                                if node.children.count > 0:
                                    for child in node.children:
                                        child.parent = node.parent
                                else:
                                    node.parent = None

                        # Render the malicious chain
                        logger.info("Extracted Malicious Redirection Chain:\n")
                        print_tree(stripped_malicious_redir.root, logger)
                        # Once we've extracted a malicious chain, we can stop processing
                        return stripped_malicious_redir
    # If we failed to extract any chains, print an error
    logger.info("Unable to extract Malicious Redirection Chain (" + compromised_site + " -> " + ek_page + "):")
    return None


def extract_all_benign_chains(pcap_name, redir_chain_map_list, statistics, store_json, max_nodes_per_chain, logger):
    found = False
    total_chains = 0
    extracted_chains = []

    # Loop through each of the trees
    for redir_chain_map in redir_chain_map_list:
        total_chains += len(redir_chain_map)
        for redir_chain in redir_chain_map:
            root = redir_chain.root
            # Chains that have at least one redirection
            if root.height >= 1:
                found = True
                # Get each of the leaf nodes
                leaves = root.leaves
                # Loop through each leaf, extracting the path from root
                for leaf in leaves:
                    # Extract a chain for each of leaf nodes
                    benign_redirs = search.findall_by_attr(root, leaf.name, name='name', maxlevel=None, mincount=None, maxcount=None)
                    # For each of the benign chains
                    for redir in benign_redirs:
                        stripped_benign_redir = extract_chain(redir, leaf.name)
                        # If we managed to extract, append it
                        if stripped_benign_redir:
                            # If there are more URLs in the chain than allowed according to threshold
                            if len(stripped_benign_redir.root.descendants) > max_nodes_per_chain:
                                logger.debug("Too many URLs (" + str(len(stripped_benign_redir.root.descendants)) + ") in this chain, max threshold is " +
                                             str(max_nodes_per_chain))
                            else:
                                extracted_chains.append(stripped_benign_redir)
            # If there are no redirections
            elif root.height == 0:
                found = True
                extracted_chains.append(redir_chain)
    # If we found some benign chains
    if found:
        # Remove identical chains
        extracted_chains = remove_duplicates(extracted_chains)
        # Render the benign chain
        logger.info("Extracted Benign Redirection Chains:\n")
        for chain in extracted_chains:
            # Count the number of different types of redirections that occurred
            statistics = count_redirs(chain.root, 0, statistics)
            # Print tree
            print_tree(chain.root, logger)
            logger.info("")
        if store_json:
            # Add extracted chains to test_cases.json
            test_cases = {pcap_name: {}}
            for i, chain in enumerate(extracted_chains):
                test_cases[pcap_name][i] = dict_exporter.export(chain.root)
            add_to_test_cases(pcap_name, 'test_cases.json', test_cases, 'ben_data/')
        # Return the extracted chains
        return extracted_chains
    # Else, no chains at all
    else:
        return None


def extract_chain(redir, target):
    stripped_redir = None
    # We dont want all to model redirections of initially visited URL (compromised site)
    # But, we do want to capture all siblings AFTER the first redirection..
    for child in redir.root.children:
        child_copy = dict_importer.import_(dict_exporter.export(child))
        child_copy.parent = None
        # Find a route from child to leaf
        child_to_leaf = search.findall_by_attr(child_copy, target, name='name', maxlevel=None, mincount=None, maxcount=None)

        # If multiple chains between root + leaf exist, extract the longest chain (similar to malicious)
        for chain in child_to_leaf:
            if not stripped_redir:
                stripped_redir = chain
            elif stripped_redir.depth < chain.depth:
                stripped_redir = chain
    stripped_redir.root.parent = Node(redir.root.name)

    return stripped_redir


def clean_tree(tree):
    # Delete redirs and seconds
    for node in tree.descendants:
        try:
            del node.redirs
            del node.seconds
        except:
            pass
    return tree


def count_redirs(node, c_missing, statistics):
    # Loop through each of the parents, recording the redir_types
    for descendant in node.descendants:
        # If there are any redirections
        for redir in descendant.redirs:
            # Record them
            statistics['confirmed_redir_types'][redir] += 1

        if isinstance(descendant.seconds, (int, float, complex)):
            # Record timing
            statistics['total_redir_timing'] += descendant.seconds
            if descendant.seconds > statistics['max_redir_timing']:
                statistics['max_redir_timing'] = descendant.seconds
            if not statistics['min_redir_timing']:
                statistics['min_redir_timing'] = descendant.seconds
            elif descendant.seconds < statistics['min_redir_timing']:
                statistics['min_redir_timing'] = descendant.seconds

    # Update total redirects
    statistics['total_redirects'] += node.height + c_missing
    # Update max redirects
    if (node.height + c_missing) > statistics['max_redirects']:
        statistics['max_redirects'] = node.height + c_missing
    if ((len(node.descendants) + 1) + c_missing) > statistics['max_nodes']:
        statistics['max_nodes'] = (len(node.descendants) + 1) + c_missing
    if not statistics['min_redirects']:
        statistics['min_redirects'] = node.height + c_missing
    elif (node.height + c_missing) < statistics['min_redirects']:
        statistics['min_redirects'] = node.height + c_missing
    # Update total malicious URLs
    statistics['total_urls'] += (len(node.descendants) + 1) + c_missing
    # Update total chains
    statistics['total_chains'] += 1

    return statistics


# Remove duplicates from a list
def remove_duplicates(chain_list):
    str_trees = []
    new_chain_list = []

    # Currently we are doing this by converting descendants to strings
    # There is likely a better way - this may cause issues in future,
    # particularly due to timing/redirections being different or out of order
    for chain in chain_list:
        if not str(chain.root.descendants) in str_trees:
            new_chain_list.append(chain)
            str_trees.append(str(chain.root.descendants))

    return new_chain_list
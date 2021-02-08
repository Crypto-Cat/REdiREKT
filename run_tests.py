import csv
import json
import re
from anytree.exporter import JsonExporter
from anytree.importer import JsonImporter
from anytree.importer import DictImporter
from anytree.exporter import DictExporter
from collections import OrderedDict
from parse_data import count_redirs, clean_tree
from print_output import print_tree
from store_data import write_test_results, add_to_test_cases

# Used for exporting to JSON
exporter = JsonExporter(indent=2, sort_keys=False)
importer = JsonImporter(sort_keys=False)
dict_exporter = DictExporter(dictcls=OrderedDict, attriter=sorted)
dict_importer = DictImporter()


def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj


def verify_malicious_chain(pcap_name, malicious_chain, statistics, data_dir, logger):
    found = False
    testing_root = malicious_chain

    if malicious_chain:
        # Create new dictionary from malicious chain
        new = dict_exporter.export(malicious_chain.root)
        # Add the PCAP name
        malicious_chain = {pcap_name: new}

    # Load the JSON file with labelled with full malicious redirection chain
    with open(data_dir + 'test_cases.json', 'r') as test_cases:
        try:
            existing_tests = json.load(test_cases)
            # Loop through each test case
            for existing_test in existing_tests:
                # Extract the sample name and sample dict from test case
                for sample_name, _ in existing_test.items():
                    # If the sample name matches the current PCAP
                    if sample_name == pcap_name:
                        found = True
                        # If we missed the compromised host
                        c_missing = 0
                        if re.search(r"missingC", pcap_name):
                            c_missing = 1
                            statistics['missing_compromised'] += 1
                            statistics['confirmed_redir_types']['Unknown'] += 1

                        # If is malvertising
                        if re.search(r"malvert|hookads|admedia|ngay|seamless|fobos", pcap_name, re.I):
                            statistics['malvertising'] += 1

                        # Select this as correct chain
                        correct_malicious_chain = existing_test
                        # Convert chains dict to tree
                        correct_root = dict_importer.import_(correct_malicious_chain[pcap_name])
                        if malicious_chain:
                            testing_root = dict_importer.import_(malicious_chain[pcap_name])

                        # Count the number of different types of redirections that occurred
                        statistics = count_redirs(correct_root.root, c_missing, statistics)

                        # If we were able to extract a malicious chain
                        if malicious_chain:
                            # Need to do this messing around to compare trees without comparing redirections (which are randomly ordered)
                            c_tree = ordered(dict_exporter.export(clean_tree(dict_importer.import_(correct_malicious_chain[pcap_name]))))
                            t_tree = ordered(dict_exporter.export(clean_tree(dict_importer.import_(malicious_chain[pcap_name]))))
                            # Is the chain correct?
                            if c_tree == t_tree:
                                message = "\nMalicious chain extraction result was CORRECT!\n"
                                return process_chain_extraction_result(pcap_name, message, "1", 'correct', correct_root, statistics, data_dir, logger)
                            else:
                                # If malicious chain was semi-correct
                                message = "\nMalicious chain extraction result was SEMI-CORRECT!\n\nCorrect Malicious Chain:\n"
                                # How many URLs did we miss?
                                missed = (len(correct_root.descendants) + 1) - (len(testing_root.descendants) + 1)
                                # Did we miss URLs in our test?
                                if missed > 0:
                                    statistics['missed_redirects'] += missed
                                # Or did we have too many URLs?
                                elif missed < 0:
                                    statistics['missed_redirects'] -= missed
                                return process_chain_extraction_result(pcap_name, message, "0", 'partial', correct_root, statistics, data_dir, logger)
                        else:
                            # If we failed to extract a malicious chain
                            message = "\nMalicious chain extraction result was INCORRECT!\n\nCorrect Malicious Chain:\n"
                            # How many URLs did we miss?
                            missed = (len(correct_root.descendants) + 1)
                            statistics['missed_redirects'] += missed
                            return process_chain_extraction_result(pcap_name, message, "?", 'incorrect', correct_root, statistics, data_dir, logger)

        except Exception as e:
            pass
            # print("\n" + str(e))

    if malicious_chain:
        # If the PCAP name wasn't found, add it to test cases and results
        print("\nERROR: PCAP was not found in test_cases.json - Adding it now!\n")
        # If it's not added to test cases, add to test cases + results
        add_to_test_cases(pcap_name, 'test_cases.json', malicious_chain, data_dir)
        add_to_test_results(pcap_name, 'test_results.csv', None, data_dir)
        # If we didn't count correct redirs
        if not found:
            # Count the number of different types of redirections that occurred
            statistics = count_redirs(testing_root.root, 0, statistics)
        return statistics

    # If the PCAP name was found but no test case
    print("\nERROR: Test case missing! No malicious chain to enter..\n")
    return statistics


def process_chain_extraction_result(pcap_name, message, result_char, result_index, correct_chain, statistics, data_dir, logger):
    # Log the message
    logger.info(message)
    if result_char == "0" or result_char == "?":
        print_tree(correct_chain, logger)
        logger.info("")

    # Write the test results to file
    write_test_results(pcap_name, result_char, data_dir)
    statistics['test_results'][result_index] += 1

    return statistics


def add_to_test_results(pcap_name, file_name, malicious_chain, data_dir):
    # Make sure the entry doesn't already exist
    csv_results_lines = list(csv.reader(open(data_dir + 'test_results.csv', 'r'), delimiter=','))
    for line in csv_results_lines:
        if line[0] == pcap_name:
            return
    # Add PCAP name to test_results and test_cases (saves some time)
    csv_test_name_writer = csv.writer(open(file_name, 'a', newline=''))
    if malicious_chain:
        # If we extracted a malicious chain, add it to test results to save time
        csv_test_name_writer.writerow([pcap_name, malicious_chain])
    else:
        csv_test_name_writer.writerow([pcap_name])
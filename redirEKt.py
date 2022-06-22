import logging
import sys
import re
import getopt
import csv
import time
from os import system, path, getcwd, listdir
import subprocess
from brologparse import parse_log_file  # https://github.com/elnappo/bro-log-parser
from parse_data import extract_http_features, extract_malicious_chain, extract_all_benign_chains
from prepare_data_for_storage import build_chain_features
from store_data import store_features
from run_tests import verify_malicious_chain
from print_output import print_final_output


def create_global_vars():
    # Initialise logger
    logger = logging.getLogger('rEKd')

    # Define which URLs/Redirections to ignore
    whitelisted_sites = r'(google(apis)?(\-analytics)?|\.facebook|microsoft|bing|yahoo|duckduckgo|baidu|ask|aol|wolframalpha|yandex|adultfriendfinder)\.|localhost|ya\.ru'

    statistics = {
        # Track how many Referrer/Location/HTML/JS/iFrame/Unknown redirections
        'confirmed_redir_types': {
            'Referrer': 0,
            'Location': 0,
            'HTML': 0,
            'JavaScript': 0,
            'iFrame': 0,
            'Subdomain': 0,
            'Base64': 0,
            'Concat': 0,
            'Unknown': 0,
            'Advanced': 0
        },
        # Time the program execution
        'start_time': time.time(),
        # Track how many of the extracted malicious chains are Correct/Paritial/Wrong
        'test_results': {
            'correct': 0,
            'partial': 0,
            'incorrect': 0
        },
        # More useful global stats
        'total_chains': 0,
        'total_urls': 0,
        'total_redirects': 0,
        'min_redirects': None,
        'max_redirects': 0,
        'max_nodes': 0,
        'missed_redirects': 0,
        'missing_compromised': 0,
        'malvertising': 0,
        'total_redir_timing': 0,
        'min_redir_timing': None,
        'max_redir_timing': 0,
        'failed_pcaps': 0,
        'empty_pcaps': 0,
        'no_redir_pcaps': 0,
        'column_count': 0
    }

    return statistics, whitelisted_sites, logger


# Flags
classification = 1  # Change program behaviour for malicious/benign processing
store_csv = 1  # Enable/disable generation and storage of CSV data
store_json = 0  # Enable/disable generation and storage of JSON data
# Configured based on analysis of malicious and benign HTTP redirection
# chains, currently only applies to benign chains (haven't seen malicious
# chains this big)
max_nodes_per_chain = 50


def setup_logging(write_mode, data_dir, logger):
    # Delete the log files we generated
    system('rm -rf logs/*.log')
    system('rm -rf ' + data_dir + 'PCAP/extract_files/*')
    # Basic logging
    logger.setLevel(logging.DEBUG)
    # Print logs to screen
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)  # Change this to to logging.INFO to disable GUI output
    # Save logs to file as well
    fh_debug = logging.FileHandler('logs/debug.log', mode=write_mode)
    fh_info = logging.FileHandler('logs/info.log', mode=write_mode)
    fh_debug.setLevel(logging.DEBUG)
    fh_info.setLevel(logging.INFO)
    # Add handers
    logger.addHandler(handler)
    logger.addHandler(fh_debug)
    logger.addHandler(fh_info)

    return logger


def clean_up(data_dir):
    # Delete the log files we generated
    system('cd ' + (path.join(getcwd(), data_dir + 'PCAP/')) + '; rm -rf *.log')


def generate_logs(pcap, data_dir, logger):
    # CD into data directory (can't set BRO log output dir) and generate the BRO logs
    command = 'cd ' + (
        path.join(getcwd(), data_dir + 'PCAP/')
    ) + '; /usr/local/zeek/bin/zeek -r' + pcap + ' -C ../../bro_scripts/extract-header-names-and-values.bro ../../bro_scripts/http-url-extract.bro'  # ../../bro_scripts/extract-all-files.bro

    # How long should we wait for the process to complete?
    time_out = 120

    # Try to generate logs
    try:
        subprocess.run(command, shell=True, timeout=time_out)
    except BaseException:
        logger.info(pcap.split("/")[-1] + " took longer than " + str(time_out) + " seconds!\n")
        return None, None, None, None

    if path.exists(path.join(getcwd(), data_dir + 'PCAP/') + 'http.log'):
        # Store the logs (we don't need DNS or files yet)
        http_log = parse_log_file((path.join(getcwd(), data_dir + 'PCAP/')) + 'http.log')
        dns_log = None  # parse_log_file((path.join(getcwd(), 'data/PCAP/')) + 'dns.log')
        files_log = None  # parse_log_file((path.join(getcwd(), data_dir + 'PCAP/')) + 'files.log')
        # The redirection log may not exist
        redir_log = None
        if path.exists(path.join(getcwd(), data_dir + 'PCAP/') + 'redirections.log'):
            redir_log = parse_log_file((path.join(getcwd(), data_dir + 'PCAP/')) + 'redirections.log')
    else:
        return None, None, None, None

    # Return the logs for processing
    return http_log, dns_log, files_log, redir_log


def generate_features(filename, statistics, whitelisted_sites, data_dir, logger):
    # Get the PCAP file
    pcap_name = path.join(getcwd(), filename)

    # If the PCAP exists
    if path.exists(pcap_name):
        found = False
        # Generate the logs
        http_log, dns_log, files_log, redir_log = generate_logs(pcap_name, data_dir, logger)

        # Did we successfully extract the HTTP log
        if http_log is not None:

            # Extract the HTTP features
            http_feature_list, redir_chain_map_list = extract_http_features(
                http_log, redir_log, statistics, whitelisted_sites, classification, logger)

            # Create array now as there may be multiple chains (multiple SRC IP)
            chain_features = []

            # For each source IP in the PCAP
            for ip, feature_list in http_feature_list.items():
                # If we are processing malicious dataset and we haven't already extracted the chain we want
                if classification == 1 and len(chain_features) == 0:
                    # Compare redir_chains with CSV of known compromised sites / EK sites, extracting the malicious chain
                    malicious_chain = extract_malicious_chain(path.basename(pcap_name), redir_chain_map_list, whitelisted_sites, logger)
                    # If a malicious chain was returned, run tests to confirm it is correct
                    # This is important because as changes to code are made, it could break previously working samples
                    if malicious_chain:
                        found = True
                        statistics = verify_malicious_chain(pcap_name.split("/")[-1], malicious_chain, statistics, data_dir, logger)
                        # Build a list of features for the malicious chain
                        chain_features.append(build_chain_features(malicious_chain, feature_list))
                    else:  # Did we fail to extract any chains altogether?
                        statistics = verify_malicious_chain(pcap_name.split("/")[-1], malicious_chain, statistics, data_dir, logger)
                # If we are processing the benign dataset, lets extract all chains that have at least one redirection
                elif classification == 0:
                    benign_chains = extract_all_benign_chains(path.basename(pcap_name), redir_chain_map_list,
                                                              statistics, store_json, max_nodes_per_chain, logger)
                    if benign_chains:
                        found = True
                        # Build a list of features for each benign chain and add it to array
                        for chain in benign_chains:
                            # Add chains with no redirections to stats
                            if chain.root.height == 0:
                                statistics['no_redir_pcaps'] += 1
                            chain_features.append(build_chain_features(chain, feature_list))

            # Do we want to store data to CSV?
            if store_csv:
                # If we extracted at least one chain
                if len(chain_features) > 0:
                    # Print features to CSV file
                    store_features(path.basename(pcap_name), classification, chain_features, data_dir)

            # If we didn't find any chains
            if not found:
                if classification == 0:
                    system('mv ' + pcap_name + ' ' + data_dir + 'PCAP/empty/')
                    logger.info("PCAP contained no URLs!\n")
                    statistics['empty_pcaps'] += 1

        # If we failed to extract logs
        else:
            logger.info("Failed to extract HTTP log from PCAP - HTTPS/404/Timeout?\n")
            statistics['failed_pcaps'] += 1
            if classification == 0:
                system('mv ' + pcap_name + ' ' + data_dir + 'PCAP/failed/')

        # Perform clean-up
        clean_up(data_dir)
        return statistics

    # If the PCAP didn't exist
    else:
        logger.info("PCAP not found!\n")
        statistics['failed_pcaps'] += 1
        return statistics


def process_csv_file(filename, num_of_lines, data_dir):
    statistics, whitelisted_sites, logger = create_global_vars()

    # Load the CSV file PCAP names
    csv_file = csv.reader(open(filename, "r"), delimiter=",")

    # If we only want to process a specific number of lines
    if num_of_lines:
        rows = list(csv_file)[-num_of_lines:]
    else:
        rows = list(csv_file)

    tmp_dir_name = path.join(getcwd(), data_dir + 'PCAP/')
    # Enable logging in append mode
    logger = setup_logging('a', data_dir, logger)

    # Find out how many PCAPs are listed in CSV
    row_count = sum(1 for line in rows)
    if row_count == 0:
        logger.info("Zero PCAPs to process!")
        exit(0)
    logger.info("Processing " + str(row_count) + " PCAPs..\n")

    # Find the row in CSV file with current PCAP name
    for row in rows:
        if row[0].endswith('.pcap'):
            # Process PCAP, generating features and storing to CSV file
            logger.info("Processing " + row[0] + "..\n")
            statistics = generate_features(path.join(tmp_dir_name, row[0]), statistics, whitelisted_sites, data_dir, logger)
            logger.info("=" * 100 + "\n")
    logger.info("Processing Complete..\n")

    # Print final output stats, test results etc
    print_final_output(row_count, statistics, classification, logger)


def process_directory(filename, data_dir):
    statistics, whitelisted_sites, logger = create_global_vars()

    # Get a list of all files in the directory
    dir_name = path.join(getcwd(), filename)

    # Get a list of PCAPs in the directory
    files = [f for f in listdir(dir_name) if (f.endswith('.pcap'))]
    # Enable logging in append mode
    logger = setup_logging('a', data_dir, logger)
    logger.info("Processing " + str(len(files)) + " PCAPs..\n")

    # Loop through each PCAP, generating features and storing to CSV file
    for file in files:
        logger.info("Processing " + file + "..\n")
        statistics = generate_features(path.join(dir_name, file), statistics, whitelisted_sites, data_dir, logger)
        logger.info("=" * 100 + "\n")
    logger.info("Processing Complete..\n")

    # Print final output stats, test results etc
    print_final_output(len(files), statistics, classification, logger)


def process_single_pcap(filename, data_dir):
    statistics, whitelisted_sites, logger = create_global_vars()

    # Enable logging in write mode
    logger = setup_logging('w', data_dir, logger)
    pcap_name = filename.split("/")[-1]
    logger.info("Processing " + pcap_name + "\n")

    # Process PCAP, generating features and storing to CSV file
    statistics = generate_features(filename, statistics, whitelisted_sites, data_dir, logger)
    logger.info("=" * 100 + "\n")
    logger.info("Processing Complete..\n")

    # Print final output stats, test results etc
    print_final_output(1, statistics, classification, logger)


def main(argv):
    try:
        opts, _ = getopt.getopt(argv, 'hr:t:l:d:', ['help', 'read=', 'test=', 'last=', 'demo='])
    except getopt.GetoptError:
        print('python log_parser.py -h')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('python redirEKt.py\n'
                  '-r (input local PCAP file or directory (for multiple PCAPs)))\n')
            sys.exit()
        else:
            # Set data directory according to classification
            if classification == 1:
                data_dir = "mal_data/"
            else:
                data_dir = "ben_data/"
            if opt in ('-r', '--read'):
                # If the argument ends with / we process all PCAPs in that directory
                if arg.endswith('/'):
                    # Process directory of PCAPs
                    process_directory(arg, data_dir)
                # If the argument ends with .pcap we just process the single pcap
                elif arg.endswith('.pcap'):
                    if not re.search("/", arg):
                        arg = data_dir + 'PCAP/' + arg
                    # Process single PCAP file
                    process_single_pcap(arg, data_dir)
                else:
                    # If neither of the conditions above were true, there may be an issue
                    print("Check the PCAP/directory you're providing..")
                    sys.exit()
            if opt in ('-t', '--test'):
                # Process the last PCAP in the verify.csv (speeds up testing)
                if arg == "last":
                    # Get the last line of the CSV file
                    csv_file = list(csv.reader(open(data_dir + 'verify.csv', "r"), delimiter=","))[-1]
                    process_single_pcap(data_dir + 'PCAP/' + csv_file[0], data_dir)
                # Process all PCAPs in verify.csv (speeds up testing)
                elif arg == "all":
                    process_csv_file(data_dir + 'verify.csv', None, data_dir)
                # Make sure a CSV file has been provided
                elif not arg.endswith('.csv'):
                    print("Check the CSV file you're providing..")
                    sys.exit()
                else:
                    # Process list of PCAPs stored in CSV file
                    process_csv_file(arg, None, data_dir)
            if opt in ('-l', '--last'):
                if arg.isdigit():
                    # Get the last X lines of the CSV file
                    process_csv_file(data_dir + 'verify.csv', int(arg), data_dir)
            if opt in ('-d', '--demo'):
                # If the user didn't specify how many samples to demo
                if not arg.isdigit():
                    arg = 10
                system('shuf -n ' + str(arg) + ' ' + data_dir + 'verify.csv > ' + data_dir + 'temp.csv')
                process_csv_file(data_dir + 'temp.csv', None, data_dir)
                system('rm -rf ' + data_dir + 'temp.csv')


if __name__ == "__main__":
    main(sys.argv[1:])

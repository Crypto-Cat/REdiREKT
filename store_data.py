from os import path
import csv
import json
import pandas as pd
import time


def store_feature(pcap_name, classification, http_feature_list, data_dir):
    # Columns
    cols = [
        'redir_no', 'redir_time', 'node_depth', 'requests_no', 'port_80', 'domain_is_ip', 'domain_len_avg', 'domain_entropy_avg', 'uri_len_avg', 'uri_entropy_avg',
        'uri_ch_slash_total', 'uri_ch_slash_avg', 'uri_ch_amp_total', 'uri_ch_amp_avg', 'uri_ch_dash_total', 'uri_ch_dash_avg', 'uri_ch_plus_total', 'uri_ch_plus_avg',
        'response_len_total', 'response_len_avg', 'bytes_shockwave_total', 'bytes_shockwave_avg', 'bytes_x-dosexec_total', 'bytes_x-dosexec_avg', 'bytes_java_total',
        'bytes_java_avg', 'bytes_silverlight_total', 'bytes_silverlight_avg', 'bytes_javascript_total', 'bytes_javascript_avg', 'bytes_xml_total', 'bytes_xml_avg',
        'bytes_zip_total', 'bytes_zip_avg', 'bytes_image_total', 'bytes_image_avg', 'bytes_html_total', 'bytes_html_avg', 'redir_referrer', 'redir_location', 'redir_html',
        'redir_js', 'redir_iframe', 'redir_subdomain', 'redir_concat', 'redir_base64', 'redir_unknown', 'tld'
    ]

    # Convert to dataframe
    df_url = pd.DataFrame.from_records(http_feature_list)

    # Re-order columns
    df_url = df_url[cols]

    # Store PCAP name and classification
    df_url.insert(0, 'classification', classification)
    df_url.insert(1, 'sample', pcap_name)

    # Store the rows in CSV file
    if path.isfile('CSV/features.csv'):
        # Append to CSV file
        df_url.to_csv('CSV/features.csv', mode='a', sep=',', index=False, header=False)
    else:
        # Create new CSV file
        df_url.to_csv('CSV/features.csv', sep=',', index=False)


def store_features(pcap_name, classification, http_feature_list, data_dir):
    # If we have multiple src_ip then we need to store to multiple files
    # Also if we are processing benign data and have multiple benign chains per PCAP
    if len(http_feature_list) > 1:
        count = 0
        for chain in http_feature_list:
            # Store in CSV
            store_feature(path.splitext(pcap_name)[0] + "[" + str(count) + "]", classification, chain, data_dir)
            # Increment counter
            count += 1
    else:
        # Store in CSV
        store_feature(path.splitext(pcap_name)[0], classification, http_feature_list[0], data_dir)


def write_test_results(pcap_name, result, data_dir):
    # Load CSV files for writing results
    csv_results_lines = list(csv.reader(open(data_dir + 'test_results.csv', 'r'), delimiter=','))
    csv_results_writer = csv.writer(open(data_dir + 'test_results.csv', 'w'), delimiter=',')

    # Store the results in CSV file so we can track the effects of changes
    for i, line in enumerate(csv_results_lines):
        if line[0] == pcap_name:
            line.append(result)
            csv_results_lines[i] = line
            csv_results_writer.writerows(csv_results_lines)
            return

    # If we failed to find the PCAP in test_results, print error and revert the CSV
    # Note that we could just add the PCAP name, but there would be disparity between number of column entries
    print("ERROR: PCAP was not found in test_results.csv!\n")
    csv_results_lines.append([pcap_name, result])
    csv_results_writer.writerows(csv_results_lines)


def add_to_test_cases(pcap_name, file_name, chain, data_dir):
    existing = []
    # Open the existing test cases
    with open(data_dir + file_name, "r") as test_cases:
        try:
            existing_tests = json.load(test_cases)
            # Loop through each test case
            for existing_test in existing_tests:
                # Extract the sample name and sample dict from test case
                for sample_name, _ in existing_test.items():
                    # If the sample name matches the current PCAP, it's been added already
                    if sample_name == pcap_name:
                        return
                    else:
                        # Otherwise, add it
                        existing.append(existing_test)
        except Exception as e:
            pass
            # print("\n" + str(e))

        # Open same test cases for writing
        with open(data_dir + file_name, "w") as f:
            # Append it to our list of existing test cases
            existing.append(chain)
            # Dump it baby!
            json.dump(existing, f, indent=2)
            return

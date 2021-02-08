import time
from anytree import Node, RenderTree
from tabulate import tabulate
from operator import itemgetter


def print_redir_count(num_of_pcaps, statistics, logger):
    list_of_redirs = []
    # Keep track of obfuscated redirs
    obfuscated = 0
    # Any missed redirects we class as advanced obfuscation
    statistics['confirmed_redir_types']['Advanced'] = statistics['missed_redirects']
    # Calculate totals etc
    total = sum(statistics['confirmed_redir_types'].values())

    # For each type of redirection
    for redir_type, count in statistics['confirmed_redir_types'].items():
        # Statistics calculations
        if redir_type == "Base64" or redir_type == "Concat" or redir_type == "Subdomain" or redir_type == "Unknown" or redir_type == "Advanced":
            obfuscated += count
        percentage = 0
        average = 0
        if total > 0:
            percentage = round((count / total) * 100, 2)
            average = round(count / total, 3)
        # Append the info to the list
        list_of_redirs.append([redir_type, str(count) + "/" + str(total), str(percentage) + "%", str(average)])

    # Print the results
    logger.info(tabulate(sorted(list_of_redirs, key=itemgetter(3), reverse=True), headers=['Redir_Type', 'Num', '%', 'Avg'], tablefmt='orgtbl'))

    if total > 0:
        # Print obfuscated redirection stats
        logger.info("\n" + str(obfuscated) + "/" + str(total) + " (" + str(round((obfuscated / total) * 100, 2)) + "%) of redirections were obfuscated!")

    if statistics['total_chains'] > 0:
        # Note, we are are dividing by the number of correct/semi-correct PCAPs
        logger.info("\nMin chain depth: " + str(statistics['min_redirects']))
        logger.info("Max chain depth: " + str(statistics['max_redirects']))
        logger.info("Avg chain depth: " + str(round(statistics['total_redirects'] / statistics['total_chains'], 3)))
        logger.info("\nMax nodes per chain: " + str(statistics['max_nodes']))
        logger.info("Avg nodes per chain: " + str(round(statistics['total_urls'] / statistics['total_chains'], 3)))
    # Redirection timing
    if statistics['min_redir_timing'] and statistics['max_redir_timing']:
        logger.info("\nMin time between redirects: " + str(round(statistics['min_redir_timing'], 3)) + " seconds!")
        logger.info("Max time between redirects: " + str(round(statistics['max_redir_timing'], 3)) + " seconds!")
        logger.info("Avg time between redirects: " + str(round(statistics['total_redir_timing'] / statistics['total_redirects'], 3)) + " seconds!")
    logger.info("\n" + ("=" * 100) + "\n")


def print_final_output(num_of_pcaps, statistics, classification, logger):
    # Print timing related info
    print_timing(num_of_pcaps, statistics, logger)
    # If dataset is malicious, print relevant stats
    if classification == 1:
        print_malicious_stats(num_of_pcaps, statistics, logger)
    else:
        print_benign_stats(num_of_pcaps, statistics, logger)
    # Print redirections
    print_redir_count(num_of_pcaps, statistics, logger)


def print_benign_stats(num_of_pcaps, statistics, logger):
    # Print the results
    logger.info(str(statistics['total_urls']) + " Benign URLs were extracted from " + str(statistics['total_chains']) + " benign chains!\n")
    logger.info("=" * 100 + "\n")
    logger.info(str(num_of_pcaps - statistics['failed_pcaps'] - statistics['empty_pcaps']) + "/" + str(num_of_pcaps) + " PCAPs were successful!")
    logger.info(str(statistics['no_redir_pcaps']) + "/" + str(num_of_pcaps) + " PCAPs had no redirections!")
    logger.info(str(statistics['failed_pcaps']) + "/" + str(num_of_pcaps) + " PCAPs failed!")
    logger.info(str(statistics['empty_pcaps']) + "/" + str(num_of_pcaps) + " PCAPs were empty (could be HTTPS/404)!\n")


def print_malicious_stats(num_of_pcaps, statistics, logger):
    # How many URLs did we fail to capture (semi-correct/incorrect)?
    urls_extracted = statistics['total_urls'] - statistics['missed_redirects']
    percentage = 0
    if statistics['total_urls'] > 0:
        percentage = round(((urls_extracted / statistics['total_urls']) * 100), 2)

    # Print the results
    logger.info(
        str(urls_extracted) + "/" + str(statistics['total_urls']) + " (" + str(percentage) + "%) Malicious URLs were correctly extracted from " + str(num_of_pcaps) +
        " malicious chains!\n")
    logger.info("=" * 100 + "\n")

    # Calculate accuracy percentages
    percentage_correct = round((statistics['test_results']['correct'] / num_of_pcaps) * 100, 2)
    percentage_semi_correct = round((statistics['test_results']['partial'] / num_of_pcaps) * 100, 2)
    percentage_incorrect = round((statistics['test_results']['incorrect'] / num_of_pcaps) * 100, 2)
    percentage_missing_C = round((statistics['missing_compromised'] / num_of_pcaps) * 100, 2)
    percentage_malvertising = round((statistics['malvertising'] / num_of_pcaps) * 100, 2)

    # Log results
    logger.info(str(statistics['test_results']['correct']) + "/" + str(num_of_pcaps) + " (" + str(percentage_correct) + "%) Malicious chains were correctly identified!")
    logger.info(
        str(statistics['test_results']['partial']) + "/" + str(num_of_pcaps) + " (" + str(percentage_semi_correct) + "%) Malicious chains were semi-correctly identified!")
    logger.info(
        str(statistics['test_results']['incorrect']) + "/" + str(num_of_pcaps) + " (" + str(percentage_incorrect) + "%) Malicious chains were incorrectly identified!\n")
    logger.info(str(statistics['missing_compromised']) + "/" + str(num_of_pcaps) + " (" + str(percentage_missing_C) + "%) PCAPs were missing the compromised site!")
    logger.info(str(statistics['malvertising']) + "/" + str(num_of_pcaps) + " (" + str(percentage_malvertising) + "%) PCAPs were Malvertising!\n")


def print_timing(num_of_pcaps, statistics, logger):
    # Print total execution time
    total_time = divmod(time.time() - statistics['start_time'], 60)
    average_pcap_time = round((time.time() - statistics['start_time']) / num_of_pcaps, 2)
    average_chain_time = round((time.time() - statistics['start_time']) / statistics['total_chains'], 2)
    logger.info("Total execution time: " + str(int(total_time[0])) + " minutes and " + str(round(total_time[1], 2)) + " seconds!")
    logger.info("Average PCAP processing time: " + str(average_pcap_time) + " seconds!")
    logger.info("Average chain processing time: " + str(average_chain_time) + " seconds!\n")


def print_tree(tree, logger):
    # Print redirection tree
    for pre, _, node in RenderTree(tree):
        if not node.is_root:
            redirs_to_print = '/'.join(node.redirs)
            logger.info("%s%s (%s) [%s]" % (pre, node.name, redirs_to_print, node.seconds))
        else:
            logger.info("%s%s" % (pre, node.name))
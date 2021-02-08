import time
import os
import re
import webbrowser
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import NoSuchElementException
import subprocess
import requests
import json
import time
import urllib3


def end_dump(browser, dump):
    FNULL = open(os.devnull, 'w')

    # Close the browser
    browser.quit()
    try:
        subprocess.Popen('TASKKILL /IM iexplore.exe /T /F /FI "STATUS eq RUNNING"', stdout=FNULL, stderr=FNULL)
    except:
        pass
    time.sleep(1)

    # End PCAP
    if dump:
        dump.kill()
        try:
            subprocess.Popen('TASKKILL /IM tshark.exe /T /F /FI "STATUS eq RUNNING"', stdout=FNULL, stderr=FNULL)
        except:
            pass
        time.sleep(1)


def main():
    # Disable SSL warning from VT contact
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Program start time
    start_time = time.time()

    # Query URL in virus_total before processing
    vt_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    vt_params = {'apikey': 'ab453259e9ce24ed6990d5ac1460c69b687014121f4c825555660f03eb88aec3', 'resource': '', 'scan': 1}

    # Directory to store PCAPs
    pcap_dir = r'C:\\Users\\Crystal\\Desktop\\benign_data_gen\\PCAPs\\'
    # URL Processing results
    malicious_urls = r'C:\\Users\\Crystal\\Desktop\\benign_data_gen\\malicious_urls.txt'
    failed_urls = r'C:\\Users\\Crystal\\Desktop\\benign_data_gen\\failed_urls.txt'
    successful_urls = r'C:\\Users\\Crystal\\Desktop\\benign_data_gen\\successful_urls.txt'

    # Load the URLs
    with open('urls.txt') as f:
        urls = f.readlines()

    # Strip any whitespace
    urls = [x.strip() for x in urls]

    # Set up the web browser
    IE_path = r'C:\\Users\\Crystal\\Desktop\\benign_data_gen\\IEDriverServer.exe'
    option = webdriver.IeOptions()
    option.add_additional_option("ignoreProtectedModeSettings", True)
    option.add_additional_option("unexpectedAlertBehaviour", "accept")
    option.add_additional_option("acceptSslCerts", True)
    option.add_additional_option("javascriptEnabled", True)
    option.add_additional_option("enablePersistentHover", True)

    pcap_count = 0

    # Delete files if they already exists
    if os.path.exists(malicious_urls):
        os.remove(malicious_urls)
    if os.path.exists(failed_urls):
        os.remove(failed_urls)
    if os.path.exists(successful_urls):
        os.remove(successful_urls)

    for url in urls:
        pcap_count += 1
        malicious = False

        # Check VT
        vt_params['resource'] = url
        response = (requests.get(vt_url, params=vt_params, verify=False)).json()

        if 'positives' in response:
            # If the URL is classified as malicious
            if response['positives'] >= 1:
                malicious = True
                # Save malicious URL to file
                with open(malicious_urls, 'a+') as f:
                    print(url + " flagged by virustotal: " + str(response['positives']))
                    f.write(url + '\n')

        # If the URL wasn't detected as malicious
        if not malicious:
            # Strip HTTP(S)://www. (for filename)
            stripped_url = (re.search(r"(https?://)?(www\.)?([a-z0-9\-\.\:]+)", url, flags=re.I)).group(3).lower()
            if not re.search(r"^(https?\:\/\/(www\.)?)", url, re.I):
                url = "http://" + url
            # Try and process the URL
            try:
                browser = webdriver.Ie(executable_path=IE_path, options=option)
                browser.set_page_load_timeout(60)
                # Capture the PCAP
                capture_pcap(pcap_dir + stripped_url, browser, url, failed_urls)
                # Save successful URL
                if os.path.exists(pcap_dir + stripped_url + '.pcap'):
                    with open(successful_urls, 'a+') as f:
                        f.write(url + '\n')
            except BaseException as e:
                # Stored the failed URL
                with open(failed_urls, 'a+') as f:
                    print(url + " failed!")
                    print(str(e))
                    f.write(url + ',' + str(e))
                # End the packet capture and exit browser windows
                end_dump(browser, None)

    # Print total execution time
    total_time = divmod(time.time() - start_time, 60)
    average_time = round((time.time() - start_time) / pcap_count, 2)
    print("Total execution time: " + str(int(total_time[0])) + " minutes and " + str(round(total_time[1], 2)) + " seconds!")
    print("Average PCAP processing time: " + str(average_time) + " seconds!\n")


def capture_pcap(pcap_dir, browser, url, failed_urls):

    # Start the PCAP - note we only want traffic from this host
    dump = subprocess.Popen([r'C:\Program Files\Wireshark\tshark.exe', '-s', '65535', '-w', pcap_dir + '.pcap', '-n', '-i', '1', '-f', 'host 192.168.226.132'])

    try:
        # Open the website
        browser.get(url)
    except BaseException as e:
        # Stored the failed URL
        with open(failed_urls, 'a+') as f:
            print(url + " failed! PCAP removed!")
            print(str(e))
            f.write(url + ',' + str(e))
        # End the packet capture and exit browser windows
        end_dump(browser, dump)
        # Delete the PCAP if page failed to load
        os.remove(pcap_dir + '.pcap')
        return

    # Click OK on any GDPR alerts etc
    try:
        browser.find_element_by_xpath("//input[@type='submit' and @value='OK']").click()
    except:
        pass
    try:
        browser.find_element_by_xpath("//*[@id='form_save']").click()
    except:
        pass

    # Wait for x more seconds to ensure all redirections have occurred
    time.sleep(10)

    # End the packet capture and exit browser windows
    end_dump(browser, dump)


if __name__ == "__main__":
    main()

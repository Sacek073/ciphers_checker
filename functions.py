import subprocess
import requests
import os
from prettytable import PrettyTable
from ansicolors import *
import xml.etree.ElementTree as ET

# Windows
SSLSCANPATH = "C:\\Users\\klusacekj\\Documents\\Tools\\sslscan-2.1.4\\sslscan.exe"
# Linux
# SSLSCANPATH = "sslscan"


def get_ciphers_nmap(domain, port):
    """
    Run nmap to get the ciphers used in the domain and port
    Output is saved in a file tmp_{domain}_{port}.xml and also returned as a string
    """
    cmd = f"nmap -oX tmp_{domain}_{port}.xml -p {port} -Pn --script ssl-enum-ciphers,ssl-cert {domain}"
    print(f"Running nmap for host: {domain} on port: {port}")
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    return output

def get_results_sslscan(domain, port):
    """
    Run sslscan in order to get info about SSLv2, SSLv3 and TLS Compression
    """
    cmd = f"{SSLSCANPATH} --xml=tmp_sslscan_{domain}_{port}.xml {domain}:{port}"
    print(f"Running sslscan for host: {domain} on port: {port}")
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    return output


def parse_ciphers(domain=None, port=None, file=None):
    """
    Function parses the xml file generated by nmap and returns the ciphers used
    """
    root = get_xml_root(domain, port, file)
    ciphers_table = root.findall(".//table[@key='ciphers']")

    ciphers = {}
    # for table in ciphers_table:
    #     for cipher in table.findall(".//elem[@key='name']"):
    #         ciphers.append(cipher.text)

    for table in ciphers_table:
        cipher_name = None
        kex_info = None

        for elem in table.findall(".//elem"):
            try:
                if elem.get("key") == "name":
                    cipher_name = elem.text
                elif elem.get("key") == "kex_info":
                    kex_info = elem.text
                if cipher_name and kex_info:
                    ciphers[cipher_name] = kex_info
            except:
                # Element is not cipher
                pass

    return ciphers


def remove_tmp_files(domain, port):
    """
    Removes tmp file generated by nmap
    """
    try:
        os.remove(f"tmp_{domain}_{port}.xml")
        os.remove(f"tmp_sslscan_{domain}_{port}.xml")
    except:
        pass


def get_stats(cipher):
    """
    Function returns the stats of a cipher, using the ciphersuite.info API
    """
    url = f"https://ciphersuite.info/api/cs/{cipher}"

    payload = {}
    headers = {
    'Accept': 'application/json'
    }

    response = requests.request("GET", url, headers=headers, data=payload)
    data = response.json()

    return data


def print_table(results):
    """
    Function prints the results in a table
    """
    print("Overview of the used ciphers (ciphersuite.info):")
    table = PrettyTable()
    table.field_names = ["Cipher", "Security", "TLS", "URL"]
    for key, value in results.items():
        value = value.get("stats")
        tls_versions = [tls_color(float(tls[3:])) for tls in value.get('tls_version')]

        table.add_row([key, security_color(value.get('security')), ",".join(tls_versions), f"https://ciphersuite.info/cs/{key}"])

    table.align["Cipher"] = "l"
    table.align["URL"] = "l"
    print(table)


def tls_color(version):
    """
    Adds colors to output based on the TLS version
    """
    if version < 1.1: # TODO nastavit správnou hodnotu
        return f"{RED}{str(version)}{RESET}"
    elif version < 1.2:
        return f"{YELLOW}{str(version)}{RESET}"
    else:
        return f"{str(version)}"

def security_color(word):
    """
    Adds colors to output based on the security of the cipher
    Colors are coresponing to the security level on the web version of ciphersuite.info
    """
    if word == "secure":
        return f"{LIGHT_GREEN}{word}{RESET}"
    elif word == "recommended":
        return f"{GREEN}{word}{RESET}"
    elif word == "weak":
        return f"{YELLOW}{word}{RESET}"
    elif word == "insecure":
        return f"{RED}{word}{RESET}"
    else:
        return word


def get_xml_root(domain=None, port=None, file=None):
    if file:
        tree = ET.parse(file)
    elif domain and port:
        tree = ET.parse(f"tmp_{domain}_{port}.xml")
    else:
        print("No file or domain and port specified in function parse_ciphers, exitting...")
        exit(1)

    return tree.getroot()

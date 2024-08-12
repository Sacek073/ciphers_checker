import subprocess
import requests
from prettytable import PrettyTable
import xml.etree.ElementTree as ET


def get_ciphers_nmap(domain, port):
    """
    Run nmap to get the ciphers used in the domain and port
    Output is saved in a file tmp_{domain}_{port}.xml and also returned as a string
    """
    cmd = f"nmap -oX tmp_{domain}_{port}.xml -p {port} -Pn --script ssl-enum-ciphers {domain}"
    print(f"Running nmap for host: {domain} on port: {port}")
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    return output


def parse_ciphers(domain, port):
    """
    Function parses the xml file generated by nmap and returns the ciphers used
    """
    tree = ET.parse(f"tmp_{domain}_{port}.xml")
    root = tree.getroot()
    ciphers_table = root.findall(".//table[@key='ciphers']")

    ciphers = []
    for table in ciphers_table:
        for cipher in table.findall(".//elem[@key='name']"):
            ciphers.append(cipher.text)

    return ciphers


def parse_ciphers_file(file):
    """
    Function parses the file with ciphers and returns the ciphers
    """
    with open(file, "r") as f:
        ciphers = [line.strip() for line in f.readlines()]

    return ciphers


def remove_tmp_file(domain, port):
    """
    Removes tmp file generated by nmap
    """
    cmd = f"rm tmp_{domain}_{port}.xml"
    subprocess.check_output(cmd, shell=True, universal_newlines=True)


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
    table = PrettyTable()
    table.field_names = ["Cipher", "Security", "TLS", "URL"]
    for key, value in results.items():
        tls_versions = [tls_color(float(tls[3:])) for tls in value.get('tls_version')]

        table.add_row([key, security_color(value.get('security')), ",".join(tls_versions), f"https://ciphersuite.info/cs/{key}"])

    table.align["Cipher"] = "l"
    table.align["URL"] = "l"
    print(table)


def tls_color(version):
    """
    Adds colors to output based on the TLS version
    """
    RED = "\033[31m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"

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
    SECURE = "\033[92m"
    RECCOMENDED = "\033[32m"
    WEAK = "\033[33m"
    INSECURE = "\033[31m"
    RESET = "\033[0m"

    if word == "secure":
        return f"{SECURE}{word}{RESET}"
    elif word == "reccomended":
        return f"{RECCOMENDED}{word}{RESET}"
    elif word == "weak":
        return f"{WEAK}{word}{RESET}"
    elif word == "insecure":
        return f"{INSECURE}{word}{RESET}"
    else:
        return word
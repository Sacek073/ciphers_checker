from prettytable import PrettyTable
from ansicolors import *
import xml.etree.ElementTree as ET
import functions


def result_wrapper(func):
    """
    Wraps result into table and prints it
    """
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        table = PrettyTable()
        table.align = "l"
        table.field_names = ["Cipher", "Result"]

        for key, value in result.items():
            table.add_row([key, value])

        print(table)
        print(70*"#")
        return result
    return wrapper


@result_wrapper
def is_TLS_1(stats):
    print("Testing for TLS 1.0 support:")
    result = {}
    for key, value in stats.items():
        value = value.get("stats")
        tls_versions = value.get('tls_version')
        if "TLS1.0" in tls_versions:
            result[f"{RED}{key}{RESET}"] = "supports TLS 1.0"
        else:
            result[f"{GREEN}{key}{RESET}"] = "does not support TLS 1.0"
    return result


@result_wrapper
def no_forward_secrecy(stats):
    print("Testing for forward secrecy:")
    result = {}
    # PFS ciphers use DHE or ECDHE or EDH
    for key in stats:
        if "ECDHE" in key.upper() or "DHE" in key.upper() or "EDH" in key.upper():
            result[f"{GREEN}{key}{RESET}"] = "supports forward secrecy"
        else:
            result[f"{RED}{key}{RESET}"] = "does not support forward secrecy"
    return result


@result_wrapper
def sweet_32(stats):
    print("Testing for SWEET32 vulnerability:")
    result = {}
    # SWEET32 ciphers use 3DES or BLOWFISH with block size 64 bits
    # https://sweet32.info
    # But also DES and IDEA use 64 bit block size
    for key in stats:
        if "3DES" in key.upper() or "BLOWFISH" in key.upper() or "DES" in key.upper() or "IDEA" in key.upper():
            result[f"{RED}{key}{RESET}"] = "vulnerable to SWEET32"
        else:
            result[f"{GREEN}{key}{RESET}"] = "not vulnerable to SWEET32"
    return result


@result_wrapper
def supports_RC4(stats):
    print("Testing for RC4 support:")
    result = {}
    for key in stats:
        if "RC4" in key.upper():
            result[f"{RED}{key}{RESET}"] = "supports RC4"
        else:
            result[f"{GREEN}{key}{RESET}"] = "does not support RC4"
    return result


@result_wrapper
def export_ciphers(stats):
    print("Testing for EXPORT ciphers:")
    result = {}
    for key in stats:
        if "EXPORT" in key.upper():
            result[f"{RED}{key}{RESET}"] = "is EXPORT cipher"
        else:
            result[f"{GREEN}{key}{RESET}"] = "is not EXPORT cipher"
    return result


@result_wrapper
def null_ciphers(stats):
    print("Testing for NULL ciphers:")
    result = {}
    for key in stats:
        if "NULL" in key.upper():
            result[f"{RED}{key}{RESET}"] = "is NULL cipher"
        else:
            result[f"{GREEN}{key}{RESET}"] = "is not NULL cipher"
    return result


@result_wrapper
def anon_ciphers(stats):
    print("Testing for anonymous ciphers:")
    result = {}
    for key in stats:
        if "anon" in key.lower():
            result[f"{RED}{key}{RESET}"] = "is anonymous cipher"
        else:
            result[f"{GREEN}{key}{RESET}"] = "is not anonymous cipher"
    return result


@result_wrapper
def logjam(stats):
    print("Testing for Logjam vulnerability:")
    result = {}
    # Logjam ciphers use DHE with 1024 or 512 or 256 or 128 bits
    # https://weakdh.org/
    for key, value in stats.items():
        value = value.get("kex_info")
        if "dh " in value.lower():
            value = value.split(" ")
            bits = int(value[1])
            if bits < 2048:
                result[f"{RED}{key}{RESET}"] = "vulnerable to Logjam"
            else:
                result[f"{GREEN}{key}{RESET}"] = "not vulnerable to Logjam"
        else:
            result[f"{GREEN}{key}{RESET}"] = "not vulnerable to Logjam"
    return result


@result_wrapper
def supports_CBC(stats):
    print("Testing for CBC support:")
    result = {}
    for key in stats:
        if "CBC" in key.upper():
            result[f"{RED}{key}{RESET}"] = "supports CBC"
        else:
            result[f"{GREEN}{key}{RESET}"] = "does not support CBC"
    return result


def sslscan_findings(domain=None, port=None):
    if domain and port:
        tree = ET.parse(f"tmp_sslscan_{domain}_{port}.xml")
    else:
        print("No file or domain and port specified in function parse_ciphers, exitting...")
        functions.remove_tmp_files(domain, port)
        exit(1)

    root = tree.getroot()
    # SSLv2 anf SSLv3
    ssls = root.findall(".//protocol[@type='ssl']")
    for ssl in ssls:
        print(f"SSLv{ssl.get('version')} is {f'{RED}enabled{RESET}' if ssl.get('enabled') == 1 else f'{GREEN}disabled{RESET}'}")

    # TLS Compression
    tls_compression = root.findall(".//compression")
    if len(tls_compression) == 0:
        print(f"{RED}TLS Compression information cannot be fetched, probably error in sslscan, check the output manually.{RESET}")
    for compression in tls_compression:
        print(f"TLS Compression is {f'{RED}supported{RESET}' if compression.get('supported') == 1 else f'{GREEN}not supported{RESET}'}")

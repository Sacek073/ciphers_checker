from prettytable import PrettyTable
from ansicolors import *


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
        if "ECDHE" in key or "DHE" in key or "EDH" in key:
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
        if "3DES" in key or "BLOWFISH" in key or "DES" in key or "IDEA" in key:
            result[f"{RED}{key}{RESET}"] = "vulnerable to SWEET32"
        else:
            result[f"{GREEN}{key}{RESET}"] = "not vulnerable to SWEET32"
    return result


@result_wrapper
def supports_RC4(stats):
    print("Testing for RC4 support:")
    result = {}
    for key in stats:
        if "RC4" in key:
            result[f"{RED}{key}{RESET}"] = "supports RC4"
        else:
            result[f"{GREEN}{key}{RESET}"] = "does not support RC4"
    return result


@result_wrapper
def weak_SSL(stats):
    print("TBD: Testing for weak SSL support:")
    # TODO
    return {"TBD": "TBD"}


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
        if "CBC" in key:
            result[f"{RED}{key}{RESET}"] = "supports CBC"
        else:
            result[f"{GREEN}{key}{RESET}"] = "does not support CBC"
    return result
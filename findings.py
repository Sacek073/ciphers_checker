from prettytable import PrettyTable
# ANSI escape codes for colors
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def result_wrapper(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        table = PrettyTable()
        table.align = "l"
        table.field_names = ["Cipher", "Result"]

        for key, value in result.items():
            table.add_row([key, value])

        print(table)
        print("######################################################################")
        return result
    return wrapper


@result_wrapper
def is_TLS_1(stats):
    print("Testing for TLS 1.0 support:")
    result = {}
    for key, value in stats.items():
        tls_versions = value.get('tls_version')
        if "TLS1.0" in tls_versions:
            result[f"{RED}{key}{RESET}"] = "supports TLS 1.0"
        else:
            result[f"{GREEN}{key}{RESET}"] = "does not support TLS 1.0"
    return result


@result_wrapper
def no_forward_secrecy(stats):
    ...


@result_wrapper
def sweet_32(stats):
    ...


@result_wrapper
def supports_RC4(stats):
    print("Testing for RC4 support:")
    result = {}
    for key in stats:
        # TODO
        if "RC4" in key:
            result[f"{RED}{key}{RESET}"] = "supports RC4"
        else:
            result[f"{GREEN}{key}{RESET}"] = "does not support RC4"
    return result


@result_wrapper
def weak_SSL(stats):
    ...


@result_wrapper
def logjam(stats):
    ...


@result_wrapper
def supports_CBC(stats):
    print("Testing for CBC support:")
    result = {}
    for key in stats:
        # TODO
        if "CBC" in key:
            result[f"{RED}{key}{RESET}"] = "supports CBC"
        else:
            result[f"{GREEN}{key}{RESET}"] = "does not support CBC"
    return result
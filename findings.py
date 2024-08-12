# ANSI escape codes for colors
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def wrap_finding(func):
    def wrapper(stats):
        print("######################################################################")
        func(stats)

    return wrapper

@wrap_finding
def is_TLS_1(stats):
    print("Testing for TLS 1.0 support:")
    for key, value in stats.items():
        tls_versions = value.get('tls_version')
        if "TLS1.0" in tls_versions:
            print(f"{RED}{key.ljust(45)}{RESET} supports TLS 1.0")
        else:
            print(f"{GREEN}{key.ljust(45)}{RESET} does not support TLS 1.0{RESET}")


@wrap_finding
def no_forward_secrecy(stats):
    ...


@wrap_finding
def sweet_32(stats):
    ...


@wrap_finding
def supports_RC4(stats):
    print("Testing for RC4 support:")
    for key in stats:
        # TODO
        if "RC4" in key:
            print(f"{RED}{key.ljust(45)}{RESET} supports RC4{RESET}")
        else:
            print(f"{GREEN}{key.ljust(45)}{RESET} does not support RC4{RESET}")


@wrap_finding
def weak_SSL(stats):
    ...


@wrap_finding
def logjam(stats):
    ...


@wrap_finding
def supports_CBC(stats):
    print("Testing for CBC support:")
    for key in stats:
        # TODO
        if "CBC" in key:
            print(f"{RED}{key.ljust(45)}{RESET} supports CBC")
        else:
            print(f"{GREEN}{key.ljust(45)}{RESET} does not support CBC")
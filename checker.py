import functions
import argparse
import signal
import findings


# Global variables used for removeing tmp file when SIGINT is received
domain = ""
port = 0


def arguments():
    parser = argparse.ArgumentParser(description="Check the strength of the ciphers used in app. To use this script, specify the input file, or specify the domain and port to check")
    parser.add_argument("-d", "--domain", help="Domain to check", type=str)
    parser.add_argument("-p", "--port", help="Port to check", type=int)
    parser.add_argument("-f", "--file", help="Input file with ciphers separated by newline, if this argument is present, domain and port is ignored", type=str)
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    args = parser.parse_args()

    if args.file:
        if args.domain or args.port:
            print("If you specify the input file, domain and port are ignored")
    else:
        if not args.domain or not args.port:
            print("Domain and port are required")
            exit(1)

    return args


def signal_handler(sig, frame):
    print("Ctrl-C pressed. Exiting...")
    try:
        functions.remove_tmp_file(domain, port)
    except:
        pass
    exit(0)


if __name__ == '__main__':

    # Handle Ctrl-C
    signal.signal(signal.SIGINT, signal_handler)

    # Get settings from command line
    args = arguments()
    domain = args.domain
    port = args.port
    verbose = args.verbose
    file = args.file

    if not file:
        output = functions.get_ciphers_nmap(domain, port)
        if verbose: # Prints nmap output
            print(output)
        ciphers = functions.parse_ciphers(domain=domain, port=port)
    else:
        ciphers = functions.parse_ciphers(file=file)

    stats = {}
    for key, value in ciphers.items():
        stats[key] = {"kex_info": value, "stats": functions.get_stats(key).get(key)}

    functions.print_table(stats)

    print("FOLLOWING SECTION COVERS FINDINGS FROM THE DATABASE:")

    findings.is_TLS_1(stats)
    findings.no_forward_secrecy(stats)
    findings.sweet_32(stats)
    findings.supports_RC4(stats)
    findings.weak_SSL(stats)
    findings.logjam(stats)
    findings.supports_CBC(stats)

    if not file:
        functions.remove_tmp_file(domain, port)
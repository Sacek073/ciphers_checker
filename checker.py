import argparse
import signal
import findings
import functions
from ansicolors import *


# Global variables used for removing tmp file when SIGINT is received
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
        functions.remove_tmp_files(domain, port)
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
        output_nmap = functions.get_ciphers_nmap(domain, port)
        if verbose: # Prints nmap output
            print(output_nmap)
            print(70*"#")


        ciphers = functions.parse_ciphers(domain=domain, port=port)

    else:
        print(f"Reading ciphers from file: {file}")
        ciphers = functions.parse_ciphers(file=file)

    stats = {}
    for key, value in ciphers.items():
        try:
            stats[key] = {"kex_info": value, "stats": functions.get_stats(key).get(key)}
        except:
            # If the error occurs here, it is probably because the cipher is not found in the ciphersuite.info
            print(f"{YELLOW}Error getting stats for {key}{RESET}")

    functions.print_table(stats)

    print("FOLLOWING SECTION COVERS FINDINGS FROM THE DATABASE:")

    findings.is_TLS_1(stats)
    findings.no_forward_secrecy(stats)
    findings.sweet_32(stats)
    findings.supports_RC4(stats)
    findings.logjam(stats)
    findings.supports_CBC(stats)

    print(70*"#")
    print("Following sections covers WEAK SSL FINDING from databse:")

    findings.export_ciphers(stats)
    findings.null_ciphers(stats)
    findings.anon_ciphers(stats)

    if not file:
        findings.tls_compression(domain=domain, port=port)
    else:
        findings.tls_compression(file=file)

    if not file:
        try:
            print(70*"#")
            print(f"{YELLOW}NOTE: FOR THE TESTING OF {RED}SSLv2{YELLOW} AND {RED}SSLv3{YELLOW}, THE SSLSCAN TOOL IS NECESSARY.\nPLEASE CONFIGURE IT'S PATH IN THE FILE functions.py on line 9.{RESET}")
            sslscan_output = functions.get_results_sslscan(domain, port)
            if verbose:
                print(sslscan_output)
                print(70*"#")

            findings.sslscan_findings(domain, port)

        except Exception as e:
            print(f"{RED}Error getting SSLSCAN info: {e}{RESET}")
    else:
        print(70*"#")
        print(f"{YELLOW}NOTE: FOR THE TESTING OF {RED}SSLv2{YELLOW} AND {RED}SSLv3{YELLOW}, THE SSLSCAN LIVE SCAN IS NECESSARY, WHICH IS UNAVAILABLE WITH THE FILE OPTION (-f). THIS TEST WILL BE SKIPPED.{RESET}")

    print(70*"#")
    if not file:
        findings.certificate_test(domain=domain, port=port)
    else:
        findings.certificate_test(file=file)


    if not file:
        functions.remove_tmp_files(domain, port)

import functions
import argparse

def arguments():
    parser = argparse.ArgumentParser(description="Check the strength of the ciphers used in app.")
    parser.add_argument("-d", "--domain", help="Domain to check", required=True, type=str)
    parser.add_argument("-p", "--port", help="Port to check", required=True, type=int)
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    # Get settings from command line
    args = arguments()
    domain = args.domain
    port = args.port
    verbose = args.verbose

    output = functions.get_ciphers_nmap(domain, port)
    if verbose: # Prints nmap output
        print(output)

    ciphers = functions.parse_ciphers(domain, port)
    stats = {}

    for cipher in ciphers:
        stats[f"{cipher}"] = functions.get_stats(cipher).get(f"{cipher}")


    functions.print_results(stats)

    functions.remove_tmp_file(domain, port)
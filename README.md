# Ciphers checker
This repository contains script for checking the strength of the ciphers used.

* For enumeration of the ciphers the nmap script ssl-enum-ciphers is used.
* For verification of the strength the ciphersuite.info is used.
* Custom checks are also implemented.

## Dependecies
In order to run this script it is necessary to have installed nmap and python3.
* https://nmap.org/
* https://www.python.org/downloads/

The script runs both on Linux and Windows, it suposses that nmap is in PATH, so the nmap command is executed without specific path as:

```
functions.py line 21:
cmd = f"nmap -oX tmp_{domain}_{port}.xml -p {port} -Pn --script ssl-enum-ciphers {domain}"
```

In case that nmap is not in PATH, the script will probably fail. In that case you can modify the line above and specify the path to nmap.

Before running the script, it is necessary to install the required python packages. This can be done by running the following command:

```
pip install -r requirements.txt
```

The script uses ANSI escape codes for coloring the output. It is possible to expirience problems with older terminals/command line apps.

## Usage
This scripts offers two modes of operation:
1) Live nmap scan + ciphersuite.info check
2) Input file with nmap scan results + ciphersuite.info check

For both of these modes the script needs internet connectivity to fetch the data about ciphers used from ciphersuite.info.

### Live nmap scan + ciphersuite.info check
To run the script in this mode, you need to specify the domain and the port to scan.

```
python3 checker.py -d www.example.com -p 443
```

### Input file with nmap scan results + ciphersuite.info check
To run the script in this mode, you need to specify the input file. The input file needs to be xml output from the nmap scan, which you can obtain by running the following command:

```
nmap -oX output.xml -p 443 -Pn --script ssl-enum-ciphers www.example.com
```

Then the usage of the script is as follows:

```
python3 checker.py -f output.xml
```
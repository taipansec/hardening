from argparse import ArgumentParser, RawTextHelpFormatter
from sys import exit


# initializing argument parser
parser = ArgumentParser(prog='ubu20cis',
                        description='Perform CIS Benchmark scoring on your Linux System',
                        usage='# ./%(prog)s [optional arguments]',
                        epilog='Enjoy Hardening your System!',
                        formatter_class=RawTextHelpFormatter)

# ubu20cis version
parser.version = '%(prog)s v0.5.1'

# optional arguments

# inlcude
parser.add_argument('-i', '--include', type=str, nargs='+',
                    action='store', help='List recommendations to be INCLUDED in score (Whitelist)'
                    '\nDefault all recommendations are benchmarked'
                    '\nGive recommendations seperated by space'
                    '\nExample:'
                    '\n --include 1.*   [Will only score Initial Setup]'
                    '\n --include 2.1.* [Will only score inetd Services]')

# exclude
parser.add_argument('-e', '--exclude', type=str, nargs='+',
                    action='store', help='List recommendations to be EXCLUDED in score (Blacklist)'
                    '\nDefault NONE of the recommendations will be excluded'
                    '\nGive recommendations seperated by space'
                    '\nExample:'
                    '\n --exclude 3.*  [Skip scoring of Network Parameters]'
                    '\n --exclude 4.2* [Skip scoring of logging]')

# level 1 / level 2
parser.add_argument('-l', '--level', type=int, choices=[1, 2],
                    action='store', help='Select Profile Applicability ( Level 1 / Level 2 )'
                    '\nDefault both Level 1 AND Level 2 are benchmarked'
                    '\nExample:'
                    '\n --level 1 [Only Level 1 recommendations will be scored]'
                    '\n --level 2 [Only Level 2 recommendations will be scored]')

# Not Scored (0) / Scored (1)
parser.add_argument('-s', '--score', type=int, choices=[0, 1],
                    action='store', help='Choose to test (Not Scored) [or] (Scored)'
                    '\nDefault both Scored and Not Scored are benchmarked'
                    '\nExample:'
                    '\n --score 0 [Only Not Scored recommendations are checked]'
                    '\n --score 1 [Only Scored recommendations will be checked]')

# Server / Workstation
parser.add_argument('-p', '--platform', type=str, choices=['server', 'workstation'],
                    action='store', help='Choose to test Servers [or] Workstations'
                    '\nDefault both Servers and Workstations are benchmarked'
                    '\nExample:'
                    '\n -p server [Only recommendations of servers are checked]'
                    '\n -p workstation [Only check workstation recommendations]')

# Auditor name
parser.add_argument('-a', '--auditor', type=str, metavar='AUDITOR_NAME',
                    action='store', help='Name of the Auditor performing the benchmark'
                    '\nDefault auditor name is taken as: None'
                    '\nExample:'
                    '\n -a Brian')

# Organization name
parser.add_argument('-o', '--org', type=str, metavar='ORGANIZATION_NAME',
                    action='store', help='Name of the Organization being audited'
                    '\nUsed to name the audit report file as ORG-sysid.ubu20cis'
                    '\nDefault organization name is taken as: None'
                    '\nExample:'
                    '\n -o DMB'
                    '\nResultant binary file would be DMB-None.ubu20cis')

# Unique System ID
parser.add_argument('-u', '--unique', type=str, metavar='UNIQUE_SYSTEM_ID',
                    action='store', help='Name to uniquely identify the system in the org'
                    '\nUsed to name the audit report file as org-SYSID.ubu20cis'
                    '\nDefault system ID is taken as: None'
                    '\nExample:'
                    '\n -u 710'
                    '\nResultant binary file would be None-710.ubu20cis')

# Description about the system
parser.add_argument('-d', '--descript', type=str, nargs='+',
                    action='store', help='Any auditor notes for future reference'
                    '\nExample:'
                    '\n -d This is a sample description'
                    '\n -d \t\'This is an example of how to store\n\tA description on multiple lines\'')

# Linux Distribution of the system
parser.add_argument('--dist', type=str, choices=['deb', 'ubu'],
                    action='store', help='Specify distribution of auditing system if known'
                    '\nDefault benchmarks against independent'
                    '\nLegend:'
                    '\ndeb - Debian 9 v1.0.1'
                    '\nubu - Ubuntu 18.04 LTS v2.0.2'
                    '\nExample:'
                    '\n --dist deb')

# Report Generation
parser.add_argument('-r', '--report', type=str, metavar='ubu20cis.csv',
                    action='store', help='Generate report from a ubu20cis.csv file'
                    '\nUse to generate a org-sysid.pdf report'
                    '\nFrom modified ubu20cis.csv(s)'
                    '\nExample:'
                    '\n -r "None-None" [.ubu20cis.csv will be taken implicitly]'
                    '\n -r "~/csvs/*" [all *.ubu20cis.csv in folder called "csvs"]')

# Control explainer
parser.add_argument('--exp', type=str, nargs='+',
                    action='store', help='Explain a control based on recommendation number'
                    '\nExample:'
                    '\n --exp 4.1')

# Print result True/False
parser.add_argument('-v', '--verbose',
                    action='store_true', help='Display each score on the terminal')

# Print version
parser.add_argument('-V', '--version', action='version',
                    help='Display tool version and exit')


if __name__ == "__main__":
    exit('Please run ./ubu20cis -h')

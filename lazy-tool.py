import argparse
import time

from helpers.colors import Color, color_text
from helpers.config_tools import load_config
from helpers.scanner import process_host, checker
from helpers.process_results import parse_nmaps
from helpers.ad_tools import en_users, roasting, responder_run, pas_audit
from helpers.ssh_connect import close_all_ssh_connections


def main():
    """CLI entry point. Parses arguments and dispatches to the appropriate mode."""
    parser = argparse.ArgumentParser(description="This has turned into a big tool......")
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Select a mode")

    launch_parser = subparsers.add_parser("network-scans", help="Launch scans mode")
    launch_parser.add_argument("config_file", help="Path to YAML configuration file")
    launch_parser.add_argument("-live", required=False, action=argparse.BooleanOptionalAction, help="Use this one if you want to scan only live hosts. Using arp-scan")
    launch_parser.add_argument("-printonly", required=False, action=argparse.BooleanOptionalAction, help="Use this if you only want the scans to be printed and not started.")

    monitor_parser = subparsers.add_parser("monitor-scans", help="Monitor scans mode - this is probably broken now.")
    monitor_parser.add_argument("config_file", help="Path to YAML configuration file")

    results_parser = subparsers.add_parser("scan-results", help="Show scan results - this prob broken too.")
    results_parser.add_argument("config_file", help="Path to YAML configuration file")

    users_parser = subparsers.add_parser("users", help="Grab all enabled and all high priv users on the target AD domain.")
    users_parser.add_argument("-jumphost", "-jh", required=True, help="SSH host to run the command from")
    users_parser.add_argument("-dc-ip", "-dc", required=True, help="Target DC or AD machine IP")
    users_parser.add_argument("-user", "-u", required=True, help="Active Directory user. Example: admin@marvel.local")
    users_parser.add_argument("-password", "-p", required=True, help="Ehm Password of that user?")
    users_parser.add_argument("-domain", "-d", required=True, help="target domain. Example: marvel.local")

    roasting_parser = subparsers.add_parser("roasting", help="ASREPRoasting and Kerberoasting on the target AD domain.")
    roasting_parser.add_argument("-jumphost", "-jh", required=True, help="SSH host to run the command from")
    roasting_parser.add_argument("-dc-ip", "-dc", required=True, help="Target DC or AD machine IP")
    roasting_parser.add_argument("-user", "-u", required=True, help="Active Directory user. Example: admin@marvel.local")
    roasting_parser.add_argument("-password", "-p", required=True, help="Ehm Password of that user?")
    roasting_parser.add_argument("-domain", "-d", required=True, help="target domain. Example: marvel.local")

    responder_parser = subparsers.add_parser("responder", help="Start responder on target host.")
    responder_parser.add_argument("-jumphost", "-jh", required=True, help="SSH host to run the command from. If you provide a config file it will check all hosts for smb signing and run responder+ntlmrelayx in socks mode.")
    responder_parser.add_argument("--config_file", "-c", help="Path to YAML configuration file")

    pasaudit_parser = subparsers.add_parser("pass-audit", help="This will grab ntds.dit file, all enabled usersl, all high priv users, and dump the ntds.dit(this is done locally).")
    pasaudit_parser.add_argument("-jumphost", "-jh", required=False, help="SSH jumphost to run the command from, if there is one.")
    pasaudit_parser.add_argument("-dc-ip", "-dc", required=True, help="Target DC or AD machine IP")
    pasaudit_parser.add_argument("-user", "-u", required=True, help="Active Directory user. Example: admin@marvel.local")
    pasaudit_parser.add_argument("-password", "-p", required=True, help="Ehm Password of that user?")
    pasaudit_parser.add_argument("-domain", "-d", required=True, help="target domain. Example: marvel.local")
    pasaudit_parser.add_argument("-verbose", "-v", required=False, action=argparse.BooleanOptionalAction, help="Verbose output. You will see each running command and it's output.")

    parse_parser = subparsers.add_parser("parse", help="Parse nmap output. It will parse the output and create a directory with files that contain commands to run against the open services.")
    parse_parser.add_argument("--nmap-output", "-n", required=True, help="Path to nmap output directory or file.")
    parse_parser.add_argument("--no-http-check", "-nhc", required=False, action="store_true", help="Skip HTTP probing with httpx.")
    parse_parser.add_argument("--seclists-path", "-sp", required=False, default=None, help="Path to SecLists directory for wordlists.")
    parse_parser.add_argument("--check-tools", "-ct", required=False, action="store_true", help="Check which required tools are installed.")

    args = parser.parse_args()

    if args.mode == 'network-scans':
        config = load_config(args.config_file)

        if args.live:
            scans = process_host(config, True)
        else:
            scans = process_host(config)

    if args.mode == 'monitor-scans':
        config = load_config(args.config_file)

        print('monitoring NOW !!!')

        while True:
            for host in config['hosts']:
                print(f"\n{color_text('Checking status scans on:', Color.BOLD)} {host['name']}")
                checker(host)
            time.sleep(10)

    if args.mode == 'scan-results':
        config = load_config(args.config_file)
        for host in config['hosts']:
            print(f"\n{color_text('Downloading scans from:', Color.BOLD)} {host['name']}")

    if args.mode == 'users':
        en_users(args.jumphost, args.dc_ip, args.user, args.password, args.domain)

    if args.mode == 'roasting':
        roasting(args.jumphost, args.dc_ip, args.user, args.password, args.domain)

    if args.mode == 'responder':
        if args.config_file:
            config = load_config(args.config_file)
            responder_run(args.jumphost, config)
        else:
            responder_run(args.jumphost)

    if args.mode == 'pass-audit':
        if args.jumphost:
            pas_audit(args.dc_ip, args.user, args.password, args.domain, args.jumphost, args.verbose)
        else:
            pas_audit(args.dc_ip, args.user, args.password, args.domain)

    if args.mode == 'parse':
        parse_nmaps(args.nmap_output, no_http_check=args.no_http_check, seclists_path=args.seclists_path, check_tools=args.check_tools)

    close_all_ssh_connections()


if __name__ == "__main__":
    main()

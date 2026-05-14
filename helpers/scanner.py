import sys
import subprocess
from pathlib import Path

from helpers.ssh_connect import run_ssh_command, run_scp_command, check_ssh_config
from helpers.colors import Color, color_text
from helpers.config_tools import check_network_in_live_ips


def process_host(config, live=False):
    """Build nmap scan commands for each host in the config, optionally filtered by live hosts."""
    nmap_scans = {}

    if not live:
        for host_config in config['hosts']:
            host_name = host_config['name']
            scans = host_config['scans']
            ifs = []

            cwd = run_ssh_command(host_name, 'pwd')

            run_ssh_command(host_name, 'mkdir lazy-tool')
            run_ssh_command(host_name, 'mkdir lazy-tool/segtest-nmaps')

            if host_config.get('interfaces'):
                temp = host_config.get('interfaces')
                for item in temp.split(','):
                    ifs.append(item.strip())

            default_tcp = host_config.get('tcp', '-dd -n -T4 -sS -p- --min-rate=200 --traceroute --reason')
            default_udp = host_config.get('udp', '-dd -n -T4 -sU -sV --min-rate=1000 --traceroute --reason')

            scan_file = []
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
                            scan_file.append(f"sudo nmap -e {eth} {scan.get('tcp', default_tcp)} -oA {cwd[0]}/lazy-tool/segtest-nmaps/{host_name}.{eth}-to-{to}.tcp {scan['target']}")
                            scan_file.append(f"sudo nmap -e {eth} {scan.get('udp', default_udp)} -oA {cwd[0]}/lazy-tool/segtest-nmaps/{host_name}.{eth}-to-{to}.udp {scan['target']}")
                        else:
                            scan_file.append(f"sudo nmap -e {eth} {scan.get('tcp', default_tcp)} -oA {cwd[0]}/lazy-tool/segtest-nmaps/{host_name}.{eth}-to-{to}.tcp {scan['target']}")
                            scan_file.append(f"sudo nmap -e {eth} {scan.get('udp', default_udp)} -oA {cwd[0]}/lazy-tool/segtest-nmaps/{host_name}.{eth}-to-{to}.udp {scan['target']}")

                else:
                    if len(scan_file) == 0:
                        scan_file.append(f"sudo nmap {scan.get('tcp', default_tcp)} -oA {cwd[0]}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp {scan['target']}")
                        scan_file.append(f"sudo nmap {scan.get('udp', default_udp)} -oA {cwd[0]}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.udp {scan['target']}")
                    else:
                        scan_file.append(f"sudo nmap {scan.get('tcp', default_tcp)} -oA {cwd[0]}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp {scan['target']}")
                        scan_file.append(f"sudo nmap {scan.get('udp', default_udp)} -oA {cwd[0]}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.udp {scan['target']}")

            nmap_scans[host_name] = scan_file

    else:
        live_ips = {}

        for host in config['hosts']:
            arp = run_ssh_command(host['name'], 'which arp-scan')

            if 'not found' in arp[0]:
                print('arp-scan not installed on host.', host)
                sys.exit()

        for host_config in config['hosts']:
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
                sys.exit()

            create_local_dir = ['mkdir', f'{host_name}-live']
            create = subprocess.run(create_local_dir, capture_output=True, text=True)

            run_ssh_command(host_name, 'mkdir lazy-tool/segtest-live')

            arp_parse = r"awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}'"

            awk = "awk '{print $3}'"
            for eth in ifs:
                run_ssh_command(host_name, f'sudo arp-scan -I {eth} --localnet | {arp_parse} > lazy-tool/segtest-live/{host_name}.{eth}.live')
                ip = run_ssh_command(host_name, f"ip -4 -br a | grep {eth} | {awk} | cut -d '/' -f 1")
                live_ips[host_name][eth] = [ ip[0], f'{host_name}-live/{host_name}.{eth}.live', f'lazy-tool/segtest-live/{host_name}.{eth}.live']
                run_scp_command(host_name, f'{host_name}-live/{host_name}.{eth}.live', f'lazy-tool/segtest-live/{host_name}.{eth}.live', 'get')

        for host_config in config['hosts']:
            host_name = host_config['name']
            scans = host_config['scans']
            ifs = []
            if host_config.get('interfaces'):
                temp = host_config.get('interfaces')
                for item in temp.split(','):
                    ifs.append(item.strip())

            cwd = run_ssh_command(host_name, 'pwd')
            cwd = cwd[0]

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

                to = scan.get('target-network-name', '.'.join(scan.get('target').split('.')[:-1]))

                check, host, eth2, ip = check_network_in_live_ips(live_ips, scan.get('target'))

                if check:
                    create_local_dir = ['mkdir', f"from-{host_name}-to"]
                    create = subprocess.run(create_local_dir, capture_output=True, text=True)

                    copy_targets_locally = f"cp {host}-live/{host}.{eth2}.live from-{host_name}-to/."
                    copy = subprocess.run(copy_targets_locally, shell=True, capture_output=True, text=True)

                    run_ssh_command(host_name, 'mkdir lazy-tool/segtest-targets')
                    run_scp_command(host_name, f'from-{host_name}-to/{host}.{eth2}.live', f'lazy-tool/segtest-targets/{host}.{eth2}.live', 'put')

                    if scan.get('source'):
                        temp = scan.get('source')
                        for interfaces in temp.split(','):
                            nmap_scans[host_name].append(f"sudo nmap -e {interfaces} {scan.get('tcp', default_tcp)} -oA {cwd}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp -iL {cwd}/lazy-tool/segtest-targets/{host}.{eth2}.live")
                            nmap_scans[host_name].append(f"sudo nmap -e {interfaces} {scan.get('udp', default_udp)} -oA {cwd}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp -iL {cwd}/lazy-tool/segtest-targets/{host}.{eth2}.live")
                    else:
                        nmap_scans[host_name].append(f"sudo nmap {scan.get('tcp', default_tcp)} -oA {cwd}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp -iL {cwd}/lazy-tool/segtest-targets/{host}.{eth2}.live")
                        nmap_scans[host_name].append(f"sudo nmap {scan.get('udp', default_udp)} -oA {cwd}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp -iL {cwd}/lazy-tool/segtest-targets/{host}.{eth2}.live")

                else:
                    if scan.get('source'):
                        temp = scan.get('source')
                        for interfaces in temp.split(','):
                            nmap_scans[host_name].append(f"sudo nmap -e {interfaces} {scan.get('tcp', default_tcp)} -oA {cwd}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp {scan.get('target')}")
                            nmap_scans[host_name].append(f"sudo nmap -e {interfaces} {scan.get('udp', default_udp)} -oA {cwd}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp {scan.get('target')}")

                    else:
                        nmap_scans[host_name].append(f"sudo nmap {scan.get('tcp', default_tcp)} -oA {cwd}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp {scan.get('target')}")
                        nmap_scans[host_name].append(f"sudo nmap {scan.get('udp', default_udp)} -oA {cwd}/lazy-tool/segtest-nmaps/{host_name}-to-{to}.tcp {scan.get('target')}")

    for host in nmap_scans.keys():
        all_scans = ''

        for scan in nmap_scans[host]:
            all_scans += scan + '\n'

        run_ssh_command(host, f"echo '{all_scans}' > lazy-tool/all-scans")

    return None


def validate_access(config):
    """Check that each host in the config has the required SSH config and remote tools."""
    requirements = {
        'nmap': {
            'cmd': 'command -v nmap',
            'fix': 'sudo apt install -y nmap'
        },
        'tmux': {
            'cmd': 'command -v tmux',
            'fix': 'sudo apt install -y tmux'
        },
        'sudo_nopasswd': {
            'cmd': 'sudo -n true',
            'fix': 'Run "sudo visudo" and add: "$USER ALL=(ALL) NOPASSWD: ALL"'
        }
    }

    for host_config in config['hosts']:
        host_name = host_config['name']
        print(f"\n{color_text('Checking requirements on:', Color.BOLD)} {host_name}")

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
        sys.exit()


def start_nmaps(scan_file, host):
    """Upload the scan file to the remote host and start the scans in a tmux session."""
    host_name = host['name']

    create_local_dir = ['mkdir', f'{host_name}-segtest']
    create = subprocess.run(create_local_dir, capture_output=True, text=True)

    run_ssh_command(host_name, 'mkdir segtest')

    with open(f'{host_name}-segtest/full_nmap.xargs', 'w') as f:
        f.write(scan_file)

    cp = run_scp_command(host_name, f'{host_name}-segtest/full_nmap.xargs', f'segtest/full_nmap.xargs', 'put')

    try:
        xargs = f'xargs -P {host["parallel"]}'
    except:
        xargs = f'xargs -P 2'

    command = 'cat segtest/full_nmap.xargs | '+xargs+' -I {} sh -c "{}"'
    tmux_command = f"tmux new-session -d -s 'nmap-scans' '{command}'"
    execute = run_ssh_command(host_name, tmux_command)

    print(f"\nScan started in tmux session 'nmap_scans' on {host_name}!")
    print(f"Results will be saved to ~/segtest directory on the remote host.")
    print(f"\nTo attach to the tmux session: \nssh {host_name} && tmux attach -t nmap-scans")


def checker(host):
    """Check the progress of running scans by tailing the last XML output."""
    for targets in host['scans']:
        command = f'tail -n 1 segtest/{targets["scan_name"]}*.xml'
        results = run_ssh_command(host['name'], command)
        print(results[0])


def copy_files(file1, file2):
    """Copy a file to/from a remote host using the SSH config for the jumpbox."""
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

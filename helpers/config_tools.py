import sys
import yaml
import ipaddress


def load_config(yaml_file):
    """Load and validate a YAML config file containing hosts and their scan targets."""
    try:
        with open(yaml_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        sys.exit(f"Error: Config file {yaml_file} not found")
    except yaml.YAMLError as e:
        sys.exit(f"Error in YAML file: {e}")

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


def check_network_in_live_ips(live_ips, network_cidr):
    """Check if any live IP (from arp-scan) falls inside the given network CIDR."""
    network = ipaddress.ip_network(network_cidr, strict=False)

    for host_name, interfaces in live_ips.items():
        for eth, ip_data in interfaces.items():
            ip = ip_data[0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj in network:
                    return True, host_name, eth, ip
            except ValueError:
                continue

    return False, None, None, None

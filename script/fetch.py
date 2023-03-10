from sys import argv
from pathlib import Path
from scp import SCPClient
from paramiko import SSHClient, AutoAddPolicy
from common import *

def print_usage():
    projects = [(project.name, project.value) for project in Project]

    print('Choose the projects to fetch using the number:')
    for name, value in projects:
        print(f'    {value}: {name}')
    print()

    print(f'For example, fetch "{projects[0][0]}" and "{projects[1][0]}" by using following command: ')
    print(f'    python3 script/fetch.py {projects[0][1]} {projects[1][1]}')
    print()

    print('[Note] you should run in the project root.')
    print()

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
    execution_params = argv[1:] if len(argv) >= 1 else ['help']
    try:
        project_IDs = [int(project_ID_str)
                       for project_ID_str in execution_params]
    except:
        print_usage()
        exit()

    for project_ID in project_IDs:
        print(f'Fetching {Project(project_ID).name}')
        fetch_project(Project(project_ID))

    print('Finished!')
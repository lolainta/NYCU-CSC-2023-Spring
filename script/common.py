from enum import Enum
from os import path


class Project(Enum):
    Project1 = 1
    Project2 = 2


CONNECTION_CONFIG = {
    Project.Project1.value: {
        'client': {
            'host': '10.6.0.21',
            'port': 22,
            'user': 'csc2023',
            'password': 'csc2023',
            'source_dir': path.join('~', 'csc-project1'),
            'target_parent_dir': path.join('.', 'project1', 'client')
        },
        'server': {
            'host': '10.6.0.31',
            'port': 22,
            'user': 'csc2023',
            'password': 'csc2023',
            'source_dir': path.join('~', 'csc-project1'),
            'target_parent_dir': path.join('.', 'project1', 'server')
        }
    }
}

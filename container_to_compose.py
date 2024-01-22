# Container to Compose: A Python script by Edino De Souza with help from ChatGPT.
# Copyright © 2024 Edino De Souza
# Author: Edino De Souza
# Repository: https://github.com/edino/container_to_compose
# License: GNU General Public License v3.0 - https://github.com/edino/container_to_compose/blob/main/LICENSE
# This file is part of Container to Compose.

# Script Summary Section
# Summary: This script automates the generation of Docker Compose files for active containers in a Docker environment.
# It meticulously extracts crucial details such as container configurations and volume information for each running container.
# The script ensures clarity and convenience by creating distinct Docker Compose files tailored to the unique characteristics of each container.
# By seamlessly integrating with Docker, the script streamlines the process of capturing container intricacies and encapsulates them in organized and deployable Docker Compose configurations.
# The generated files empower users to replicate and manage containerized environments effortlessly.

# Requirements Section
# Requirements:
#   - Python 3
# Ensure Python 3 is installed before running the script.
# sudo apt install python3 -y

#   - Docker Python library
# Install the Docker Python library using: pip3 install docker
# sudo pip3 install docker

#   - PyYAML library
# Install the PyYAML library using: pip3 install pyyaml
# sudo pip3 install pyyaml

# BuildDate: 1:37 PM EST 2024-01-21 - Working.

# Execution Section
# Execution Instructions:
# 1. Download the script using:
#    curl -sLo /tmp/container_to_compose.py https://raw.githubusercontent.com/edino/container_to_compose/main/container_to_compose.py
# 2. Run the script using:
#    sudo python3 /tmp/container_to_compose.py
# or
#    curl -s https://raw.githubusercontent.com/edino/container_to_compose/main/container_to_compose.py | python3 -

import docker
import os
import logging
from datetime import datetime, timezone
import yaml
import ipaddress

def ensure_valid_writable_path(prompt="Enter an absolute folder path (e.g., /path/to/folder, press Enter to use the current folder): "):
    """
    Ensure the provided path is valid and writable, creating it if necessary.
    """
    while True:
        user_input_path = input(prompt)
        if not user_input_path:
            user_input_path = os.getcwd()

        if not os.path.isabs(user_input_path):
            print("Error: Please provide an absolute path.")
            continue

        user_path = os.path.expanduser(user_input_path)

        if os.path.exists(user_path):
            if os.access(user_path, os.W_OK):
                print("Path already exists, and user has write access.")
                return user_path
            else:
                print("Error: User does not have write access to the existing path.")
                return None

        try:
            os.makedirs(user_path)
            print("Path created successfully.")
            return user_path
        except OSError as e:
            print(f"Error creating the path: {str(e)}")
            return None

def generate_docker_compose(container_info, user_network_info, container_execution_path, is_original=True):
    """
    Generate Docker Compose file for a single container.
    """
    sanitized_container_name = container_info.get('Name', '').lstrip('/').replace("-", "_").replace(".", "_")
    service_name = f"service_{sanitized_container_name}"
    container_config = container_info.get('Config', {})
    volumes = container_info.get('Mounts', [])
    healthcheck_info = container_config.get('Healthcheck', "")

    user_network = ipaddress.IPv4Network(user_network_info['network_address'], strict=False)
    container_ip = str(user_network.network_address + 1)

    docker_compose_template = {
        'version': '3.8',
        'services': {
            service_name: {
                'image': container_config.get('Image', ''),
                'container_name': service_name,
                'hostname': container_config.get('Hostname', ''),
                'domainname': container_config.get('Domainname', ''),
                'user': container_config.get('User', ''),
                'tty': container_config.get('Tty', ''),
                'attach_stdin': container_config.get('AttachStdin', ''),
                'attach_stdout': container_config.get('AttachStdout', ''),
                'attach_stderr': container_config.get('AttachStderr', ''),
                'expose': [port.split("/")[0] for port in container_config.get('ExposedPorts', [])],
                'stdin_once': container_config.get('StdinOnce', ''),
                'environment': container_config.get('Env', []),
                'healthcheck': {
                    'test': healthcheck_info.get('Test', []),
                    'interval': healthcheck_info.get('Interval', 0),
                    'timeout': healthcheck_info.get('Timeout', 0),
                    'retries': healthcheck_info.get('Retries', 0)
                },
                'volumes': [f"{mount.get('Source', '')}:{mount.get('Destination', '')}:{mount.get('Mode', '')}" for mount in volumes],
                'ports': [f'{port.split("/")[0]}:{port.split("/")[1]}' for port in container_config.get('ExposedPorts', [])],
                'networks': {
                    'my_network': {
                        'ipv4_address': container_ip  # Use the generated container IP address
                    }
                },
                'depends_on': container_config.get('HostConfig', {}).get('Links', []),
                'command': container_config.get('Cmd', ''),
                'logging': {
                    'driver': container_config.get('LogConfig', {}).get('Type', ''),
                    'options': container_config.get('LogConfig', {}).get('Config', {})
                },
                'labels': container_config.get('Config', {}).get('Labels', {}),
                'deploy': {
                    'replicas': container_config.get('Replica', ''),
                    'update_config': {
                        'parallelism': container_config.get('UpdateConfig', {}).get('Parallelism', ''),
                        'delay': container_config.get('UpdateConfig', {}).get('Delay', '')
                    },
                    'restart_policy': {
                        'condition': container_config.get('HostConfig', {}).get('RestartPolicy', {}).get('Name', '')
                    }
                }
            }
        },
        'networks': {
            'my_network': {
                'driver': 'bridge',
                'ipam': {
                    'config': [
                        {
                            'subnet': user_network_info['network_address'],
                            'ip_range': user_network_info['ip_address_cidr'],
                            'gateway': user_network_info['network_address'].split('/')[0],
                            'aux_addresses': {'my_gateway': user_network_info['network_address'].split('/')[0]}
                        }
                    ]
                },
                'name': user_network_info['network_name']
            }
        },
        'volumes': {}
    }

    # Add volume information to the docker compose file
    for volume in volumes:
        volume_name = volume.get('Source', '').replace("-", "_").replace(".", "_")
        docker_compose_template['volumes'][volume_name] = {}

    # Set the container execution path for all services
    docker_compose_template['services'][service_name]['container_execution_path'] = os.path.join(container_execution_path, sanitized_container_name)

    # Save the generated Docker Compose file
    file_type = "original" if is_original else "adapted"
    filename = f"{sanitized_container_name}_{file_type}_docker_compose.yml"
    with open(os.path.join(directory_path, filename), 'w') as file:
        yaml.dump(docker_compose_template, file)

    logging.info(f"Docker Compose file '{filename}' generated successfully.")

def generate_stack_docker_compose(containers_info, user_network_info, container_execution_path):
    stack_docker_compose_template = {
        'version': '3.8',
        'services': {},
        'networks': {
            'my_network': {
                'driver': 'bridge',
                'ipam': {
                    'config': [
                        {
                            'subnet': user_network_info['network_address'],
                            'ip_range': user_network_info['ip_address_cidr'],
                            'gateway': user_network_info['network_address'].split('/')[0],
                            'aux_addresses': {'my_gateway': user_network_info['network_address'].split('/')[0]}
                        }
                    ]
                },
                'name': user_network_info['network_name']
            }
        },
        'volumes': {}
    }

    for container_info in containers_info:
        sanitized_container_name = container_info.get('Name', '').lstrip('/').replace("-", "_").replace(".", "_")
        file_type = "adapted"
        service_name = f"service_{sanitized_container_name}"

        # Add service information to the stack docker compose file
        stack_docker_compose_template['services'][service_name] = {
            'image': container_info.get('Config', {}).get('Image', ''),
            'container_name': service_name,
            'hostname': container_info.get('Config', {}).get('Hostname', ''),
            'domainname': container_info.get('Config', {}).get('Domainname', ''),
            'user': container_info.get('Config', {}).get('User', ''),
            'tty': container_info.get('Config', {}).get('Tty', ''),
            'attach_stdin': container_info.get('Config', {}).get('AttachStdin', ''),
            'attach_stdout': container_info.get('Config', {}).get('AttachStdout', ''),
            'attach_stderr': container_info.get('Config', {}).get('AttachStderr', ''),
            'expose': [port.split("/")[0] for port in container_info.get('Config', {}).get('ExposedPorts', [])],
            'stdin_once': container_info.get('Config', {}).get('StdinOnce', ''),
            'environment': container_info.get('Config', {}).get('Env', []),
            'healthcheck': {
                'test': container_info.get('Config', {}).get('Healthcheck', {}).get('Test', []),
                'interval': container_info.get('Config', {}).get('Healthcheck', {}).get('Interval', 0),
                'timeout': container_info.get('Config', {}).get('Healthcheck', {}).get('Timeout', 0),
                'retries': container_info.get('Config', {}).get('Healthcheck', {}).get('Retries', 0)
            },
            'volumes': [f"{mount.get('Source', '')}:{mount.get('Destination', '')}:{mount.get('Mode', '')}" for mount in container_info.get('Mounts', [])]
        }

        # Add volume information to the stack docker compose file
        volumes = container_info.get('Mounts', [])
        for volume in volumes:
            volume_name = volume.get('Source', '').replace("-", "_").replace(".", "_")
            stack_docker_compose_template['volumes'][volume_name] = {}

        # Set the container execution path for all services in the stack
        stack_docker_compose_template['services'][service_name]['container_execution_path'] = os.path.join(container_execution_path, sanitized_container_name)

    # Save the generated Stack Docker Compose file
    stack_filename = f"my_docker_stack_{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S_%Z')}.yml"
    with open(os.path.join(directory_path, stack_filename), 'w') as file:
        yaml.dump(stack_docker_compose_template, file)

    logging.info(f"Stack Docker Compose file '{stack_filename}' generated successfully.")

def main():
    global directory_path

    # Set up logging
    log_file_path = os.path.join(os.getcwd(), 'docker_compose_generator.log')
    logging.basicConfig(filename=log_file_path, level=logging.DEBUG, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S %Z')
    
    # Adding console handler for VERBOSE level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)  # Set to INFO for VERBOSE
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    logging.getLogger().addHandler(console_handler)

    logging.info("Script execution started.")

    try:
        # Log current system timestamp and timezone
        current_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
        logging.info(f"Current system timestamp: {current_timestamp}")

        # Ask the user for the Docker Compose Files Saved Path
        directory_path = ensure_valid_writable_path("Enter the Docker Compose Files Saved Path (press Enter to use the current folder): ")

        # Ask the user for the Docker Composed Files Saved Path
        container_execution_path = ensure_valid_writable_path("Enter the Container Execution Path for non-original Docker Compose files (e.g., /mnt/rpi4mediaplayer/Docker/Apps, press Enter to skip): ")

        # Ask the user for network information
        user_network_info = {
            'network_address': input("Enter the Network Address in CIDR format (e.g., 192.168.0.0/24, press Enter to skip): "),
            'ip_address_cidr': input("Enter the IP Address in CIDR format (e.g., 192.168.0.1/24, press Enter to skip): "),
            'network_name': input("Enter the Network Name (press Enter to skip): "),
            'dns_server': input("Enter the DNS Server in CIDR format (e.g., 192.168.0.1/24, press Enter to skip): ")
        }

        # Validate and assign default values if necessary
        user_network_info['network_address'] = user_network_info.get('network_address', '192.168.0.0/24')
        user_network_info['ip_address_cidr'] = user_network_info.get('ip_address_cidr', '192.168.0.1/24')
        user_network_info['network_name'] = user_network_info.get('network_name', 'my_network')
        user_network_info['dns_server'] = user_network_info.get('dns_server', '192.168.0.1/24')

        # Validate the CIDR formats
        try:
            ipaddress.IPv4Network(user_network_info['network_address'], strict=False)
            ipaddress.IPv4Network(user_network_info['ip_address_cidr'], strict=False)
        except ValueError:
            print("Error: Invalid CIDR format. Please provide a valid CIDR format.")
            return

        # Get Docker client
        client = docker.from_env()

        # Get the list of active containers
        containers_info = [container.attrs for container in client.containers.list()]

        # Check if there are active containers
        if not containers_info:
            print("No active containers found. Exiting.")
            return

        # Generate Docker Compose files for each container
        for i, container_info in enumerate(containers_info):
            is_original = i == 0  # Only the first container is considered as the original
            generate_docker_compose(container_info, user_network_info, container_execution_path, is_original)

        # Generate Stack Docker Compose file
        generate_stack_docker_compose(containers_info, user_network_info, container_execution_path)

        logging.info("Script execution completed successfully.")

    except KeyboardInterrupt:
        logging.info("Script terminated by the user.")
        print("\nScript terminated by the user.")

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        print(f"An error occurred: {str(e)}")

    finally:
        # Display logs since the last execution started message
        with open(log_file_path, 'r') as log_file:
            logs = log_file.read().split("Script execution started\n")[1:]
            if logs:
                print("\n".join(logs))

        print(f"\nLogs are saved in: {log_file_path}")

if __name__ == "__main__":
    main()

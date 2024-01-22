# Copyright Header Starts Here.
#
#
# Container to Compose: A Python script for generating Docker Compose files for active containers.
# Copyright © 2024 Edino De Souza
# Author: Edino De Souza
# Repository: https://github.com/edino/container_to_compose
# License: GNU General Public License v3.0 - https://github.com/edino/container_to_compose/blob/main/LICENSE
# This file is part of Container to Compose.
#
#
# Script Summary Section
# Summary: This script automates the generation of Docker Compose files for active containers in a Docker environment.
# It extracts container configurations and volume information, creating distinct Docker Compose files for each running container.
# The script integrates with Docker, streamlining the process of capturing container intricacies in organized and deployable Docker Compose configurations.
# The generated files empower users to replicate and manage containerized environments effortlessly.
#
#
# Requirements Section
# Requirements:
#   - Python 3
# Ensure Python 3 is installed before running the script.
# On Debian-based systems: sudo apt install python3 -y
#
#
#   - Docker Python library
# Install the Docker Python library using: pip3 install docker
# On Debian-based systems: sudo pip3 install docker
#
#
#   - PyYAML library
# Install the PyYAML library using: pip3 install pyyaml
# On Debian-based systems: sudo pip3 install pyyaml
#
#
# Build Date: 09:27 AM EST 2024-01-22 - Working.
#
#
# Execution Section
# Execution Instructions:
# 1. Download the script using:
#    curl -sLo /tmp/container_to_compose.py https://raw.githubusercontent.com/edino/container_to_compose/main/container_to_compose.py
# 2. Run the script using:
#    sudo python3 /tmp/container_to_compose.py
# or
#    curl -s https://raw.githubusercontent.com/edino/container_to_compose/main/container_to_compose.py | python3 -
#
# Tested on: Ubuntu 20.04 LTS with Python 3.8.5 and Docker version 20.10.5
#
# Copyright Header Ends Here.
#
#
#
#
# Source Code Starts Here
#
#
import docker
import os
import logging
from datetime import datetime, timezone
import yaml
import signal  # Added signal module

def configure_logging(log_file_path):
    logging.basicConfig(
        filename=log_file_path,
        level=logging.DEBUG,  # Changed to DEBUG level for verbose mode
        format="%(asctime)s [%(levelname)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S %Z"  # Include timezone in the timestamp
    )

def check_yaml_syntax(yaml_content):
    try:
        yaml.safe_load(yaml_content)
        return {"status": "success", "errors": []}
    except yaml.YAMLError as e:
        return {"status": "error", "errors": [str(e)]}

def format_container_config(container_config):
    return "\n".join(f"      {key}: {value}" for key, value in container_config.items())

def format_mounts(mounts):
    return "\n".join(f"      - {mount['Source']}:{mount['Destination']}:{mount['Mode']}" for mount in mounts)

def validate_and_log_yaml(file_path, log_file_path):
    try:
        with open(file_path, "r") as file:
            yaml_content = file.read()
    except FileNotFoundError:
        logging.error(f"Error: File not found - {file_path}")
        return

    result = check_yaml_syntax(yaml_content)

    logging.info(f"YAML Syntax check result for {file_path}:")
    logging.info(f"Status: {result['status']}")

    if result['status'] == 'error':
        logging.info("Errors:")
        for error in result['errors']:
            logging.info(f"  - {error}")
        raise ValueError(f"YAML Syntax check failed for {file_path}")

def get_network_info(networks):
    network_info = networks.get('my_network', {})
    container_ip = network_info.get('IPAddress', '')
    dns_server = network_info.get('IPAMConfig', {}).get('AuxiliaryAddresses', {}).get('my_gateway', '')
    return container_ip, dns_server

if __name__ == "__main__":
    current_directory = os.getcwd()
    script_path = os.path.join(current_directory, "container_to_compose.py")
    log_file_path = os.path.join(current_directory, "container_to_compose_log.log")
    compose_file_extension = "_docker-compose.yml"

    def format_ports(ports):
        return "\n      - ".join(ports)

    try:
        # Initialize logging
        configure_logging(log_file_path)
        logging.info(f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} [INFO]: Script execution started")

        # Handle KeyboardInterrupt
        interrupted = [False]  # Use a list to store a mutable object
        def signal_handler(sig, frame):
            interrupted[0] = True
            logging.info(f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} [INFO]: Script execution interrupted by user")
        
        signal.signal(signal.SIGINT, signal_handler)

        client = docker.from_env()
        containers = client.containers.list()

        for container in containers:
            # Handle user interruption
            if interrupted[0]:
                break

            container_info = container.attrs
            container_config = container_info['Config']
            host_config = container_info['HostConfig']
            deploy_config = container_config.get('Deploy', {})

            # Extracting necessary information for the Docker Compose template
            container_name = container_info['Name'].lstrip('/').replace("-", "_").replace(".", "_")
            image = container_config['Image']
            hostname = container_config.get('Hostname', '')
            domainname = container_config.get('Domainname', '')
            user = container_config.get('User', '')
            tty = container_config.get('Tty', False)
            attach_stdin = container_config.get('AttachStdin', False)
            attach_stdout = container_config.get('AttachStdout', False)
            attach_stderr = container_config.get('AttachStderr', False)
            exposed_ports = list(container_config.get('ExposedPorts', {}).keys())
            stdin_once = container_config.get('StdinOnce', False)
            env = container_config.get('Env', [])
            healthcheck = container_config.get('Healthcheck', {})
            mounts = container_info.get('Mounts', [])
            ports = [f'"{port}"' for port in container_config.get('Ports', [])]
            networks = container_config.get('NetworkSettings', {}).get('Networks', {})
            depends_on = host_config.get('Links', [])
            command = container_config.get('Cmd', [])
            log_driver = host_config.get('LogConfig', {}).get('Type', '')
            log_options = host_config.get('LogConfig', {}).get('Config', {})
            labels = container_config.get('Labels', {})
            replicas = deploy_config.get('Replicas', 1)
            update_config = deploy_config.get('UpdateConfig', {})
            restart_policy = host_config.get('RestartPolicy', {}).get('Name', '')
            container_ip, dns_server = get_network_info(networks)

            # Build Docker Compose content
            compose_content = f"""\
version: '3.8'
services:
  {container_name}:
    image: {image}
    container_name: {container_name}
    hostname: {hostname}
    domainname: {domainname}
    user: {user}
    tty: {tty}
    attach_stdin: {attach_stdin}
    attach_stdout: {attach_stdout}
    attach_stderr: {attach_stderr}
    ExposedPorts: {exposed_ports}
    stdin_once: {stdin_once}
    env: {env}
    healthcheck:
      test: {healthcheck.get('Test', [])}
      interval: {healthcheck.get('Interval', '')}
      timeout: {healthcheck.get('Timeout', '')}
      retries: {healthcheck.get('Retries', '')}
    volumes:
{format_mounts(mounts)}
    ports: 
      - {format_ports(ports)}
    environment: {env}
    networks:
      my_network:
        ipv4_address: {container_ip}
    depends_on: {depends_on}
    command: {command}
    logging:
      driver: {log_driver}
      options: {log_options}
    labels: {labels}
    deploy:
      replicas: {replicas}
      update_config:
        parallelism: {update_config.get('Parallelism', 1)}
        delay: {update_config.get('Delay', '10s')}
      restart_policy:
        condition: {restart_policy}
    container_ip: {container_ip}
    dns_server: {dns_server}
"""

            # Validate YAML syntax of the generated Docker Compose file
            compose_file_path = os.path.join(current_directory, f'{container_name}{compose_file_extension}')
            with open(compose_file_path, 'w') as compose_file:
                compose_file.write(compose_content)
                validate_and_log_yaml(compose_file_path, log_file_path)

            logging.info(f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} [INFO]: Docker Compose generated for container {container_name}")
            logging.info(f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} [INFO]: Saved to {compose_file_path}")

        if interrupted[0]:
            logging.info(f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} [INFO]: Script execution terminated by user")

        logging.info(f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} [INFO]: Script execution completed successfully")

        # Display the logged information from the last execution to the user
        with open(log_file_path, 'r') as log_file:
            log_lines = log_file.readlines()
            start_index = [i for i, line in enumerate(log_lines) if "Script execution started" in line][-1]
            print("\nLogged Information:\n" + ''.join(log_lines[start_index:]))

    except docker.errors.APIError as e:
        logging.error(f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} [ERROR]: Error during Docker API call: {str(e)}")
    except ValueError as ve:
        logging.error(str(ve))
    except Exception as e:
        logging.error(f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} [ERROR]: Unexpected error: {str(e)}")
    finally:
        # Display the log file path
        print(f"\nLog file is saved at: {log_file_path}")

#
#
# Source Code Ends Here
#
#

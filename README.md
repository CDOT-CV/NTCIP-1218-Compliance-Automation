# NTCIP 1218 Compliance Automation

## Table of Contents

- [About](#about)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Contributing](../CONTRIBUTING.md)

## About <a name = "about"></a>

Simple application to review compliance against NTCIP 1218 standard. Note this is the initial version and will be updated with more features in the future. Currently only a subset of MIBs are checked. 

The [ntcip1218_compliance_check.py](./ntcip1218_compliance_check.py) script executes a series of SNMP commands to an RSU. Command host must be a server with an SNMP service configured and running, either locally or remotely. If MIB names are used in the input commands then the appropriate MIB files must be configured on the host server.


### Prerequisites
Python 3.12 or higher is required to run this project. Virtual environment is recommended to keep the dependencies clean and isolated from other projects.  

The host server executing the SNMP commands must have an SNMP service configured and running. If MIB names are used in the SNMP commands, then the host SNMP service must be configured with the appropriate MIB files.

If the host server is remote (i.e. not the server running the script) then appropriate login information must be configured in the SNMP command file to support an SSH login to the remote host. 

## Getting Started <a name = "getting-started"></a>

A JSON file is used to store the SNMP commands to be executed, see [sample_read_snmp.json](./sample_read_snmp.json) for an example. Note that the script can be run directly on the host that executes the SNMP commands or the script can be run on a different server and connect to the remote host that executes the SNMP commands. These different run configurations are specified in the "snmp_host.host_type" element of the SNMP command file. There are three configuration values supported:
- "remote-key"   
    Connect to a remote host using a private key file for ssh login authentication. The "host_private_key" element contains the path to the private_key file. If the private_key file requires a pass phrase, then this pass phrase must be specified in the "host_pw" element.  

- "remote-pw"  
    Connect to a remote host using a password for ssh login authentication. The "host_pw" element must contain the password for ssh login to the remote host.  

- "local"  
    The host executing the SNMP commands is the server that the script is running on. SNMP commands are executed directly as shell commands from the script. For this local configuration, the other "snmp_host" elements are not required.  

The snmp_connection element holds data required to execute an SNMP command to the target RSU. The device_reference element contains the an ip address or URL to reach the target RSU, the security element contains the preliminary portion of the SNMP command string including the SNMP user name, authentication protocol and password, and encryption protocol and password.

## Usage <a name = "usage"></a>

```bash
python ntcip1218_compliance_check.py -f sample_snmp.json -o output.csv
```

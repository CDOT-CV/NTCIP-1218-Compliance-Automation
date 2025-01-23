# NTCIP 1218 Compliance Automation

## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)
- [Contributing](../CONTRIBUTING.md)

## About <a name = "about"></a>

Simple application to review compliance against NTCIP 1218 standard. Note this is the initial version and will be updated with more features in the future. Currently only a subset of MIBs are checked. 

The [ntcip1218_compliance_check.py](./ntcip1218_compliance_check.py) script executes a series of SNMP commands to an RSU. Command host must a server with an SNMP service configured and running. If MIB names are used in the input commands then the appropriate MIB files must be configured on the host server.


### Prerequisites
Python 3.12 or higher is required to run this project. Virtual environment is recommended to keep the dependencies clean and isolated from other projects.

A JSON file is used to store the SNMP commands to be executed, see [sample_snmp.json](./sample_snmp.json) for an example. Note that two sets of credentials are required to run the script, one for SSH and one for SNMP. The SSH credentials are used to connect to the host server and the SNMP credentials are used to execute the SNMP commands. SSH credentials are stored in the JSON file under the key "snmp_host" and SNMP credentials are stored under the key "snmp_connection".

## Usage <a name = "usage"></a>

```bash
python ntcip1218_compliance_check.py -f sample_snmp.json -o output.csv
```

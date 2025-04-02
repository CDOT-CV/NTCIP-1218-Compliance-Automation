import argparse
import csv
import json
import paramiko
import re
import subprocess


def local_host_execute(cmd, hostdata):
    """
    This function executes the given SNMP command on a local host 
    (the server that this script is running on). The stdout and stderr 
    strings are returned from the execution of the SNMP command.

    Parameters:
        cmd (string): the assembled SNMP command to execute
        hostdata (dict): host connection data, not used for this local host execution

    Returns:
        str: stdout text from the command execution
        str: stderr text from the command execution
    """
    # Execute SNMP command
    cmdresult = ""
    cmderror = ""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, check=True)
        cmdresult = result.stdout.decode()
        print("stdout: {}".format(cmdresult))
    except subprocess.CalledProcessError as e:
        cmderror = e.stderr.decode()
        print("SNMP command failed: {}".format(cmderror))

    return cmdresult, cmderror

def remote_host_execute(cmd, hostdata):
    """
    This function executes the given SNMP command on a remote host. 
    The remote host may authenticate a shell access using either a 
    password or private key. The remote shell access is implemented 
    using paramiko.  

    Parameters:
        cmd (string): the fully defined SNMP command to execute on the remote host
        hostdata (dict): connection and authentication data for the remote host
        
    Returns:
        str: stdout text from the command execution
        str: stderr text from the command execution
    """
    # open parimiko shell to SNMP host
    # Create ssh client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the remote host and execute the SNMP command
    try:

        # connect with password
        if hostdata["host_type"] == "remote_pw":
            client.connect(hostname=hostdata["host_reference"], 
                   username=hostdata["host_user"], 
                   password=hostdata["host_pw"])

        # connect with private key 
        # password is used as the private key passphrase 
        else:
            client.connect(hostname=hostdata["host_reference"], 
                   username=hostdata["host_user"], 
                   password=hostdata["host_pw"],
                   key_filename=hostdata["host_private_key"])
            
        # Execute the SNMP command 
        stdin, stdout, stderr = client.exec_command(cmd)
        cmdresult = stdout.read().decode()
        cmderror = stderr.read().decode()
        print("stdout: {}".format(cmdresult))
        print("stderr: {}".format(cmderror))
            
    except paramiko.AuthenticationException as e:
        errorMsg = (
            "Failed to authenticate on remote host with the following data "
            "host_type: {}  host: {}  user: {}  password: {} "
            "private key path: {}")
        errorMsg = errorMsg.format(hostdata["host_type"], hostdata["host_reference"],
                                   hostdata["host_user"], hostdata["host_pw"],
                                   hostdata["host_private_key"])
        raise ValueError(errorMsg)
                    
    finally:
        client.close()
    
    # return the raw stdout and stderr strings from the command execution
    return cmdresult, cmderror

def evaluate_result(result_string, cmddata):
    """
    This function evaluates the data returned from the SNMP command and 
    determines if the command was successful or failed. The evaluation of 
    success or failure is based on matching regular expressions (RE) defined 
    in the success_return or fail_return elements of the provided command 
    data (cmddata). The regex evaluations are made ignoring case, this 
    was done because different manufacturers may use different text formats 
    in their returned result or error text string and we wanted to easily 
    match using simple RE. 

    Parameters:
        result_string (string): concatenated standard output and standard err from command
        cmddata (dict): contains reference name, command elements and evaluation strings

    Returns:
        str: result evaluation 'pass'|'fail'|'unknown'
    """
    # Initialize the return result
    result = "unknown"

    # Check if there is an obvious failure substring in the result string
    # Each defined "check" regex is evaluated in turn
    rexlist = cmddata["command"]["fail_return"]
    for rex in rexlist:
        match = re.search(rex, result_string, flags=re.IGNORECASE) 
        if match:
            result = "fail"
            break

    # Check if there is a confirmed success substring in the result string
    # The failure check must have not found any matches before this check
    if result == "unknown":
        rexlist = cmddata["command"]["success_return"]
        for rex in rexlist:
            match = re.search(rex, result_string, flags=re.IGNORECASE)
            if match:
                result = "pass"
                break

    return result

def execute_snmp_command(host_exec_func, hostdata, snmpdata, cmddata):
    """
    This function executes the given SNMP command and evaluates the result.
    The SNMP command is executed on the host defined in the hostdata. The host 
    may be remote (remote ssh access) or local (direct shell access). The 
    result of the SNMP command is evaluated to check if the command succeeded 
    or failed. Results of the executed snmp command are returned along with
    a pass/fail flag.

    Parameters:
        hostdata (dict): access data for the host executing the snmp command
        snmpdata (dict): security string and device ip for snmp command
        cmddata (dict): reference name, command elements and evaluation strings

    Returns:
        str: reference information for the command
        str: output text from the command execution no truncation.
        str: result evaluation 'pass'|'fail'|'unknown'
    """
    # build snmp command (verb, security, device_reference)
    snmp_verb = cmddata["command"]["snmp_cmd"]
    snmp_security = snmpdata["snmp_security"]
    snmp_device = snmpdata["snmp_device"]
    cmd = f"{snmp_verb} {snmp_security} {snmp_device}"

    # add multiple command elements to the command
    for cmd_element in cmddata["command"]["snmp_cmd_elements"]:
        cmd =  cmd + " " + cmd_element

    # use the given host execute function to execute the command on the specified host server
    cmdresult, cmderror = host_exec_func(cmd, hostdata)

    # Evaluate the result from the command execution
    # The stdout and stderr strings often contain newlines, which complicates
    #  analysis, so these strings are flattened and concatenated
    cmdresult = cmdresult.replace("\n", " ") + cmderror.replace("\n", " ")
    result_evaluation = evaluate_result(cmdresult, cmddata)

    return result_evaluation, cmdresult

def run_test_commands(cmdfilepath, outfilepath, truncatelength):
    """
    This function organizes a series of test snmp commands then 
    executes each test command and records the result of each 
    command to the specified output file. 

    Parameters:
        cmdfilepath (file path): input file containing all the snmp commands to test
        outfilepath (file path): file to record results of the test
        truncatelength (integer): max written length of the command output string
    """
    # Read the SNMP command file - create corresponding cmddata dictionary
    with open(cmdfilepath, 'r') as cmdfile:
        cmddata = json.load(cmdfile)

    # assemble host shell login elements {host_type, host_reference, user, pw}
    # determine the type of host access and specify the host command execute function
    
    # collect the host data {host_type, host_reference, host_user, host_pw, host_private_key}
    # this host data defines the connection to the host that executes the snmp command
    host_data = cmddata['snmp_host']

    # determine the host function to execute the SNMP command
    # "remote_key"  remote host using a private key for ssh login authentication
    # "remote_pw"   remote host using a password for ssh login authentication
    # "local"       local host using direct shell commands (no shell login required)
    # this statement also confirms that the host_type is specified correctly
    match host_data['host_type']:
        case "remote_pw" | "remote_key":
            exec_function = remote_host_execute
            #cmdresult, cmderror = remote_host_execute(hostdata,cmd)

        case "local":
            exec_function = local_host_execute
            #cmdresult, cmderror = local_host_execute(cmd)

        case _:
            raise ValueError("Unknown host type. Host type must be one of: 'remote_pw', 'remote_key', 'local'")


    # assemble default snmp command string elements (snmp security, snmp device)
    snmp_elements = {"snmp_security": cmddata['snmp_connection']['security'],
                "snmp_device": cmddata['snmp_connection']['device_reference']}

    # result list to write upon conclusion 
    result_list = []

    # iterate over each test command and collect results
    for cmd in cmddata['test_commands']:

        # indicate command reference being executed
        cmd_reference = cmd["command"]["reference"]
        cmd_type = cmd["command"]["snmp_cmd"]
        print("testing cmd: {}".format(cmd_reference))

        # execute test command based on host
        cmdresult, resultdata = execute_snmp_command(exec_function, host_data, snmp_elements, cmd)

        # truncate the result string to user specified length
        # truncated for output only, evaluation occurred with the full output string 
        resultdata = resultdata[:truncatelength]

        # write command pass fail result
        result = [cmd_reference, cmd_type, cmdresult, resultdata]
        result_list.append(result)

    # open output file and write results
    header = ["cmd_reference","cmd_type", "cmd_result", "result_data"]
    result_list.insert(0, header)

    with open(outfilepath, 'w', newline='') as fout:
        write = csv.writer(fout)
        write.writerows(result_list) 

    print("Done")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Script to execute a series of SNMP commands to an RSU. Command host must a server with an SNMP service configured and running. If MIB names are used in the input commands then the appropriate MIB files must be configured on the host server.")
    parser.add_argument('-f', '--cmdfile', required=True, help='The JSON formatted file with the series of SNMP commands to test')
    parser.add_argument('-o', '--outfile', required=True, help='Output CSV file to write results to (e.g. test2_100.csv)')
    parser.add_argument('-t', '--truncate_len', required=False, type=int, default=80, help='Maximum length of command return string to write to output file. Default=80. (OPTIONAL)' )
    args = parser.parse_args()

    run_test_commands(args.cmdfile, args.outfile, args.truncate_len)


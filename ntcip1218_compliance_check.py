import argparse
import csv
import json
import paramiko
import re

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
        result_sting (string): concatenated standard output and standard err from command
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

def execute_snmp_command(hostdata, snmpdata, cmddata):
    """
    This function executes the given SNMP command and evaluates the result.
    The SNMP command is executed on a remote host using a paramiko shell 
    command execution. The result of the SNMP command is evaluated to check
    if the command succeeded or failed. Results including a pass/fail flag
    are returned from this routine. 

    Parameters:
        hostdata (dict): contains login data for remote host 
        snmpdata (dict): contains security string and device ip for snmp command
        cmddata (dict): contains reference name, command elements and evaluation strings

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

    # open parimiko shell to SNMP host
    # Create ssh client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the remote host
    client.connect(hostdata["host"], 
                   username=hostdata["user"], 
                   password=hostdata["pw"])

    # Execute command
    stdin, stdout, stderr = client.exec_command(cmd)
    cmdresult = stdout.read().decode()
    cmderror = stderr.read().decode()
    print("stdout: {}".format(cmdresult))
    print("stderr: {}".format(cmderror))

    # Close connection
    client.close()

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

    # assemble host shell login elements {host, user, pw}
    host_login = {"host": cmddata['snmp_host']['host_reference'], 
                  "user": cmddata['snmp_host']['host_user'],
                  "pw": cmddata['snmp_host']['host_pw'] }
    
    print(host_login)

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

        # execute test command
        cmdresult, resultdata = execute_snmp_command(host_login, snmp_elements, cmd)

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


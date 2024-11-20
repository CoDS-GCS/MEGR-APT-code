def get_postgres_cred(dataset):
    username = ""
    password = ""
    dataset = dataset
    db_url = 'postgresql+psycopg2://' + username + ':' + password + '@localhost/' + dataset
    return db_url


def get_stardog_cred(dataset):
    stardog_cloud = ""
    stardog_email = ""
    stardog_password = ""
    connection_details = {
        'endpoint': stardog_cloud,
        'username': stardog_email,
        'password': stardog_password
    }
    database_name = dataset
    return database_name, connection_details



def get_dataset_nodes_and_edges(dataset):
    if dataset == "darpa_optc":
        node_types = ['PROCESS', 'SHELL', 'FILE', 'FLOW']
        edge_types = ['RENAME', 'READ', 'DELETE', 'CREATE', 'OPEN', 'MESSAGE', 'COMMAND', 'WRITE', 'TERMINATE',
                      'MODIFY']
    elif dataset == "darpa_cadets":
        node_types = ['PROCESS', 'FILE', 'FLOW', 'PIPE']
        edge_types = ['ACCEPT', 'ADD_OBJECT_ATTRIBUTE', 'BIND', 'CHANGE_PRINCIPAL', 'CLOSE', 'CONNECT', 'CREATE_OBJECT',
                      'EXECUTE', 'EXIT', 'FCNTL', 'FLOWS_TO', 'FORK', 'LINK', 'LOGIN', 'LSEEK', 'MMAP',
                      'MODIFY_FILE_ATTRIBUTES', 'MODIFY_PROCESS', 'MPROTECT', 'OPEN', 'OTHER', 'READ', 'RECVFROM',
                      'RECVMSG', 'RENAME', 'SENDMSG', 'SENDTO', 'SIGNAL', 'TRUNCATE', 'UNLINK', 'WRITE']
    elif dataset == "darpa_theia":
        node_types = ['FILE', 'MEMORY', 'PROCESS', 'FLOW']
        edge_types = ['SENDTO', 'CLONE', 'EXECUTE', 'SHM', 'RECVMSG', 'RECVFROM', 'READ_SOCKET_PARAMS', 'READ',
                      'CONNECT',
                      'SENDMSG', 'WRITE', 'MMAP', 'OPEN', 'WRITE_SOCKET_PARAMS', 'MODIFY_FILE_ATTRIBUTES', 'MPROTECT',
                      'UNLINK']
    elif dataset == "darpa_trace":
        node_types = ['PROCESS', 'FILE', 'FLOW', 'MEMORY']
        edge_types = ['EXECUTE', 'RECVMSG', 'SENDMSG', 'UNIT', 'RENAME', 'OPEN', 'CREATE_OBJECT', 'CONNECT', 'CLOSE',
                      'MPROTECT', 'LINK', 'CLONE', 'LOADLIBRARY', 'FORK', 'UPDATE', 'EXIT', 'WRITE',
                      'MODIFY_FILE_ATTRIBUTES', 'TRUNCATE', 'MMAP', 'UNLINK', 'OTHER', 'CHANGE_PRINCIPAL', 'READ']
    else:
        print("Undefined dataset")
    return node_types, edge_types


def get_ground_cases(dataset, similar_attack=False):
    if dataset == "DARPA_OPTC":
        if not similar_attack:
            ground_cases = ["Malicious_Upgrade_in_attack_SysClient0051.pt",
                        "Custom_PowerShell_Empire_in_attack_SysClient0358.pt",
                        "Custom_PowerShell_Empire_in_attack_SysClient0501.pt",
                        "Plain_PowerShell_Empire_in_attack_SysClient0201.pt",
                        "Custom_PowerShell_Empire_in_benign_SysClient0358.pt",
                        "Malicious_Upgrade_in_benign_SysClient0358.pt",
                        "Plain_PowerShell_Empire_in_benign_SysClient0358.pt",
                        "Custom_PowerShell_Empire_in_benign_SysClient0051.pt",
                        "Malicious_Upgrade_in_benign_SysClient0201.pt",
                        "Malicious_Upgrade_in_benign_SysClient0051.pt",
                        "Plain_PowerShell_Empire_in_benign_SysClient0501.pt",
                        "Plain_PowerShell_Empire_in_benign_SysClient0051.pt",
                        "Plain_PowerShell_Empire_in_benign_SysClient0201.pt",
                        "Malicious_Upgrade_in_benign_SysClient0501.pt",
                        "Custom_PowerShell_Empire_in_benign_SysClient0501.pt",
                        "Custom_PowerShell_Empire_in_benign_SysClient0201.pt"]
            y_true = [1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0]
        else:
            ground_cases = []
            y_true = []
            for qg in ["Plain_PowerShell_Empire","Custom_PowerShell_Empire","Malicious_Upgrade"]:
                for pg in ["attack_SysClient0201","attack_SysClient0501","attack_SysClient0051","benign_SysClient0201","benign_SysClient0501","benign_SysClient0051","benign_SysClient0358"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)
                    if "attack" in pg:
                        y_true.append(1)
                    else:
                        y_true.append(0)

    elif dataset == "DARPA_CADETS":
        if not similar_attack:
            ground_cases = ["BSD_1_in_attack_BSD_1.pt", "BSD_2_in_attack_BSD_2.pt","BSD_3_in_attack_BSD_3_4.pt","BSD_4_in_attack_BSD_3_4.pt",
                            "BSD_1_in_benign_BSD.pt","BSD_2_in_benign_BSD.pt","BSD_3_in_benign_BSD.pt","BSD_4_in_benign_BSD.pt"]
            y_true = [1,1,1,1,0,0,0,0]
        else:
            ground_cases = []
            y_true = []
            for qg in ["BSD_1","BSD_2","BSD_3","BSD_4"]:
                for pg in ["attack_BSD_1","attack_BSD_2","attack_BSD_3_4","benign_BSD"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)
                    if "attack" in pg:
                        y_true.append(1)
                    else:
                        y_true.append(0)

    elif dataset == "DARPA_THEIA":
        if not similar_attack:
            ground_cases = ["Linux_1_in_attack_linux_1_2.pt", "Linux_2_in_attack_linux_1_2.pt",
                        "Linux_1_in_benign_theia.pt", "Linux_2_in_benign_theia.pt"]
            y_true = [1,1,0,0]
        else:
            ground_cases = []
            y_true = []
            for qg in ["Linux_1","Linux_2"]:
                for pg in ["attack_linux_1_2","benign_theia"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)
                    if "attack" in pg:
                        y_true.append(1)
                    else:
                        y_true.append(0)
    elif dataset == "DARPA_TRACE":
        if not similar_attack:
            ground_cases = ["Linux_3_in_attack_linux_3.pt","Linux_4_in_attack_linux_4.pt" ,
                            "Linux_3_in_benign_trace.pt", "Linux_4_in_benign_trace.pt"]
            y_true = [1, 1, 0, 0]
        else:
            ground_cases = []
            y_true =[]
            for qg in ["Linux_3","Linux_4"]:
                for pg in ["attack_linux_3","attack_linux_4","benign_trace"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)
                    if "attack" in pg:
                        y_true.append(1)
                    else:
                        y_true.append(0)
    else:
        print("Undefined dataset")
    return ground_cases,y_true

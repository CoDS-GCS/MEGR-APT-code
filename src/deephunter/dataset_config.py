import json

def get_stardog_cred(dataset):
    connection_details = {
        'endpoint': '',
        'username': '',
        'password': ''
    }
    database_name = dataset
    return database_name, connection_details

def get_subgraphs_label(dataset,query_graph=False):
    attributes = {}
    if dataset == "darpa_cadets":
        if query_graph:
            attributes['process'] = 'image_path'
            attributes['file'] = 'file_path'
            attributes['flow'] = 'remote_ip'
            attributes['pipe'] = 'NA'
        else:
            attributes['process'] = 'NA'
            attributes['pipe'] = 'NA'
            attributes['file'] = 'object_paths'
            attributes['flow'] = 'remote_ip'
    elif dataset == "darpa_theia":
        if query_graph:
            attributes['process'] = 'image_path'
            attributes['file'] = 'file_path'
            attributes['flow'] = 'remote_ip'
            attributes['memory'] = "image_path"
        else:
            attributes['process'] = 'command_lines'
            attributes['file'] = 'NA'
            attributes['flow'] = 'remote_ip'
            attributes['memory'] = "NA"
    elif dataset == "darpa_trace":
        if query_graph:
            attributes['process'] = 'image_path'
            attributes['file'] = 'file_path'
            attributes['flow'] = 'remote_ip'
            attributes['memory'] = "image_path"
        else:
            attributes['process'] = 'command_lines'
            attributes['memory'] = "NA"
            attributes['file'] = 'object_paths'
            attributes['flow'] = 'remote_ip'
    elif dataset == "darpa_optc":
        if query_graph:
            attributes['process'] = 'image_path'
            attributes['file'] = 'file_path'
            attributes['flow'] = 'src_ip'
        else:
            attributes['process'] = 'image_paths'
            attributes['file'] = 'file_paths'
            attributes['flow'] = 'src_ip'
    else:
        print("Undefined dataset")
    return attributes

def get_ground_cases(dataset, similar_attack=False):
    if dataset == "darpa_optc":
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
        else:
            ground_cases = []
            for qg in ["Plain_PowerShell_Empire","Custom_PowerShell_Empire","Malicious_Upgrade"]:
                for pg in ["attack_SysClient0201","attack_SysClient0501","attack_SysClient0051","attack_SysClient0358","benign_SysClient0201","benign_SysClient0501","benign_SysClient0051","benign_SysClient0358"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)

    elif dataset == "darpa_cadets":
        if not similar_attack:
            ground_cases = ["BSD_4_in_benign_BSD.pt", "BSD_3_in_benign_BSD.pt", "BSD_4_in_attack_BSD_3_4.pt",
                            "BSD_3_in_attack_BSD_3_4.pt", "BSD_2_in_attack_BSD_2.pt", "BSD_1_in_attack_BSD_1.pt",
                            "BSD_1_in_benign_BSD.pt", "BSD_2_in_benign_BSD.pt"]
        else:
            ground_cases = []
            for qg in ["BSD_1","BSD_2","BSD_3","BSD_4"]:
                for pg in ["attack_BSD_1","attack_BSD_2","attack_BSD_3_4","benign_BSD"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)

    elif dataset == "darpa_theia":
        if not similar_attack:
            ground_cases = ["Linux_1_in_attack_linux_1_2.pt", "Linux_2_in_attack_linux_1_2.pt",
                        "Linux_1_in_benign_theia.pt", "Linux_2_in_benign_theia.pt"]
        else:
            ground_cases = []
            for qg in ["Linux_1","Linux_2"]:
                for pg in ["attack_linux_1_2","benign_theia"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)
    elif dataset == "darpa_trace":
        if not similar_attack:
            ground_cases = ["Linux_3_in_benign_trace.pt", "Linux_4_in_benign_trace.pt",
                        "Linux_4_in_attack_linux_4.pt", "Linux_3_in_attack_linux_3.pt"]
        else:
            ground_cases = []
            for qg in ["Linux_3","Linux_4"]:
                for pg in ["attack_linux_3","attack_linux_4","benign_trace"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)
    else:
        print("Undefined dataset")
    return ground_cases

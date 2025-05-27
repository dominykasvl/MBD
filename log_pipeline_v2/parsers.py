import re
import pandas as pd
import os 
import config 
import utils  

def parse_asa_message(message_content):
    """Helper to parse ASA message details."""
    details = {"action": None, "protocol": None, "src_ip": None, "src_port": None, 
               "dst_ip": None, "dst_port": None, "asa_interface": None, 
               "src_interface_host": None, "dst_interface_host": None}
    
    conn_match = re.search(config.ASA_CONNECTION_REGEX, message_content)
    if conn_match:
        details["action"] = conn_match.group(1) 
        details["protocol"] = conn_match.group(3).upper()
        details["src_interface_host"] = conn_match.group(4)
        details["src_ip"] = conn_match.group(5)
        details["src_port"] = conn_match.group(6)
        details["dst_interface_host"] = conn_match.group(7)
        details["dst_ip"] = conn_match.group(8)
        details["dst_port"] = conn_match.group(9)
        return details

    deny_permit_match = re.search(config.ASA_DENY_PERMIT_REGEX, message_content)
    if deny_permit_match:
        details["action"] = deny_permit_match.group(1)
        details["protocol"] = deny_permit_match.group(2).upper()
        details["src_interface_host"] = deny_permit_match.group(3) 
        details["src_ip"] = deny_permit_match.group(4)
        details["src_port"] = deny_permit_match.group(5)
        details["dst_interface_host"] = deny_permit_match.group(6) 
        details["dst_ip"] = deny_permit_match.group(7)
        details["dst_port"] = deny_permit_match.group(8)
        if "on interface" in message_content:
            interface_match = re.search(r"on interface (\w+)", message_content)
            if interface_match:
                details["asa_interface"] = interface_match.group(1)
        return details

    deny_no_conn_match = re.search(config.ASA_DENY_NO_CONN_REGEX, message_content)
    if deny_no_conn_match:
        details["action"] = deny_no_conn_match.group(1)
        details["protocol"] = deny_no_conn_match.group(2).upper()
        details["src_ip"] = deny_no_conn_match.group(3)
        details["src_port"] = deny_no_conn_match.group(4)
        details["dst_ip"] = deny_no_conn_match.group(5)
        details["dst_port"] = deny_no_conn_match.group(6)
        if "on interface" in message_content:
            interface_match = re.search(r"on interface (\w+)", message_content)
            if interface_match:
                details["asa_interface"] = interface_match.group(1)
        return details
        
    return details 

def parse_windows_security_message_detail(message_detail):
    """Helper to parse Windows Security EventID message details."""
    extracted_details = {}
    
    user_match = re.search(r"(?:User|Account Name):\s*([\w@$.-]+)", message_detail, re.IGNORECASE)
    if user_match: extracted_details["user"] = user_match.group(1)
    
    target_user_match = re.search(
        r"(?:Account Name For Which Logon Failed|Target Account:\s*Account Name|Account That Was Locked Out:\s*Account Name):\s*([\w@$.-]+)", 
        message_detail, re.IGNORECASE
    )
    if target_user_match:
        extracted_details["target_user"] = target_user_match.group(1)

    logon_type_match = re.search(r"Logon Type:\s*(\d+)", message_detail, re.IGNORECASE)
    if logon_type_match: extracted_details["logon_type"] = logon_type_match.group(1)
        
    src_workstation_match = re.search(r"(?:Source Workstation|Workstation Name):\s*([\w.-]+)", message_detail, re.IGNORECASE)
    if src_workstation_match: extracted_details["client_ip"] = src_workstation_match.group(1) 
    
    src_ip_match = re.search(r"Source Network Address:\s*([\d.:]+)", message_detail, re.IGNORECASE) 
    if src_ip_match: extracted_details["src_ip"] = src_ip_match.group(1)

    src_port_match = re.search(r"Source Port:\s*(\d+)", message_detail, re.IGNORECASE)
    if src_port_match: extracted_details["src_port"] = src_port_match.group(1)

    status_match = re.search(r"Status:\s*(0x[\da-fA-F]+)", message_detail, re.IGNORECASE) 
    if status_match: extracted_details["status_code"] = status_match.group(1)
        
    return extracted_details

def parse_log_line(log_line, current_file, line_num):
    """
    Parses a single raw log line into a structured dictionary.
    Refactored Linux parsing logic.
    Returns None if parsing fails.
    """
    base_info = {
        "timestamp": None, "hostname": None, "process_name": "Unknown", "pid": None,
        "message": None, "original_log": log_line, "source_file": current_file,
        "source_line_number": line_num, "event_id": None, "user": None,
        "src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None,
        "protocol": None, "action": None, "command": None, "domain_queried": None,
        "client_ip": None, "logon_type": None, "status_code": None, "target_user": None,
        "asa_interface": None, "asa_msg_code": None, "src_interface_host": None, 
        "dst_interface_host": None
    }

    general_match = re.match(config.GENERAL_LOG_REGEX, log_line)
    if not general_match:
        return None

    timestamp_str, hostname, message_content = general_match.groups()
    
    parsed_datetime = utils.parse_timestamp(timestamp_str)
    if not parsed_datetime:
        return None
    
    base_info["timestamp"] = parsed_datetime
    base_info["hostname"] = hostname
    base_info["message"] = message_content 

    # --- Hostname-Specific Parsing Logic ---
    if hostname == "ASA-FIREWALL":
        base_info["process_name"] = "ASA"
        asa_msg_code_match = re.match(config.ASA_MSG_CODE_REGEX, message_content)
        if asa_msg_code_match:
            base_info["asa_msg_code"] = asa_msg_code_match.group(1)
            detailed_message = asa_msg_code_match.group(2).strip()
            asa_details = parse_asa_message(detailed_message)
            base_info.update(asa_details) 
            base_info["message"] = detailed_message
        else:
            base_info["message"] = message_content 

    elif hostname.startswith("WINSRV01"):
        # Windows Parsing Logic
        ms_event_match = re.match(config.MSWINEVENTLOG_FORMAT_REGEX, message_content)
        if ms_event_match:
            base_info["process_name"] = ms_event_match.group(1).strip() 
            base_info["event_id"] = ms_event_match.group(2).strip()     
            message_detail = ms_event_match.group(3).strip() 
            base_info["message"] = message_detail
            if base_info["process_name"].lower() == "security": 
                sec_details = parse_windows_security_message_detail(message_detail)
                base_info.update(sec_details)
        else:
            named_dns_match = re.match(config.WINDOWS_NAMED_DNS_PREFIX_REGEX, message_content)
            dhcpd_match = re.match(config.WINDOWS_DHCPD_PREFIX_REGEX, message_content)
            iis_match_prefix = re.match(config.WINDOWS_IIS_PREFIX_REGEX, message_content)
            win_sec_simple_match = re.search(config.WINDOWS_SECURITY_EVENT_REGEX, message_content)

            if named_dns_match:
                base_info["process_name"] = "DNS" 
                dns_detail = named_dns_match.group(1).strip()
                base_info["message"] = dns_detail
                client_query_match = re.search(config.WINDOWS_DNS_CLIENT_QUERY_REGEX, dns_detail)
                if client_query_match:
                    base_info["client_ip"] = client_query_match.group(1)
                    base_info["domain_queried"] = client_query_match.group(2)
                    base_info["action"] = "DNS Query"
                else: 
                    query_match = re.search(config.WINDOWS_DNS_QUERY_REGEX, message_content)
                    if query_match:
                        current_action = base_info.get("action", "")
                        base_info["action"] = f"{current_action} DNS Query".strip()
                        base_info["domain_queried"] = query_match.group(1)
                        base_info["client_ip"] = query_match.group(2)
                    response_match = re.search(config.WINDOWS_DNS_RESPONSE_REGEX, message_content)
                    if response_match: 
                        current_action = base_info.get("action", "")
                        base_info["action"] = f"{current_action} DNS Response".strip()
                        if not base_info.get("domain_queried"): base_info["domain_queried"] = response_match.group(1)
                        base_info["src_ip"] = response_match.group(2) 
                    forward_match = re.search(config.WINDOWS_DNS_FORWARD_REGEX, message_content)
                    if forward_match:
                        current_action = base_info.get("action", "")
                        base_info["action"] = f"{current_action} DNS Forward".strip()
                        if not base_info.get("domain_queried"): base_info["domain_queried"] = forward_match.group(1)
                        base_info["dst_ip"] = forward_match.group(2)
            elif dhcpd_match:
                base_info["process_name"] = "dhcpd" 
                dhcp_detail = dhcpd_match.group(1).strip()
                base_info["message"] = dhcp_detail
                action_match = re.search(config.WINDOWS_DHCP_ACTION_REGEX, dhcp_detail)
                if action_match:
                    base_info["action"] = action_match.group(1)
                    base_info["dst_ip"] = action_match.group(2) 
                    base_info["user"] = action_match.group(3) 
            elif iis_match_prefix:
                base_info["process_name"] = "IIS"
                iis_detail = iis_match_prefix.group(1).strip()
                base_info["message"] = iis_detail
                log_match = re.search(config.WINDOWS_IIS_LOG_REGEX, iis_detail)
                if log_match:
                    base_info["client_ip"] = log_match.group(1)
                    base_info["action"] = log_match.group(2) 
                    base_info["command"] = log_match.group(3) 
                    base_info["status_code"] = log_match.group(4)
            elif win_sec_simple_match: 
                base_info["process_name"] = "Security" 
                if win_sec_simple_match.group(1) and win_sec_simple_match.group(1).isdigit():
                    base_info["pid"] = win_sec_simple_match.group(1)
                    base_info["event_id"] = win_sec_simple_match.group(2)
                    message_detail = win_sec_simple_match.group(3).strip() if win_sec_simple_match.group(3) else message_content.split(":",1)[-1].strip()
                else: 
                    base_info["event_id"] = win_sec_simple_match.group(1) if not win_sec_simple_match.group(2) else win_sec_simple_match.group(2) 
                    message_detail = win_sec_simple_match.group(3).strip() if win_sec_simple_match.group(3) else message_content.split(":",1)[-1].strip()
                base_info["message"] = message_detail
                sec_details = parse_windows_security_message_detail(message_detail)
                base_info.update(sec_details)
            else: 
                win_comp_match = re.match(config.WINDOWS_GENERIC_COMPONENT_REGEX, message_content)
                if win_comp_match:
                    proc_name_candidate = win_comp_match.group(1).strip().replace(":", "")
                    base_info["process_name"] = proc_name_candidate
                    base_info["message"] = win_comp_match.group(2).strip()
                else:
                    base_info["process_name"] = "WINSRV01_Unknown"
                    base_info["message"] = message_content
    
    # --- Linux-like hosts (PCx, kali) ---
    else: 
        linux_gen_match = re.match(config.LINUX_GENERAL_PROCESS_REGEX, message_content)
        
        if linux_gen_match:
            process_name_candidate = linux_gen_match.group(1).strip()
            if '/' in process_name_candidate and len(process_name_candidate) > 25:
                 base_info["process_name"] = os.path.basename(process_name_candidate)
            else:
                base_info["process_name"] = process_name_candidate
            
            if linux_gen_match.group(2): base_info["pid"] = linux_gen_match.group(2)
            message_detail = linux_gen_match.group(3).strip()
            base_info["message"] = message_detail 

            process_name_lower = base_info["process_name"].lower()

            # --- SSHD Parsing (Using Detail Regexes) ---
            if process_name_lower == 'sshd':
                sshd_failed_match = re.search(config.SSHD_DETAIL_FAILED_PASSWORD_REGEX, message_detail)
                sshd_invalid_user_match = re.search(config.SSHD_DETAIL_INVALID_USER_REGEX, message_detail)
                sshd_accepted_match = re.search(config.SSHD_DETAIL_ACCEPTED_REGEX, message_detail)
                sshd_disconnect_match = re.search(config.SSHD_DETAIL_DISCONNECT_REGEX, message_detail)
                sshd_conn_closed_match = re.search(config.SSHD_DETAIL_CONN_CLOSED_REGEX, message_detail)
                
                if sshd_failed_match:
                    base_info["action"] = "Failed password"
                    # Check if "invalid user" prefix exists in the original message_detail
                    if re.search(r"Failed password for invalid user", message_detail):
                         base_info["target_user"] = sshd_failed_match.group(1)
                         base_info["user"] = "invalid user"
                    else:
                         base_info["user"] = sshd_failed_match.group(1) 
                         base_info["target_user"] = base_info["user"] 
                    base_info["src_ip"] = sshd_failed_match.group(2)
                    base_info["src_port"] = sshd_failed_match.group(3) 
                elif sshd_invalid_user_match:
                     base_info["action"] = "Invalid user"
                     base_info["user"] = "invalid user" 
                     base_info["target_user"] = sshd_invalid_user_match.group(1) 
                     base_info["src_ip"] = sshd_invalid_user_match.group(2)
                     base_info["src_port"] = sshd_invalid_user_match.group(3) if sshd_invalid_user_match.group(3) else ''
                elif sshd_accepted_match:
                    base_info["action"] = "Accepted password"
                    base_info["user"] = sshd_accepted_match.group(1)
                    base_info["src_ip"] = sshd_accepted_match.group(2)
                    base_info["src_port"] = sshd_accepted_match.group(3)
                elif sshd_disconnect_match:
                     base_info["action"] = "Disconnected"
                     base_info["user"] = sshd_disconnect_match.group(1) 
                     base_info["src_ip"] = sshd_disconnect_match.group(2)
                     base_info["src_port"] = sshd_disconnect_match.group(3) 
                elif sshd_conn_closed_match:
                     base_info["action"] = "Connection closed"
                     base_info["user"] = sshd_conn_closed_match.group(1)
                     base_info["src_ip"] = sshd_conn_closed_match.group(2)
                     base_info["src_port"] = sshd_conn_closed_match.group(3) 
            
            # --- Other Linux Process Parsing ---
            elif process_name_lower == 'cron':
                 cron_detail_match = re.match(r"\(([\w.-]+)\) CMD \((.*)\)", message_detail)
                 if cron_detail_match:
                     base_info["user"] = cron_detail_match.group(1)
                     base_info["command"] = cron_detail_match.group(2)
                     base_info["action"] = "CMD"
                     
            elif process_name_lower == 'dhclient':
                 dhclient_action_match = re.match(r"(DHCPREQUEST|DHCPACK|DHCPOFFER|DHCPNAK|BOUND|RENEW|FAIL)(?:.*)", message_detail)
                 if dhclient_action_match:
                     base_info["action"] = dhclient_action_match.group(1)
                 ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", message_detail) 
                 if ip_match: base_info["dst_ip"] = ip_match.group(1) 

            elif process_name_lower == 'vsftpd':
                 vsftpd_core_message = re.sub(r"^\[.*?\]\s*", "", message_detail) 
                 vsftpd_detail_match = re.search(
                     r"(OK LOGIN|FAIL LOGIN|OK UPLOAD|FAIL UPLOAD|OK DOWNLOAD|FAIL DOWNLOAD|OK DELETE|CONNECT|FTP command|FTP session closed|DISCONNECT):\s*(?:Client \"([\d.]+)\")?(?:,\s*[\w\s\"@.-]+)?(?:\"(.*)\")?", 
                     vsftpd_core_message
                 )
                 if vsftpd_detail_match:
                     base_info["action"] = vsftpd_detail_match.group(1)
                     if vsftpd_detail_match.group(2): base_info["client_ip"] = vsftpd_detail_match.group(2)
                     if vsftpd_detail_match.group(3): base_info["message"] = vsftpd_detail_match.group(3) 
                 
                 user_match = re.match(r"\[([\w.:)-]+)\]", message_detail)
                 if user_match:
                     base_info["user"] = user_match.group(1)

            elif process_name_lower == 'kernel':
                 pass 

        else: 
             kernel_ts_match = re.match(r"\[\s*([\d.]+)\]\s*(.*)", message_content)
             if kernel_ts_match:
                 base_info["process_name"] = "kernel"
                 base_info["message"] = kernel_ts_match.group(2).strip()
             else:
                 base_info["process_name"] = f"{hostname}_UnknownFormat"
                 base_info["message"] = message_content

    # Final cleanup for Nones to empty strings 
    for key, value in base_info.items():
        if value is None:
            base_info[key] = '' 

    return base_info

def parse_all_logs(log_dir_path):
    """
    Parses all log lines from files in the given directory.
    Returns a Pandas DataFrame.
    """
    parsed_data = []
    log_generator = utils.read_log_files(log_dir_path)
    
    if log_generator is None: 
        print(f"Log generator is None. No log files to process in {log_dir_path}")
        return pd.DataFrame()

    processed_lines_count = 0
    print("Starting log processing loop...")
    for item in log_generator:
        try:
            if not (isinstance(item, tuple) and len(item) == 3):
                continue 
            log_line, filename, line_num = item
            processed_lines_count += 1
        except ValueError as e: 
            continue 
        
        if not log_line and log_line != "": 
            continue
            
        parsed_entry = parse_log_line(log_line, filename, line_num)
        if parsed_entry:
            parsed_data.append(parsed_entry)
    
    print(f"Finished processing. Total items from generator considered: {processed_lines_count}.")
    
    if not parsed_data:
        print("No logs were successfully parsed into structured data.")
        return pd.DataFrame()

    df = pd.DataFrame(parsed_data)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        original_rows = len(df)
        df.dropna(subset=['timestamp'], inplace=True)
        if len(df) < original_rows:
            print(f"Dropped {original_rows - len(df)} rows due to invalid timestamps after parsing.")
    else:
        print("Warning: 'timestamp' column not found after parsing. Aggregation might fail.")
        df['timestamp'] = pd.NaT 
    
    return df

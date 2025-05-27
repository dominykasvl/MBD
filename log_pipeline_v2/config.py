import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_LOGS_DIR = os.path.join(BASE_DIR, "data", "input_logs")
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, "data", "processed")
os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

DAILY_METRICS_DIR = os.path.join(PROCESSED_DATA_DIR, "daily_metrics")
os.makedirs(DAILY_METRICS_DIR, exist_ok=True)

BASELINE_DIR = os.path.join(PROCESSED_DATA_DIR, "baseline")
os.makedirs(BASELINE_DIR, exist_ok=True)

DAILY_DEVIATIONS_DIR = os.path.join(PROCESSED_DATA_DIR, "daily_deviations")
os.makedirs(DAILY_DEVIATIONS_DIR, exist_ok=True)

LOG_YEAR = 2025

# --- Output File Names ---
PARSED_LOGS_PARQUET = os.path.join(PROCESSED_DATA_DIR, "parsed_logs_v2_enhanced.parquet")

# --- Method Choices ---
AGGREGATION_METHODS = ['hourly_events', 'failed_logins', 'source_ip_hourly_events',
                       'src_dst_ip_hourly_events', 'http_errors']
NORMALIZATION_METHODS = ['scaler', 'l2', 'minmax', 'none']
CORRELATION_METHODS = ['cosine', 'pearson', 'spearman', 'kendall']
DISTANCE_METHODS = ['euclidean', 'manhattan']
METRIC_METHODS = CORRELATION_METHODS + DISTANCE_METHODS

# --- Regexes ---
GENERAL_LOG_REGEX = r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w.-]+)\s+(.*)$"
ASA_MSG_CODE_REGEX = r"%(ASA-\d-\d+): (.*)"
ASA_CONNECTION_REGEX = r"(Built|Teardown) (inbound|outbound) (TCP|UDP) connection \d+ for ([\w./:-]+):([\d.]+)/(\d+) \((?:[\d.]+)/?(?:\d+)?\) to ([\w./:-]+):([\d.]+)/(\d+) \((?:[\d.]+)/?(?:\d+)?\)(?: duration .*)?(?: bytes .*)?"
ASA_DENY_PERMIT_REGEX = r"(Deny|Permit|permitted) (tcp|udp|icmp) src ([\w./:-]+):([\d.]+)/(\d+) dst ([\w./:-]+):([\d.]+)/(\d+)"
ASA_DENY_NO_CONN_REGEX = r"(Deny) (TCP|UDP|ICMP) \(no connection\) from ([\d.]+)/(\d+) to ([\d.]+)/(\d+)"
MSWINEVENTLOG_FORMAT_REGEX = r"MSWinEventLog\s+\d+\s+([\w-]+)\s+\d+\s+[\w\s:]+\d{4}\s+(\d+)\s(?:[\w.-]+)\s(?:[\w\s./-]+)?:\s*(.*)"
WINDOWS_SECURITY_EVENT_REGEX = r"Security(?:(?:\([\w-]+\))?\[(\d+)\])?:\s*(?:EventID=)?(\d+)\s*(.*)"
WINDOWS_NAMED_DNS_PREFIX_REGEX = r"(?:Named|DNS(?:\(named\))?)(?:\[\d+\])?:\s*(.*)"
WINDOWS_DNS_QUERY_REGEX = r"query:\s*([\w.-]+)\s+IN\s+\w+\s+\+\s*(?:\(([\d.]+)\))?"
WINDOWS_DNS_CLIENT_QUERY_REGEX = r"client\s+([\d.#@]+):\s*query:\s*([\w.-]+)\s+IN"
WINDOWS_DNS_RESPONSE_REGEX = r"response:\s*([\w.-]+)\s+IN\s+\w+\s+([\d.]+)"
WINDOWS_DNS_FORWARD_REGEX = r"Forwarding query for ([\w.-]+) to ([\d.]+)"
WINDOWS_DHCPD_PREFIX_REGEX = r"(?:dhcpd|DHCPServer)(?:\[\d+\])?:\s*(?:\[\w+\]\s*Event ID \d+:\s*\w*:\s*)?(.*)"
WINDOWS_DHCP_ACTION_REGEX = r"(DHCPACK|DHCPREQUEST|DHCPOFFER|DHCPNAK|DHCPDECLINE|DHCPINFORM|DHCPRELEASE|Discover|Assign|Renew|Offer)\s*(?:on|for|from)?\s*([\d.]+) (?:to|from)? ([\w:]+)"
WINDOWS_IIS_PREFIX_REGEX = r"(?:IIS(?: W3SVC1)?|W3SVC1)(?:\[\w*\])?(?:[-:])?\s*(.*)"
WINDOWS_IIS_LOG_REGEX = r"([\d.]+) (GET|POST|HEAD) ([\S]+) .*? (\d{3})"
WINDOWS_GENERIC_COMPONENT_REGEX = r"([\w -]+?):\s*(.*)"
LINUX_CRON_REGEX = r"CRON\[(\d+)\]:\s*\(([\w.-]+)\) CMD \((.*)\)"
LINUX_DHCLIENT_REGEX = r"dhclient(?:\[(\d+)\])?:\s*(DHCPREQUEST|DHCPACK|DHCPOFFER|DHCPNAK|BOUND|RENEW|FAIL)(?:.*)"

# --- SSHD Detail Regexes (to be applied to message *after* process[pid]:) ---
SSHD_DETAIL_FAILED_PASSWORD_REGEX = r"Failed password for (invalid user )?([\w.-]+) from ([\d.]+) port (\d+)(?: ssh\d)?"
SSHD_DETAIL_INVALID_USER_REGEX = r"Invalid user ([\w.-]+) from ([\d.]+)(?: port (\d+))?(?: ssh\d)?"
SSHD_DETAIL_ACCEPTED_REGEX = r"Accepted \w+ for ([\w.-]+) from ([\d.]+) port (\d+)(?: ssh\d)?"
SSHD_DETAIL_DISCONNECT_REGEX = r"(?:Received disconnect|Disconnected) from (?:user )?([\w.-]+) ([\d.]+) port (\d+)"
SSHD_DETAIL_CONN_CLOSED_REGEX = r"Connection closed by (?:authenticating user )?([\w.-]+) ([\d.]+) port (\d+)"

LINUX_KERNEL_REGEX = r"kernel:\s*\[\s*([\d.]+)\]\s*(.*)"
VSFTPD_LOG_REGEX = r"vsftpd(?:\[(\d+)\])?:\s*(?:\[pid\s+\d+\]\s*)?(?:\[([\w.:)-]+)\]\s*)?(OK LOGIN|FAIL LOGIN|OK UPLOAD|FAIL UPLOAD|OK DOWNLOAD|FAIL DOWNLOAD|OK DELETE|CONNECT|FTP command|FTP session closed|DISCONNECT):\s*(?:Client \"([\d.]+)\")?(?:,\s*[\w\s\"@.-]+)?(?:\"(.*)\")?"
LINUX_GENERAL_PROCESS_REGEX = r"([\w./~-]+)(?:\[(\d+)\])?: (.*)"

AGGREGATION_WINDOW = 'h'

STD_DEV_MULTIPLIER = 2.5

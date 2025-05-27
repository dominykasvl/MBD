import pandas as pd
import config 
import re 

def aggregate_hourly_events_per_host(parsed_logs_df):
    """
    Aggregates total log events to get hourly counts per host.
    """
    if parsed_logs_df.empty:
        print("Input DataFrame for hourly event aggregation is empty.")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'event_count'])

    df = parsed_logs_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    df.set_index('timestamp', inplace=True)

    try:
        aggregated = df.groupby('hostname').resample(config.AGGREGATION_WINDOW).size()
    except Exception as e:
        print(f"Error during resampling by hostname: {e}")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'event_count'])

    aggregated = aggregated.rename('event_count').reset_index()
    aggregated.rename(columns={'timestamp': 'timestamp_hour'}, inplace=True)

    return aggregated

def aggregate_failed_logins_per_host(parsed_logs_df):
    """
    Aggregates FAILED login attempts per destination host per hour.
    """
    if parsed_logs_df.empty:
        print("Input DataFrame for failed login aggregation is empty.")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'failed_login_count'])

    df = parsed_logs_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    for col in ['process_name', 'event_id', 'message', 'action']:
        if col not in df.columns:
            df[col] = ''
        else:
            df[col] = df[col].fillna('')


    is_win_fail = (df['process_name'].str.lower() == 'security') & (df['event_id'].astype(str) == '4625')

    is_sshd_fail = (
        (df['process_name'].str.lower() == 'sshd') &
        (df['message'].str.contains('Failed password|Invalid user', case=False, regex=True))
    )

    is_vsftpd_fail = (
        (df['process_name'].str.lower() == 'vsftpd') &
        (df['message'].str.contains('FAIL LOGIN', case=False, regex=True))
    )

    failed_login_conditions = is_win_fail | is_sshd_fail | is_vsftpd_fail

    failed_logins_df = df[failed_login_conditions].copy()

    if failed_logins_df.empty:
        print("No failed login events found based on refined conditions.")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'failed_login_count'])

    print(f"Found {len(failed_logins_df)} potential failed login events using refined conditions.")

    failed_logins_df.set_index('timestamp', inplace=True)
    try:
        aggregated = failed_logins_df.groupby('hostname').resample(config.AGGREGATION_WINDOW).size()
    except Exception as e:
        print(f"Error during resampling failed logins by hostname: {e}")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'failed_login_count'])

    aggregated = aggregated.rename('failed_login_count').reset_index()
    aggregated.rename(columns={'timestamp': 'timestamp_hour'}, inplace=True)

    return aggregated

def aggregate_source_ip_hourly_events(parsed_logs_df):
    """
    Aggregates total log events initiated BY a source IP per hour.
    """
    if parsed_logs_df.empty:
        print("Input DataFrame for source IP hourly event aggregation is empty.")
        return pd.DataFrame(columns=['timestamp_hour', 'src_ip', 'event_count'])

    df = parsed_logs_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    valid_ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if 'src_ip' not in df.columns:
         print("Error: 'src_ip' column not found for source IP aggregation.")
         return pd.DataFrame(columns=['timestamp_hour', 'src_ip', 'event_count'])
    df_filtered = df[df['src_ip'].astype(str).str.match(valid_ip_pattern, na=False)]


    if df_filtered.empty:
        print("No log entries with valid source IPs found for aggregation.")
        return pd.DataFrame(columns=['timestamp_hour', 'src_ip', 'event_count'])

    print(f"Aggregating events for {df_filtered['src_ip'].nunique()} unique source IPs.")

    df_filtered.set_index('timestamp', inplace=True)

    try:
        aggregated = df_filtered.groupby('src_ip').resample(config.AGGREGATION_WINDOW).size()
    except Exception as e:
        print(f"Error during resampling by source IP: {e}")
        return pd.DataFrame(columns=['timestamp_hour', 'src_ip', 'event_count'])

    aggregated = aggregated.rename('event_count').reset_index()
    aggregated.rename(columns={'timestamp': 'timestamp_hour'}, inplace=True)

    return aggregated

def aggregate_src_dst_ip_hourly_events(parsed_logs_df):
    """
    Aggregates total log events between source-destination IP pairs per hour.
    """
    if parsed_logs_df.empty:
        print("Input DataFrame for src-dst IP hourly event aggregation is empty.")
        return pd.DataFrame(columns=['timestamp_hour', 'src_dst_pair', 'event_count'])

    df = parsed_logs_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    if 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
        print("Error: 'src_ip' or 'dst_ip' column not found for src-dst IP aggregation.")
        return pd.DataFrame(columns=['timestamp_hour', 'src_dst_pair', 'event_count'])

    valid_ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    df_filtered = df[
        df['src_ip'].astype(str).str.match(valid_ip_pattern, na=False) &
        df['dst_ip'].astype(str).str.match(valid_ip_pattern, na=False)
    ].copy() # Use .copy()

    if df_filtered.empty:
        print("No log entries with valid source AND destination IPs found for aggregation.")
        return pd.DataFrame(columns=['timestamp_hour', 'src_dst_pair', 'event_count'])

    df_filtered['src_dst_pair'] = df_filtered['src_ip'] + '->' + df_filtered['dst_ip']

    print(f"Aggregating events for {df_filtered['src_dst_pair'].nunique()} unique source->destination IP pairs.")

    df_filtered.set_index('timestamp', inplace=True)

    try:
        aggregated = df_filtered.groupby('src_dst_pair').resample(config.AGGREGATION_WINDOW).size()
    except Exception as e:
        print(f"Error during resampling by src_dst_pair: {e}")
        return pd.DataFrame(columns=['timestamp_hour', 'src_dst_pair', 'event_count'])

    aggregated = aggregated.rename('event_count').reset_index()
    aggregated.rename(columns={'timestamp': 'timestamp_hour'}, inplace=True)

    return aggregated

def aggregate_http_errors_per_host(parsed_logs_df):
    """
    Aggregates HTTP client (4xx) and server (5xx) errors per target host per hour.
    """
    if parsed_logs_df.empty:
        print("Input DataFrame for HTTP error aggregation is empty.")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'http_error_count'])

    df = parsed_logs_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    if 'status_code' not in df.columns:
        print("Warning: 'status_code' column not found for HTTP error aggregation.")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'http_error_count'])

    http_error_conditions = df['status_code'].astype(str).str.match(r'^[45]\d{2}$', na=False)
    http_errors_df = df[http_error_conditions].copy()

    if http_errors_df.empty:
        print("No HTTP 4xx/5xx error events found based on status code.")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'http_error_count'])

    print(f"Found {len(http_errors_df)} potential HTTP error logs.")

    http_errors_df.set_index('timestamp', inplace=True)
    try:
        aggregated = http_errors_df.groupby('hostname').resample(config.AGGREGATION_WINDOW).size()
    except Exception as e:
        print(f"Error during resampling HTTP errors by hostname: {e}")
        return pd.DataFrame(columns=['timestamp_hour', 'hostname', 'http_error_count'])

    aggregated = aggregated.rename('http_error_count').reset_index()
    aggregated.rename(columns={'timestamp': 'timestamp_hour'}, inplace=True)

    return aggregated


def create_host_activity_matrix(aggregated_df, index_column='hostname', value_column='event_count'):
    """
    Pivots aggregated data to create a matrix where:
    Rows are defined by index_column (e.g., 'hostname', 'src_ip', 'src_dst_pair').
    Columns are hourly timestamps.
    Values are from the specified value_column.
    """
    if aggregated_df.empty:
        print(f"Input DataFrame for activity matrix (index: {index_column}, value: {value_column}) is empty.")
        return pd.DataFrame()

    required_cols = [index_column, value_column, 'timestamp_hour']
    missing_cols = [col for col in required_cols if col not in aggregated_df.columns]
    if missing_cols:
        print(f"Error: Missing required columns for pivoting: {missing_cols}")
        return pd.DataFrame()

    try:
        if not pd.api.types.is_datetime64_any_dtype(aggregated_df['timestamp_hour']):
            aggregated_df['timestamp_hour'] = pd.to_datetime(aggregated_df['timestamp_hour'])

        host_activity_matrix = aggregated_df.pivot_table(
            index=index_column,
            columns='timestamp_hour',
            values=value_column,
            fill_value=0
        )
        host_activity_matrix = host_activity_matrix.sort_index(axis=1)
        return host_activity_matrix
    except Exception as e:
        print(f"Error creating activity matrix (index: {index_column}, value: {value_column}): {e}")
        return pd.DataFrame()

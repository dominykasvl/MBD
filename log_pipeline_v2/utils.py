import pandas as pd
from datetime import datetime
import os
import re
import config

def parse_timestamp(timestamp_str, year=config.LOG_YEAR):
    """
    Parses a log timestamp string (e.g., "Mar  6 00:00:01") into a datetime object.
    Assumes a fixed year if not present in the timestamp.
    """
    try:
        parts = timestamp_str.split()
        if len(parts[1]) == 1:
            timestamp_str_corrected = f"{parts[0]}  {parts[1]} {parts[2]}"
        else:
            timestamp_str_corrected = timestamp_str
        
        # Standardize spaces for strptime
        timestamp_str_standardized = re.sub(r'\s+', ' ', timestamp_str_corrected)
        
        dt_object = datetime.strptime(f"{year} {timestamp_str_standardized}", "%Y %b %d %H:%M:%S")
        return dt_object
    except ValueError as e:
        try:
            # Try original string directly
            timestamp_str_standardized_orig = re.sub(r'\s+', ' ', timestamp_str)
            dt_object = datetime.strptime(f"{year} {timestamp_str_standardized_orig}", "%Y %b %d %H:%M:%S")
            return dt_object
        except ValueError:
            # print(f"Timestamp parsing failed for: {timestamp_str}")
            return None


def read_log_files(log_dir_path):
    """
    Reads all .txt files from the specified directory.
    Yields a tuple: (stripped_line, filename, line_number).
    """
    if not os.path.exists(log_dir_path):
        print(f"Log directory not found: {log_dir_path}")
        return
    if not os.listdir(log_dir_path):
        print(f"No files found in log directory: {log_dir_path}")
        return

    for filename in sorted(os.listdir(log_dir_path)):
        if filename.endswith(".txt"):
            file_path = os.path.join(log_dir_path, filename)
            print(f"Reading file: {file_path}")
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: 
                    for line_number, line in enumerate(f, 1):
                        yield line.strip(), filename, line_number
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")

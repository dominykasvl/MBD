import pandas as pd
import os
import numpy as np
import argparse
import json
import config
import parsers
import aggregators
import normalizers
import correlators
import sys

def get_dynamic_filename(prefix, aggregation, normalization, metric, date_str=None, ext=".csv"):
    """Helper function to create descriptive filenames."""
    parts = [prefix]
    if aggregation: parts.append(f"agg-{aggregation}")
    if normalization: parts.append(f"norm-{normalization}")
    if metric: parts.append(f"metric-{metric}")
    if date_str: parts.append(date_str)

    filename = "_".join(parts) + ext
    return filename

def calculate_matrix_stats(df):
    """Calculates mean and std dev of off-diagonal elements."""
    if df is None or df.empty:
        return None, None
    df_copy = df.copy()
    np.fill_diagonal(df_copy.values, np.nan)
    values = df_copy.values.flatten()
    values = values[~np.isnan(values)]

    if len(values) == 0:
        return 0.0, 0.0
    mean = np.mean(values)
    std_dev = np.std(values)
    return mean, std_dev

def run_pipeline(mode, aggregation_method, normalization_method, metric_method,
                 baseline_log_files_str=None, analysis_log_files_str=None): # Removed run_detection, run_anomaly flags
    """
    Executes the log processing pipeline with selectable methods and dynamic thresholds,
    focusing on statistical anomaly detection.
    """
    print(f"--- Starting Log Pipeline V2 ---")
    print(f"Mode: {mode}")
    print(f"Aggregation: {aggregation_method}")
    print(f"Normalization: {normalization_method}")
    print(f"Metric: {metric_method}")

    # --- Validate Method Choices ---
    if aggregation_method not in config.AGGREGATION_METHODS:
        print(f"Error: Invalid aggregation method '{aggregation_method}'. Choices: {config.AGGREGATION_METHODS}")
        sys.exit(1)
    if normalization_method not in config.NORMALIZATION_METHODS:
        print(f"Error: Invalid normalization method '{normalization_method}'. Choices: {config.NORMALIZATION_METHODS}")
        sys.exit(1)
    if metric_method not in config.METRIC_METHODS:
        print(f"Error: Invalid metric method '{metric_method}'. Choices: {config.METRIC_METHODS}")
        sys.exit(1)

    # --- Convert file strings to lists ---
    baseline_log_files = baseline_log_files_str.split(',') if baseline_log_files_str else None
    analysis_log_files = analysis_log_files_str.split(',') if analysis_log_files_str else None

    # --- Define Aggregation Function and Columns ---
    if aggregation_method == 'hourly_events':
        aggregate_func = aggregators.aggregate_hourly_events_per_host
        value_column = 'event_count'
        index_column = 'hostname'
    elif aggregation_method == 'failed_logins':
        aggregate_func = aggregators.aggregate_failed_logins_per_host
        value_column = 'failed_login_count'
        index_column = 'hostname'
    elif aggregation_method == 'source_ip_hourly_events':
        aggregate_func = aggregators.aggregate_source_ip_hourly_events
        value_column = 'event_count'
        index_column = 'src_ip'
    elif aggregation_method == 'src_dst_ip_hourly_events':
        aggregate_func = aggregators.aggregate_src_dst_ip_hourly_events
        value_column = 'event_count'
        index_column = 'src_dst_pair'
    elif aggregation_method == 'http_errors':
        aggregate_func = aggregators.aggregate_http_errors_per_host
        value_column = 'http_error_count'
        index_column = 'hostname'
    else:
        print(f"Error: Unknown aggregation function for '{aggregation_method}'")
        sys.exit(1)

    # --- Define Normalization Function ---
    if normalization_method == 'scaler':
        normalize_func = normalizers.normalize_activity_matrix_standardscaler
    elif normalization_method == 'l2':
        normalize_func = normalizers.normalize_activity_matrix_l2
    elif normalization_method == 'minmax':
        normalize_func = normalizers.normalize_activity_matrix_minmax
    elif normalization_method == 'none':
        normalize_func = None
    else:
        print(f"Error: Unknown normalization function for '{normalization_method}'")
        sys.exit(1)

    # --- Define Correlation/Distance Function ---
    if metric_method == 'cosine':
        metric_func = correlators.calculate_host_cosine_similarity
    elif metric_method == 'euclidean':
        metric_func = correlators.calculate_host_euclidean_distance_matrix
    elif metric_method == 'manhattan':
        metric_func = correlators.calculate_host_manhattan_distance_matrix
    elif metric_method in config.CORRELATION_METHODS:
        metric_func = lambda df: correlators.calculate_rank_correlation(df, method=metric_method)
    else:
        print(f"Error: Unknown metric function for '{metric_method}'")
        sys.exit(1)

    # --- Check if Parsed Data Exists, Parse if Not ---
    if not os.path.exists(config.PARSED_LOGS_PARQUET):
        print("\n--- Stage 1: Parsing Log Files (Required) ---")
        if not os.path.exists(config.INPUT_LOGS_DIR) or not os.listdir(config.INPUT_LOGS_DIR):
            print(f"No log files found or input directory does not exist: {config.INPUT_LOGS_DIR}.")
            os.makedirs(config.INPUT_LOGS_DIR, exist_ok=True)
            if not os.listdir(config.INPUT_LOGS_DIR):
                 print(f"Creating dummy log files in {config.INPUT_LOGS_DIR} for a test run.")
                 with open(os.path.join(config.INPUT_LOGS_DIR, "dummy_log_file.txt"), "w") as f:
                     f.write("Mar  6 00:00:01 PC1 kernel: Test log line 1 for pipeline\n")
                     f.write("Mar  7 01:00:01 PC2 sshd[123]: Accepted password for user_test\n")

        parsed_logs_df = parsers.parse_all_logs(config.INPUT_LOGS_DIR)
        if parsed_logs_df.empty:
            print("Pipeline halted: No data after parsing.")
            return
        parsed_logs_df.to_parquet(config.PARSED_LOGS_PARQUET, index=False)
        print(f"Parsed logs saved to: {config.PARSED_LOGS_PARQUET}")
    else:
        print("\n--- Stage 1: Loading Existing Parsed Logs ---")
        parsed_logs_df = pd.read_parquet(config.PARSED_LOGS_PARQUET)
        print(f"Loaded parsed logs from: {config.PARSED_LOGS_PARQUET}")
        if 'timestamp' in parsed_logs_df.columns and not pd.api.types.is_datetime64_any_dtype(parsed_logs_df['timestamp']):
             parsed_logs_df['timestamp'] = pd.to_datetime(parsed_logs_df['timestamp'])

    # --- Mode Execution ---
    if mode == "baseline":
        print("\n--- Generating Baseline Metrics ---")
        if baseline_log_files:
            print(f"Using specific files for baseline: {baseline_log_files}")
            if 'source_file' not in parsed_logs_df.columns:
                print("Error: 'source_file' column missing in parsed logs. Cannot filter.")
                return
            current_parsed_logs_df = parsed_logs_df[parsed_logs_df['source_file'].isin(baseline_log_files)]
            if current_parsed_logs_df.empty:
                 print(f"No logs found from the specified baseline files: {baseline_log_files}")
                 return
        else:
            print(f"Using ALL parsed logs for baseline.")
            current_parsed_logs_df = parsed_logs_df

        print(f"Aggregating baseline data using: {aggregation_method}...")
        aggregated_df = aggregate_func(current_parsed_logs_df)
        if aggregated_df.empty: print("Baseline aggregation failed."); return

        activity_matrix_df = aggregators.create_host_activity_matrix(aggregated_df, index_column=index_column, value_column=value_column)
        if activity_matrix_df.empty or activity_matrix_df.shape[0] < 2 or activity_matrix_df.shape[1] == 0:
            print("Could not create valid baseline activity matrix."); return

        print(f"Normalizing baseline data using: {normalization_method}...")
        if normalize_func:
            normalized_df = normalize_func(activity_matrix_df)
            if normalized_df.empty: print("Baseline normalization failed."); return
            data_for_metric = normalized_df
        else:
            print("Skipping normalization as per selection.")
            data_for_metric = activity_matrix_df

        print(f"Calculating baseline metric using: {metric_method}...")
        baseline_metric_df = metric_func(data_for_metric)

        if baseline_metric_df is not None and not baseline_metric_df.empty:
            baseline_metric_filename = get_dynamic_filename("baseline", aggregation_method, normalization_method, metric_method, ext=".csv")
            baseline_metric_filepath = os.path.join(config.BASELINE_DIR, baseline_metric_filename)
            baseline_metric_df.to_csv(baseline_metric_filepath, index=True)
            print(f"Baseline {metric_method} matrix saved to: {baseline_metric_filepath}")

            mean_stat, std_dev_stat = calculate_matrix_stats(baseline_metric_df)
            if mean_stat is None or std_dev_stat is None:
                 print(f"Warning: Could not calculate stats for baseline {metric_method} matrix (likely too few entities).")
                 baseline_stats = {'mean': 0.0, 'std_dev': 0.0}
            else:
                 baseline_stats = {'mean': mean_stat, 'std_dev': std_dev_stat}

            baseline_stats_filename = get_dynamic_filename("baseline", aggregation_method, normalization_method, metric_method, ext=".json")
            baseline_stats_filepath = os.path.join(config.BASELINE_DIR, baseline_stats_filename)
            try:
                with open(baseline_stats_filepath, 'w') as f:
                    json.dump(baseline_stats, f, indent=4)
                print(f"Baseline {metric_method} stats saved to: {baseline_stats_filepath}")
                print(f"  Baseline Mean: {baseline_stats['mean']:.4f}, Baseline Std Dev: {baseline_stats['std_dev']:.4f}")
            except Exception as e:
                print(f"Error saving baseline stats to JSON: {e}")
        else:
            print(f"Failed to calculate baseline {metric_method}.")

        print("--- Baseline Generation Finished ---")

    elif mode == "analysis":
        print("\n--- Running Analysis Mode ---")

        baseline_metric_filename = get_dynamic_filename("baseline", aggregation_method, normalization_method, metric_method, ext=".csv")
        baseline_metric_filepath = os.path.join(config.BASELINE_DIR, baseline_metric_filename)
        baseline_stats_filename = get_dynamic_filename("baseline", aggregation_method, normalization_method, metric_method, ext=".json")
        baseline_stats_filepath = os.path.join(config.BASELINE_DIR, baseline_stats_filename)

        print(f"\n--- Loading Baseline Metric & Stats ({metric_method}) ---")
        try:
            baseline_metric_df = pd.read_csv(baseline_metric_filepath, index_col=0)
            print(f"Loaded baseline {metric_method} matrix from: {baseline_metric_filepath}")
        except FileNotFoundError:
            print(f"Error: Baseline metric file '{baseline_metric_filename}' not found. Cannot run anomaly detection.")
            return
        try:
            with open(baseline_stats_filepath, 'r') as f:
                baseline_stats = json.load(f)
            baseline_mean = baseline_stats.get('mean', 0)
            baseline_std_dev = baseline_stats.get('std_dev', 0)
            print(f"Loaded baseline {metric_method} stats from: {baseline_stats_filepath} (Mean: {baseline_mean:.4f}, StdDev: {baseline_std_dev:.4f})")
        except FileNotFoundError:
            print(f"Error: Baseline stats file '{baseline_stats_filename}' not found. Cannot run anomaly detection.")
            return
        except json.JSONDecodeError:
             print(f"Error: Could not decode JSON from baseline stats file: {baseline_stats_filepath}.")
             return

        if analysis_log_files:
            if 'source_file' not in parsed_logs_df.columns:
                print("Error: 'source_file' column missing in parsed logs. Cannot filter for analysis files.")
                return
            current_parsed_logs_df = parsed_logs_df[parsed_logs_df['source_file'].isin(analysis_log_files)]
            if current_parsed_logs_df.empty:
                 print(f"No logs found from the specified analysis files: {analysis_log_files}")
                 return
            print(f"Analyzing specific files: {analysis_log_files}")
        else:
            print(f"Analyzing ALL parsed logs.")
            current_parsed_logs_df = parsed_logs_df

        hourly_aggregated_df = aggregate_func(current_parsed_logs_df)
        if hourly_aggregated_df.empty:
            print("Analysis halted: No data after aggregation for analysis period.")
            return

        if not pd.api.types.is_datetime64_any_dtype(hourly_aggregated_df['timestamp_hour']):
            hourly_aggregated_df['timestamp_hour'] = pd.to_datetime(hourly_aggregated_df['timestamp_hour'])

        unique_dates = hourly_aggregated_df['timestamp_hour'].dt.date.unique()
        print(f"Found {len(unique_dates)} unique dates for daily analysis.")

        # --- Daily Analysis Loop ---
        for specific_date in sorted(unique_dates):
            date_str = specific_date.strftime('%Y-%m-%d')
            print(f"\n--- Processing Daily Analysis for: {date_str} ---")

            daily_hourly_aggregated_df = hourly_aggregated_df[
                hourly_aggregated_df['timestamp_hour'].dt.date == specific_date
            ].copy()

            if daily_hourly_aggregated_df.empty: continue

            daily_activity_matrix_df = aggregators.create_host_activity_matrix(daily_hourly_aggregated_df, index_column=index_column, value_column=value_column)

            if daily_activity_matrix_df.empty or daily_activity_matrix_df.shape[0] < 2 or daily_activity_matrix_df.shape[1] == 0:
                print(f"Not enough data for {date_str}. Skipping daily metrics.")
                continue

            common_entities = baseline_metric_df.index.intersection(daily_activity_matrix_df.index)
            if len(common_entities) < 2:
                print(f"Not enough common entities ({index_column}) with baseline for {date_str}. Skipping.")
                continue

            aligned_baseline_metric_df = baseline_metric_df.loc[common_entities, common_entities]
            current_daily_activity_aligned = daily_activity_matrix_df.loc[common_entities]

            if normalize_func:
                normalized_daily_df = normalize_func(current_daily_activity_aligned)
                if normalized_daily_df.empty:
                    print(f"Daily normalization failed for {date_str}. Skipping metric calculation.")
                    continue
                data_for_metric = normalized_daily_df
            else:
                data_for_metric = current_daily_activity_aligned

            daily_metric_df = metric_func(data_for_metric)

            if daily_metric_df is not None and not daily_metric_df.empty:
                daily_metric_df = daily_metric_df.loc[common_entities, common_entities]

                daily_metric_filename = get_dynamic_filename("host", aggregation_method, normalization_method, metric_method, date_str, ext=".csv")
                daily_metric_filepath = os.path.join(config.DAILY_METRICS_DIR, daily_metric_filename)
                daily_metric_df.to_csv(daily_metric_filepath, index=True)
                print(f"Daily {metric_method} for {date_str} saved to: {daily_metric_filepath}")

                # Calculate and save deviations based on baseline stats
                deviation_df = pd.DataFrame(np.nan, index=common_entities, columns=common_entities)
                significant_mask = pd.DataFrame(False, index=common_entities, columns=common_entities)
                threshold = np.nan

                if metric_method in config.CORRELATION_METHODS:
                    deviation_df = (daily_metric_df - aligned_baseline_metric_df).abs()
                    threshold = config.STD_DEV_MULTIPLIER * baseline_std_dev
                    significant_mask = deviation_df > threshold
                    deviation_type = f"abs_change_vs_baseline(>{threshold:.3f})"

                elif metric_method in config.DISTANCE_METHODS:
                    deviation_df = daily_metric_df - aligned_baseline_metric_df
                    threshold = baseline_mean + config.STD_DEV_MULTIPLIER * baseline_std_dev
                    significant_mask = daily_metric_df > threshold
                    deviation_type = f"dist_above_baseline_mean+{config.STD_DEV_MULTIPLIER}std(>{threshold:.3f})"
                    deviation_df = deviation_df[significant_mask]

                else: continue

                np.fill_diagonal(significant_mask.values, False)
                np.fill_diagonal(deviation_df.values, np.nan)

                if not significant_mask.empty and significant_mask.stack().any():
                    significant_changes = deviation_df[significant_mask]
                    print(f"Significant {metric_method} changes ({deviation_type}) for {date_str}:\n{significant_changes.dropna(how='all', axis=0).dropna(how='all', axis=1)}")
                    deviation_filename = get_dynamic_filename("deviations", aggregation_method, normalization_method, metric_method, date_str, ext=".csv")
                    deviation_filepath = os.path.join(config.DAILY_DEVIATIONS_DIR, deviation_filename)
                    significant_changes.to_csv(deviation_filepath, index=True)
                    print(f"{metric_method.capitalize()} deviations saved to {deviation_filepath}")
                else:
                    print(f"No significant {metric_method} changes detected for {date_str} using dynamic threshold (Mean: {baseline_mean:.3f}, StdDev: {baseline_std_dev:.3f}, Threshold: {threshold:.3f}). Max deviation found: {deviation_df.max().max():.3f}")
            else:
                 print(f"Daily {metric_method} calculation failed for {date_str}.")

    else:
        print(f"Unknown mode: {mode}. Please use 'baseline' or 'analysis'.")

    print("\n--- Log Pipeline V2 Finished ---")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Analysis Pipeline V2 - Enhanced Methods & Dynamic Thresholds")
    parser.add_argument(
        "mode",
        choices=["baseline", "analysis"],
        help="Pipeline mode: 'baseline' or 'analysis'."
    )
    parser.add_argument(
        "--agg",
        choices=config.AGGREGATION_METHODS,
        default='hourly_events',
        help=f"Aggregation method (default: hourly_events)."
    )
    parser.add_argument(
        "--norm",
        choices=config.NORMALIZATION_METHODS,
        default='scaler',
        help=f"Normalization method (default: scaler)."
    )
    parser.add_argument(
        "--metric",
        choices=config.METRIC_METHODS,
        default='cosine',
        help=f"Correlation/Distance metric (default: cosine)."
    )
    parser.add_argument(
        "--baseline_files",
        type=str,
        help="Comma-separated string of log filenames for baseline generation (optional)."
    )
    parser.add_argument(
        "--analysis_files",
        type=str,
        help="Comma-separated string of log filenames for analysis (optional)."
    )
    parser.add_argument(
        "--stdev_mult",
        type=float,
        default=config.STD_DEV_MULTIPLIER,
        help=f"Multiplier for standard deviation to set anomaly threshold (default: {config.STD_DEV_MULTIPLIER})."
    )

    args = parser.parse_args()

    # Update config threshold multiplier if provided via CLI
    config.STD_DEV_MULTIPLIER = args.stdev_mult
    print(f"Using Standard Deviation Multiplier: {config.STD_DEV_MULTIPLIER}")

    # --- Example Command-Line Usage ---
    #
    # 1. Generate baseline using failed logins, L2 norm, Euclidean Distance (using ALL logs):
    #    python main_pipeline.py baseline --agg failed_logins --norm l2 --metric euclidean
    #
    # 2. Run analysis using failed logins, L2 norm, Euclidean Distance (using ALL logs, comparing to corresponding baseline):
    #    (Ensure baseline_agg-failed_logins_norm-l2_metric-euclidean.csv/json exist)
    #    python main_pipeline.py analysis --agg failed_logins --norm l2 --metric euclidean
    #
    # 3. Run analysis using http_errors, MinMax norm, Cosine Similarity (on specific files):
    #    (Ensure baseline_agg-http_errors_norm-minmax_metric-cosine.csv/json exist)
    #    python main_pipeline.py analysis --agg http_errors --norm minmax --metric cosine --analysis_files "0307.txt,0322.txt,0328.txt"
    #
    # --- End Example Usage ---

    run_pipeline(mode=args.mode,
                 aggregation_method=args.agg,
                 normalization_method=args.norm,
                 metric_method=args.metric,
                 baseline_log_files_str=args.baseline_files,
                 analysis_log_files_str=args.analysis_files
                 )

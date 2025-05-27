import os
import datetime
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# --- Configuration Section ---
# These should match the methods used to generate your existing analysis files
AGGREGATION_METHODS = ['hourly_events', 'failed_logins', 'source_ip_hourly_events',
                       'src_dst_ip_hourly_events']
NORMALIZATION_METHODS = ['scaler', 'l2', 'minmax', 'none']
METRIC_METHODS = ['cosine', 'pearson', 'spearman', 'kendall', 'euclidean', 'manhattan']

# Define base paths for input data (where deviation CSVs are) and output visualizations
# These paths are relative to where THIS script is run.
PROCESSED_DATA_DIR = "./data/processed"
DAILY_DEVIATIONS_DIR = os.path.join(PROCESSED_DATA_DIR, "daily_deviations")
VISUALIZATIONS_DIR = "./pipeline_visualizations_focused_attacks"

MASTER_LOG_FILE = "focused_visualization_output.log"

# Key attack dates to focus on
ATTACK_DATES_OF_INTEREST = ["2025-03-07", "2025-03-22", "2025-03-28"]
TOP_N_COMBINATIONS_TO_PLOT = 3 

def log_message(message):
    """Appends a message to the master log file and prints it."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    print(full_message)
    with open(MASTER_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(full_message + "\n")

def initialize_master_log():
    """Creates or clears the master log file."""
    with open(MASTER_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"Focused Attack Day Visualization script started at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_message("Master log file initialized for focused visualization script.")

def prepare_visualization_directory():
    """Creates necessary directories for visualizations if they don't exist."""
    if not os.path.exists(VISUALIZATIONS_DIR):
        os.makedirs(VISUALIZATIONS_DIR)
        log_message(f"Created main visualization directory: {VISUALIZATIONS_DIR}")
    
    # Subdirectory for the summary CSV
    summary_dir = os.path.join(VISUALIZATIONS_DIR, "summary_tables")
    if not os.path.exists(summary_dir):
        os.makedirs(summary_dir)
        log_message(f"Created directory for summary tables: {summary_dir}")

    # Subdirectory for top performer heatmaps
    top_heatmaps_dir = os.path.join(VISUALIZATIONS_DIR, "top_performer_heatmaps")
    if not os.path.exists(top_heatmaps_dir):
        os.makedirs(top_heatmaps_dir)
        log_message(f"Created directory for top performer heatmaps: {top_heatmaps_dir}")
    return summary_dir, top_heatmaps_dir


def get_dynamic_filename(base_name, agg_method, norm_method, metric_method, date_str=None, extension="csv"):
    """Constructs filenames consistent with the pipeline's output."""
    name_parts = [base_name]
    if agg_method: name_parts.append(f"agg-{agg_method}")
    if norm_method: name_parts.append(f"norm-{norm_method}")
    if metric_method: name_parts.append(f"metric-{metric_method}")
    if date_str: name_parts.append(date_str)
    return "_".join(name_parts) + "." + extension

def calculate_max_abs_deviation(csv_file_path):
    """Loads a deviation CSV and calculates the maximum absolute deviation value."""
    try:
        if not os.path.exists(csv_file_path):
            log_message(f"INFO: Deviation file not found for max_abs_dev calculation: {csv_file_path}")
            return None

        df = pd.read_csv(csv_file_path)
        if df.empty:
            log_message(f"INFO: Deviation file is empty: {csv_file_path}")
            return 0.0

        if df.columns[0] == 'hostname' or (df.shape[0] > 0 and isinstance(df.iloc[0,0], str) and not str(df.iloc[0,0]).isnumeric()):
            df = df.set_index(df.columns[0])
        elif 'Unnamed: 0' in df.columns:
             df = df.set_index('Unnamed: 0')
        
        df_numeric = df.apply(pd.to_numeric, errors='coerce').fillna(0)
        
        if df_numeric.empty:
            return 0.0
            
        return df_numeric.abs().max().max()
    except Exception as e:
        log_message(f"ERROR: Could not calculate max_abs_deviation for {csv_file_path}. Error: {e}")
        return None

def generate_heatmap_for_file(csv_file_path, output_image_path, title):
    """Generates and saves a heatmap from a specific deviation CSV file."""
    try:
        if not os.path.exists(csv_file_path):
            log_message(f"VISUALIZATION_INFO: CSV file not found for heatmap: {csv_file_path}")
            return

        df = pd.read_csv(csv_file_path)
        if df.empty:
            log_message(f"VISUALIZATION_INFO: CSV file is empty, skipping heatmap: {csv_file_path}")
            return
        
        if df.columns[0] == 'hostname' or (df.shape[0] > 0 and isinstance(df.iloc[0,0], str) and not str(df.iloc[0,0]).isnumeric()):
            df = df.set_index(df.columns[0])
        elif 'Unnamed: 0' in df.columns:
             df = df.set_index('Unnamed: 0')

        df_numeric = df.apply(pd.to_numeric, errors='coerce').fillna(0)

        if df_numeric.empty or df_numeric.shape[1] == 0:
            log_message(f"VISUALIZATION_INFO: DataFrame became empty for heatmap: {csv_file_path}")
            return

        plt.figure(figsize=(14, 10))
        sns.heatmap(df_numeric, annot=False, cmap="viridis") 
        plt.title(title, fontsize=16)
        plt.xticks(rotation=45, ha='right', fontsize=7)
        plt.yticks(rotation=0, fontsize=7)
        plt.tight_layout(pad=2.0)
        plt.savefig(output_image_path)
        plt.close()
        log_message(f"VISUALIZATION_SUCCESS: Saved heatmap to {output_image_path}")

    except Exception as e:
        log_message(f"VISUALIZATION_ERROR: Failed to generate heatmap for {csv_file_path}. Error: {e}")

# --- Main Execution Logic ---
def create_focused_visualizations():
    """
    Calculates max absolute deviations for key attack dates, saves a summary,
    and generates heatmaps for top-performing method combinations.
    """
    initialize_master_log()
    summary_output_dir, top_heatmaps_output_dir = prepare_visualization_directory()

    log_message("Starting focused visualization of analysis deviation files for key attack dates.")
    log_message(f"Deviation CSVs expected in: {os.path.abspath(DAILY_DEVIATIONS_DIR)}")
    
    all_max_deviations = []
    processed_files_count = 0

    for agg_method in AGGREGATION_METHODS:
        for norm_method in NORMALIZATION_METHODS:
            for metric_method in METRIC_METHODS:
                log_message(f"\n--- Analyzing combination: {agg_method}/{norm_method}/{metric_method} ---")
                for date_str in ATTACK_DATES_OF_INTEREST:
                    deviation_csv_name = get_dynamic_filename(
                        base_name="deviations",
                        agg_method=agg_method,
                        norm_method=norm_method,
                        metric_method=metric_method,
                        date_str=date_str,
                        extension="csv"
                    )
                    deviation_csv_path = os.path.join(DAILY_DEVIATIONS_DIR, deviation_csv_name)
                    
                    max_abs_dev = calculate_max_abs_deviation(deviation_csv_path)
                    processed_files_count += 1
                    
                    if max_abs_dev is not None:
                        all_max_deviations.append({
                            "date": date_str,
                            "agg_method": agg_method,
                            "norm_method": norm_method,
                            "metric_method": metric_method,
                            "max_abs_deviation": max_abs_dev
                        })
                        log_message(f"  Date: {date_str}, Max Abs Dev: {max_abs_dev:.4f}")
                    else:
                        log_message(f"  Date: {date_str}, Max Abs Dev: N/A (file issue or empty)")


    # Save the summary of all max absolute deviations
    summary_df = pd.DataFrame(all_max_deviations)
    summary_csv_path = os.path.join(summary_output_dir, "attack_days_max_deviation_summary.csv")
    try:
        summary_df.to_csv(summary_csv_path, index=False, float_format='%.6f')
        log_message(f"\nSummary of max absolute deviations saved to: {summary_csv_path}")
    except Exception as e:
        log_message(f"ERROR: Could not save summary CSV. Error: {e}")

    # Generate heatmaps for top N combinations per attack date
    log_message(f"\n--- Generating Heatmaps for Top {TOP_N_COMBINATIONS_TO_PLOT} Performers per Attack Date ---")
    if not summary_df.empty:
        for date_str in ATTACK_DATES_OF_INTEREST:
            log_message(f"\n-- Top performers for date: {date_str} --")
            date_specific_df = summary_df[summary_df['date'] == date_str].copy()
            
            date_specific_df['max_abs_deviation'] = pd.to_numeric(date_specific_df['max_abs_deviation'], errors='coerce')
            date_specific_df.dropna(subset=['max_abs_deviation'], inplace=True)


            top_n = date_specific_df.nlargest(TOP_N_COMBINATIONS_TO_PLOT, 'max_abs_deviation')

            if top_n.empty:
                log_message(f"No valid deviation data to determine top performers for {date_str}.")
                continue

            for index, row in top_n.iterrows():
                agg = row['agg_method']
                norm = row['norm_method']
                metric = row['metric_method']
                max_dev_val = row['max_abs_deviation']

                deviation_csv_name = get_dynamic_filename("deviations", agg, norm, metric, date_str=date_str)
                deviation_csv_path = os.path.join(DAILY_DEVIATIONS_DIR, deviation_csv_name)
                
                viz_filename = get_dynamic_filename(f"top_heatmap_dev_{date_str}", agg, norm, metric, extension="png")
                heatmap_output_path = os.path.join(top_heatmaps_output_dir, viz_filename)
                title = (f"Top Performer (MaxDev: {max_dev_val:.4f})\n"
                         f"{agg}/{norm}/{metric} on {date_str}")
                
                log_message(f"  Plotting Top Performer: {title.replace('\n', ' - ')}")
                generate_heatmap_for_file(deviation_csv_path, heatmap_output_path, title)
    else:
        log_message("Summary DataFrame is empty. Cannot determine top performers.")


    log_message(f"\n--- Focused visualization process complete ---")
    log_message(f"Processed {processed_files_count} deviation files for summary statistics.")
    log_message(f"Visualizations and summary saved in: {os.path.abspath(VISUALIZATIONS_DIR)}")

if __name__ == "__main__":
    if not os.path.isdir(DAILY_DEVIATIONS_DIR):
        print(f"ERROR: Daily deviations directory not found at '{os.path.abspath(DAILY_DEVIATIONS_DIR)}'. "
              "Please ensure your analysis output files (deviations_*.csv) exist there.")
    else:
        create_focused_visualizations()

    print(f"\nScript execution finished. Check '{MASTER_LOG_FILE}' for detailed output.")
    print(f"Visualizations and summary CSV should be in '{os.path.abspath(VISUALIZATIONS_DIR)}'")

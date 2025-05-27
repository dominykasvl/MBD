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
VISUALIZATIONS_DIR = "./pipeline_visualizations_analysis_only" 

MASTER_LOG_FILE = "visualization_only_output.log" 

# Dates for which analysis deviation plots will be generated
ANALYSIS_DATES = [
    "2025-03-06", "2025-03-07", "2025-03-08", "2025-03-09", "2025-03-10",
    "2025-03-11", "2025-03-12", "2025-03-13", "2025-03-14", "2025-03-15",
    "2025-03-16", "2025-03-17", "2025-03-18", "2025-03-19", "2025-03-20",
    "2025-03-21", "2025-03-22", "2025-03-23", "2025-03-24", "2025-03-25",
    "2025-03-26", "2025-03-27", "2025-03-28", "2025-03-29", "2025-03-30",
    "2025-03-31", "2025-04-01", "2025-04-02"
]

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
        f.write(f"Visualization script started at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_message("Master log file initialized for visualization script.")

def prepare_visualization_directory():
    """Creates necessary directories for visualizations if they don't exist."""
    # Main visualization directory
    if not os.path.exists(VISUALIZATIONS_DIR):
        os.makedirs(VISUALIZATIONS_DIR)
        log_message(f"Created directory: {VISUALIZATIONS_DIR}")
    
    # Subdirectory for analysis deviation plots
    analysis_viz_subdir = os.path.join(VISUALIZATIONS_DIR, "analysis_deviations_heatmaps")
    if not os.path.exists(analysis_viz_subdir):
        os.makedirs(analysis_viz_subdir)
        log_message(f"Created directory: {analysis_viz_subdir}")
    return analysis_viz_subdir


def get_dynamic_filename(base_name, agg_method, norm_method, metric_method, date_str=None, extension="csv"):
    """
    Helper to construct filenames consistent with how your main_pipeline.py saves them.
    Adjust this if your main_pipeline.py has a more complex naming scheme.
    """
    name_parts = [base_name]
    if agg_method: name_parts.append(f"agg-{agg_method}")
    if norm_method: name_parts.append(f"norm-{norm_method}")
    if metric_method: name_parts.append(f"metric-{metric_method}")
    if date_str: name_parts.append(date_str)
    return "_".join(name_parts) + "." + extension

def generate_heatmap(csv_file_path, output_image_path, title):
    """Generates and saves a heatmap from a CSV file."""
    try:
        if not os.path.exists(csv_file_path):
            log_message(f"VISUALIZATION_INFO: CSV file not found, skipping heatmap: {csv_file_path}")
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
            log_message(f"VISUALIZATION_INFO: DataFrame became empty or has no columns after numeric conversion, skipping heatmap: {csv_file_path}")
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

    except pd.errors.EmptyDataError:
        log_message(f"VISUALIZATION_ERROR: CSV file is empty or unreadable (EmptyDataError): {csv_file_path}")
    except Exception as e:
        log_message(f"VISUALIZATION_ERROR: Failed to generate heatmap for {csv_file_path}. Error: {e}")


# --- Main Execution Logic ---
def visualize_existing_analysis_data():
    """
    Iterates through method combinations and dates to generate heatmaps
    from existing analysis deviation CSV files.
    """
    initialize_master_log()
    analysis_viz_output_dir = prepare_visualization_directory() 

    log_message(f"Starting visualization of existing analysis deviation files.")
    log_message(f"Deviation CSVs expected in: {os.path.abspath(DAILY_DEVIATIONS_DIR)}")
    log_message(f"Heatmaps will be saved in subdirectories within: {os.path.abspath(analysis_viz_output_dir)}")
    
    plot_count = 0

    for agg_method in AGGREGATION_METHODS:
        for norm_method in NORMALIZATION_METHODS:
            for metric_method in METRIC_METHODS:
                
                # Create a subdirectory for this specific analysis combination's deviation plots
                analysis_combo_viz_dir_name = f"deviations_{agg_method}_{norm_method}_{metric_method}"
                current_combo_output_path = os.path.join(analysis_viz_output_dir, analysis_combo_viz_dir_name)
                if not os.path.exists(current_combo_output_path):
                    os.makedirs(current_combo_output_path)
                    log_message(f"Created subdirectory for plots: {current_combo_output_path}")

                log_message(f"\n--- Processing combination: {agg_method}/{norm_method}/{metric_method} ---")
                for analysis_date in ANALYSIS_DATES:
                    # Construct path to the daily deviation CSV file
                    deviation_csv_name = get_dynamic_filename(
                        base_name="deviations",
                        agg_method=agg_method,
                        norm_method=norm_method,
                        metric_method=metric_method,
                        date_str=analysis_date,
                        extension="csv"
                    )
                    deviation_csv_path = os.path.join(DAILY_DEVIATIONS_DIR, deviation_csv_name)
                    
                    # Define output path and title for the heatmap
                    viz_filename = get_dynamic_filename(
                        base_name=f"heatmap_dev_{analysis_date}", 
                        agg_method=agg_method,
                        norm_method=norm_method,
                        metric_method=metric_method,
                        extension="png"
                    )
                    heatmap_output_path = os.path.join(current_combo_output_path, viz_filename) 
                    heatmap_title = f"Deviations: {agg_method}/{norm_method}/{metric_method}\non {analysis_date}"
                    
                    generate_heatmap(deviation_csv_path, heatmap_output_path, heatmap_title)
                    plot_count +=1

    log_message(f"\n--- Visualization process complete ---")
    log_message(f"Attempted to generate {plot_count} heatmaps.")
    log_message(f"Visualizations saved in subdirectories within: {os.path.abspath(analysis_viz_output_dir)}")


if __name__ == "__main__":
    if not os.path.isdir(DAILY_DEVIATIONS_DIR):
        print(f"ERROR: Daily deviations directory not found at '{os.path.abspath(DAILY_DEVIATIONS_DIR)}'. Please ensure analysis output files exist.")
    else:
        visualize_existing_analysis_data()

    print(f"\nScript execution finished. Check '{MASTER_LOG_FILE}' for detailed output.")
    print(f"Visualizations should be in '{os.path.abspath(VISUALIZATIONS_DIR)}'")

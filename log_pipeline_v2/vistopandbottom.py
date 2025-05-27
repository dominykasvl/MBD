import os
import datetime
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# --- Configuration Section ---
AGGREGATION_METHODS = ['hourly_events', 'failed_logins', 'source_ip_hourly_events',
                       'src_dst_ip_hourly_events']
NORMALIZATION_METHODS = ['scaler', 'l2', 'minmax', 'none']
METRIC_METHODS = ['cosine', 'pearson', 'spearman', 'kendall', 'euclidean', 'manhattan']

PROCESSED_DATA_DIR = "./data/processed"
DAILY_DEVIATIONS_DIR = os.path.join(PROCESSED_DATA_DIR, "daily_deviations")
VISUALIZATIONS_DIR = "./pipeline_visualizations_daily_performance" 

MASTER_LOG_FILE = "daily_performance_visualization.log"

ANALYSIS_DATES = [
    "2025-03-06", "2025-03-07", "2025-03-08", "2025-03-09", "2025-03-10",
    "2025-03-11", "2025-03-12", "2025-03-13", "2025-03-14", "2025-03-15",
    "2025-03-16", "2025-03-17", "2025-03-18", "2025-03-19", "2025-03-20",
    "2025-03-21", "2025-03-22", "2025-03-23", "2025-03-24", "2025-03-25",
    "2025-03-26", "2025-03-27", "2025-03-28", "2025-03-29", "2025-03-30",
    "2025-03-31", "2025-04-01", "2025-04-02"
]

DAILY_TOP_N_TO_PLOT = 3
DAILY_BOTTOM_N_TO_PLOT = 3



def log_message(message):
    """Appends a message to the master log file and prints it."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    print(full_message)
    with open(MASTER_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(full_message + "\n")

def initialize_master_log():
    """Creates or clears the master log file for this script's execution."""
    with open(MASTER_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"Daily Top/Bottom Performance Visualization script started at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_message("Master log file initialized for daily performance visualization.")

def prepare_visualization_directory():
    """Creates necessary directories for output files if they don't exist."""
    if not os.path.exists(VISUALIZATIONS_DIR):
        os.makedirs(VISUALIZATIONS_DIR)
        log_message(f"Created main visualization directory: {VISUALIZATIONS_DIR}")
    
    summary_dir = os.path.join(VISUALIZATIONS_DIR, "summary_tables")
    if not os.path.exists(summary_dir): os.makedirs(summary_dir)
    
    trend_plots_dir = os.path.join(VISUALIZATIONS_DIR, "trend_plots_by_aggregation")
    if not os.path.exists(trend_plots_dir): os.makedirs(trend_plots_dir)

    daily_perf_graphs_dir = os.path.join(VISUALIZATIONS_DIR, "daily_top_bottom_performance_graphs")
    if not os.path.exists(daily_perf_graphs_dir): os.makedirs(daily_perf_graphs_dir)
    
    return summary_dir, trend_plots_dir, daily_perf_graphs_dir

def get_dynamic_filename(base_name, agg_method, norm_method, metric_method, date_str=None, extension="csv"):
    """Constructs filenames consistent with the pipeline's output."""
    name_parts = [base_name]
    if agg_method: name_parts.append(f"agg-{agg_method}")
    if norm_method: name_parts.append(f"norm-{norm_method}")
    if metric_method: name_parts.append(f"metric-{metric_method}")
    if date_str: name_parts.append(date_str)
    return "_".join(name_parts) + "." + extension

def calculate_max_abs_deviation_with_entities(csv_file_path):
    """
    Loads a deviation CSV and calculates the maximum absolute deviation value
    and the pair of entities that produced it.
    """
    try:
        if not os.path.exists(csv_file_path):
            return None, "N/A (file not found)", "N/A (file not found)"

        df = pd.read_csv(csv_file_path)
        if df.empty:
            return 0.0, "N/A (empty file)", "N/A (empty file)"

        df_indexed = df.copy()
        first_col_name = df.columns[0]
        if first_col_name == 'hostname' or \
           (df.shape[0] > 0 and isinstance(df.iloc[0,0], str) and not str(df.iloc[0,0]).isnumeric()):
            df_indexed = df.set_index(first_col_name)
        elif 'Unnamed: 0' in df.columns and \
             (df.shape[0] > 0 and isinstance(df['Unnamed: 0'].iloc[0], str) and not str(df['Unnamed: 0'].iloc[0]).isnumeric()):
             df_indexed = df.set_index('Unnamed: 0')

        df_numeric_abs = df_indexed.apply(pd.to_numeric, errors='coerce').fillna(0).abs()
        
        if df_numeric_abs.empty or df_numeric_abs.shape[0] == 0 or df_numeric_abs.shape[1] == 0:
            return 0.0, "N/A (no numeric data)", "N/A (no numeric data)"
            
        max_val = df_numeric_abs.stack().max() 
        
        if pd.isna(max_val) or max_val == -np.inf or max_val == np.inf: 
            max_val = 0.0

        entity1, entity2 = "N/A", "N/A"
        if max_val == 0.0:
            entity1, entity2 = "N/A (all zero/NaN)", "N/A (all zero/NaN)"
        else:
            try:
                row_label, col_label = df_numeric_abs.stack().idxmax()
                entity1 = str(row_label)
                entity2 = str(col_label)
            except ValueError: 
                log_message(f"INFO: Could not determine entities for max_val {max_val} in {csv_file_path}.")
                entity1, entity2 = "N/A (idxmax error)", "N/A (idxmax error)"
        
        return max_val, entity1, entity2
    except pd.errors.EmptyDataError: 
        return 0.0, "N/A (empty file pd_error)", "N/A (empty file pd_error)"
    except Exception as e:
        log_message(f"ERROR: Could not calculate max_abs_deviation_with_entities for {csv_file_path}. Error: {e}")
        return None, "N/A (exception)", "N/A (exception)"

# --- Main Execution Logic ---
def visualize_daily_top_bottom_performance():
    """
    Generates a summary CSV of max deviations and daily bar charts 
    highlighting top/bottom N performing methods.
    """
    initialize_master_log()
    summary_output_dir, trend_plots_output_dir, daily_perf_graphs_dir = prepare_visualization_directory()

    log_message("Starting visualization of max deviations and daily top/bottom performers.")
    log_message(f"Deviation CSVs expected in: {os.path.abspath(DAILY_DEVIATIONS_DIR)}")
    
    all_deviations_data = []
    processed_files_count = 0

    for agg_method in AGGREGATION_METHODS:
        for norm_method in NORMALIZATION_METHODS:
            for metric_method in METRIC_METHODS:
                for date_str in ANALYSIS_DATES:
                    deviation_csv_name = get_dynamic_filename(
                        "deviations", agg_method, norm_method, metric_method, date_str=date_str
                    )
                    deviation_csv_path = os.path.join(DAILY_DEVIATIONS_DIR, deviation_csv_name)
                    
                    max_abs_dev, entity1, entity2 = calculate_max_abs_deviation_with_entities(deviation_csv_path)
                    processed_files_count += 1
                    
                    if max_abs_dev is not None: 
                        all_deviations_data.append({
                            "date": date_str, 
                            "agg_method": agg_method, 
                            "norm_method": norm_method,
                            "metric_method": metric_method, 
                            "max_abs_deviation": max_abs_dev,
                            "entity1_max_dev": entity1, 
                            "entity2_max_dev": entity2
                        })
                    else:
                        all_deviations_data.append({
                            "date": date_str, "agg_method": agg_method, "norm_method": norm_method,
                            "metric_method": metric_method, "max_abs_deviation": np.nan,
                            "entity1_max_dev": "Error/Not Found", "entity2_max_dev": "Error/Not Found"
                        })

    summary_df = pd.DataFrame(all_deviations_data)
    summary_df['date_dt'] = pd.to_datetime(summary_df['date']) 
    summary_df.sort_values(by=['date_dt', 'agg_method', 'norm_method', 'metric_method'], inplace=True)
    summary_df.drop(columns=['date_dt'], inplace=True)
    
    summary_csv_path = os.path.join(summary_output_dir, "all_dates_max_deviation_summary.csv")
    try:
        summary_df.to_csv(summary_csv_path, index=False, float_format='%.6f')
        log_message(f"\nComprehensive summary of max absolute deviations saved to: {summary_csv_path}")
    except Exception as e:
        log_message(f"ERROR: Could not save comprehensive summary CSV. Error: {e}")

    log_message(f"\n--- Generating Trend Plots for Max Deviations by Aggregation Method ---")
    if not summary_df.empty:
        summary_df_trends = summary_df.copy()
        summary_df_trends['date'] = pd.to_datetime(summary_df_trends['date']) 

        for agg_method in AGGREGATION_METHODS:
            plt.figure(figsize=(20, 10))
            agg_df = summary_df_trends[summary_df_trends['agg_method'] == agg_method].copy()
            if agg_df.empty:
                log_message(f"No data for aggregation method {agg_method} to plot trends.")
                plt.close(); continue
            
            agg_df['method_combination'] = agg_df['norm_method'] + "_" + agg_df['metric_method']
            agg_df['max_abs_deviation'] = pd.to_numeric(agg_df['max_abs_deviation'], errors='coerce')

            sns.lineplot(data=agg_df, x='date', y='max_abs_deviation', hue='method_combination', 
                         style='norm_method', markers=True, dashes=False, ci=None) 
            plt.title(f"Max Absolute Deviation Trend for Aggregation: {agg_method}", fontsize=18)
            plt.xlabel("Date", fontsize=14); plt.ylabel("Maximum Absolute Deviation Score", fontsize=14)
            plt.xticks(rotation=45, ha='right', fontsize=10)
            plt.yticks(fontsize=10)
            plt.legend(title="Norm_Metric Combo", bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0., fontsize=8)
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.tight_layout(rect=[0, 0, 0.80, 1]) 
            
            plot_filename = f"max_dev_trend_agg_{agg_method}.png"
            plot_output_path = os.path.join(trend_plots_output_dir, plot_filename)
            try: 
                plt.savefig(plot_output_path)
                log_message(f"Saved trend plot: {plot_output_path}")
            except Exception as e: 
                log_message(f"ERROR: Could not save plot {plot_output_path}. Error: {e}")
            plt.close()
    else:
        log_message("Summary DataFrame is empty. Cannot generate trend plots.")

    log_message(f"\n--- Generating Daily Top/Bottom Performer Bar Charts ---")
    if not summary_df.empty:
        summary_df['max_abs_deviation'] = pd.to_numeric(summary_df['max_abs_deviation'], errors='coerce')
        valid_summary_df = summary_df.dropna(subset=['max_abs_deviation']) 
        valid_summary_df = valid_summary_df[~valid_summary_df['entity1_max_dev'].astype(str).str.contains("Error|N/A", na=False)]


        for date_str in ANALYSIS_DATES:
            daily_df = valid_summary_df[valid_summary_df['date'] == date_str].copy()
            if daily_df.empty:
                log_message(f"No valid data for date {date_str} to plot daily top/bottom performers.")
                continue

            daily_df['method_label'] = daily_df['agg_method'] + '/' + daily_df['norm_method'] + '/' + daily_df['metric_method']
            
            top_n = daily_df.nlargest(DAILY_TOP_N_TO_PLOT, 'max_abs_deviation')
            bottom_n_candidates = daily_df[daily_df['max_abs_deviation'] > 1e-9] 
            bottom_n = bottom_n_candidates.nsmallest(DAILY_BOTTOM_N_TO_PLOT, 'max_abs_deviation')
            
            combined_df = pd.concat([top_n, bottom_n]).drop_duplicates().sort_values('max_abs_deviation', ascending=False)

            if combined_df.empty:
                log_message(f"No top/bottom performers to plot for {date_str} after filtering.")
                continue

            plt.figure(figsize=(16, max(8, len(combined_df) * 0.8))) 
            
            colors = []
            for idx, row in combined_df.iterrows():
                is_top = any((top_n['method_label'] == row['method_label']) & (top_n['max_abs_deviation'] == row['max_abs_deviation']))
                colors.append("skyblue" if is_top else "lightcoral")

            barplot = sns.barplot(data=combined_df, x='max_abs_deviation', y='method_label', palette=colors, orient='h')
            plt.title(f"Top {DAILY_TOP_N_TO_PLOT} & Bottom {DAILY_BOTTOM_N_TO_PLOT} Max Absolute Deviations for {date_str}", fontsize=16)
            plt.xlabel("Maximum Absolute Deviation Score", fontsize=12)
            plt.ylabel("Method Combination (Agg/Norm/Metric)", fontsize=12)
            plt.yticks(fontsize=9)
            plt.xticks(fontsize=9)
            plt.grid(axis='x', linestyle='--', alpha=0.7)
            
            for i in barplot.patches:
                plt.text(i.get_width() + (0.01 * combined_df['max_abs_deviation'].max()),
                         i.get_y() + i.get_height() / 2, 
                         f'{i.get_width():.4f}', 
                         fontsize=8, color='black', ha='left', va='center')

            plt.tight_layout(pad=1.5)
            plot_filename = f"daily_performance_chart_{date_str}.png"
            plot_output_path = os.path.join(daily_perf_graphs_dir, plot_filename)
            try:
                plt.savefig(plot_output_path)
                log_message(f"Saved daily performance chart: {plot_output_path}")
            except Exception as e:
                log_message(f"ERROR: Could not save daily performance chart {plot_output_path}. Error: {e}")
            plt.close()
    else:
        log_message("Summary DataFrame is empty. Cannot generate daily performance charts.")


    log_message(f"\n--- Overall Max Deviation Visualization process complete ---")
    log_message(f"Processed {processed_files_count} deviation files for summary statistics.")
    log_message(f"Visualizations and summary saved in: {os.path.abspath(VISUALIZATIONS_DIR)}")

if __name__ == "__main__":
    if not os.path.isdir(DAILY_DEVIATIONS_DIR):
        print(f"ERROR: Daily deviations directory not found at '{os.path.abspath(DAILY_DEVIATIONS_DIR)}'. "
              "Please ensure your analysis output files (deviations_*.csv) exist there.")
    else:
        visualize_daily_top_bottom_performance()

    print(f"\nScript execution finished. Check '{MASTER_LOG_FILE}' for detailed output.")
    print(f"Visualizations and summary CSV should be in '{os.path.abspath(VISUALIZATIONS_DIR)}'")


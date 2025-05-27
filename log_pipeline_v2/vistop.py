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
VISUALIZATIONS_DIR = "./pipeline_visualizations_overall_max_deviations"

MASTER_LOG_FILE = "overall_max_deviation_visualization.log"

ANALYSIS_DATES = [
    "2025-03-06", "2025-03-07", "2025-03-08", "2025-03-09", "2025-03-10",
    "2025-03-11", "2025-03-12", "2025-03-13", "2025-03-14", "2025-03-15",
    "2025-03-16", "2025-03-17", "2025-03-18", "2025-03-19", "2025-03-20",
    "2025-03-21", "2025-03-22", "2025-03-23", "2025-03-24", "2025-03-25",
    "2025-03-26", "2025-03-27", "2025-03-28", "2025-03-29", "2025-03-30",
    "2025-03-31", "2025-04-01", "2025-04-02"
]

def log_message(message):
    """Logs a message with a timestamp to console and a master log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    print(full_message)
    with open(MASTER_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(full_message + "\n")

def initialize_master_log():
    """Initializes the master log file."""
    with open(MASTER_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"Overall Max Deviation Visualization script started at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_message("Master log file initialized.")

def prepare_visualization_directory():
    """Creates directories for storing visualizations and summary tables if they don't exist."""
    if not os.path.exists(VISUALIZATIONS_DIR):
        os.makedirs(VISUALIZATIONS_DIR)
        log_message(f"Created main visualization directory: {VISUALIZATIONS_DIR}")
    
    summary_dir = os.path.join(VISUALIZATIONS_DIR, "summary_tables")
    if not os.path.exists(summary_dir):
        os.makedirs(summary_dir)
    plots_dir = os.path.join(VISUALIZATIONS_DIR, "trend_plots_by_aggregation")
    if not os.path.exists(plots_dir):
        os.makedirs(plots_dir)
    return summary_dir, plots_dir

def get_dynamic_filename(base_name, agg_method, norm_method, metric_method, date_str=None, extension="csv"):
    """Generates a dynamic filename based on provided parameters."""
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
            log_message(f"INFO: Deviation file not found: {csv_file_path}")
            return None, None, None

        df = pd.read_csv(csv_file_path)
        if df.empty:
            log_message(f"INFO: Deviation file is empty: {csv_file_path}")
            return 0.0, "N/A (empty file)", "N/A (empty file)"

        df_indexed = df.copy()
        first_col_name = df.columns[0]

        if first_col_name == 'hostname' or \
           (df.shape[0] > 0 and isinstance(df.iloc[0,0], str) and not str(df.iloc[0,0]).isnumeric()):
            df_indexed = df.set_index(first_col_name)
        elif 'Unnamed: 0' in df.columns and \
             (df.shape[0] > 0 and isinstance(df.iloc[0,0], str) and not str(df.iloc[0,0]).isnumeric()):
             if isinstance(df['Unnamed: 0'].iloc[0], str):
                df_indexed = df.set_index('Unnamed: 0')
        
        df_numeric = df_indexed.select_dtypes(include=np.number)
        df_numeric_abs = df_numeric.abs()
        
        if df_numeric_abs.empty or df_numeric_abs.shape[0] == 0 or df_numeric_abs.shape[1] == 0:
            log_message(f"INFO: Numeric deviation data is empty after processing: {csv_file_path}")
            return 0.0, "N/A (no numeric data)", "N/A (no numeric data)"
            
        max_val = df_numeric_abs.stack().max() 
        
        if pd.isna(max_val) or max_val == -np.inf or max_val == np.inf : 
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
        log_message(f"INFO: Deviation file is empty (pd.errors.EmptyDataError): {csv_file_path}")
        return 0.0, "N/A (empty file)", "N/A (empty file)"
    except Exception as e:
        log_message(f"ERROR: Could not calculate max_abs_deviation_with_entities for {csv_file_path}. Error: {e}")
        return None, None, None

# --- Main Execution Logic ---
def visualize_all_dates_max_deviations():
    """
    Main function to process deviation files, calculate max deviations, save summary, and generate trend plots
    in multiple languages.
    """
    initialize_master_log()
    summary_output_dir, plots_output_dir = prepare_visualization_directory()

    log_message("Starting visualization of max deviations across all analysis dates.")
    log_message(f"Deviation CSVs expected in: {os.path.abspath(DAILY_DEVIATIONS_DIR)}")
    
    all_deviations_data = []
    processed_files_count = 0

    for agg_method in AGGREGATION_METHODS:
        for norm_method in NORMALIZATION_METHODS:
            for metric_method in METRIC_METHODS:
                log_message(f"\n--- Processing combination: {agg_method}/{norm_method}/{metric_method} ---")
                for date_str in ANALYSIS_DATES:
                    deviation_csv_name = get_dynamic_filename(
                        "deviations", agg_method, norm_method, metric_method, date_str=date_str
                    )
                    deviation_csv_path = os.path.join(DAILY_DEVIATIONS_DIR, deviation_csv_name)
                    
                    max_abs_dev, entity1, entity2 = calculate_max_abs_deviation_with_entities(deviation_csv_path)
                    processed_files_count += 1
                    
                    if max_abs_dev is not None: 
                        all_deviations_data.append({
                            "date": date_str, "agg_method": agg_method, "norm_method": norm_method,
                            "metric_method": metric_method, "max_abs_deviation": max_abs_dev,
                            "entity1_max_dev": entity1, "entity2_max_dev": entity2
                        })
                        if max_abs_dev > 0: 
                             log_message(f"  Date: {date_str}, MaxAbsDev: {max_abs_dev:.4f}, Entities: ({entity1}, {entity2})")
                    else: 
                        log_message(f"  Date: {date_str}, MaxAbsDev: Error/Not Found")
                        all_deviations_data.append({
                            "date": date_str, "agg_method": agg_method, "norm_method": norm_method,
                            "metric_method": metric_method, "max_abs_deviation": np.nan,
                            "entity1_max_dev": "Error", "entity2_max_dev": "Error"
                        })

    summary_df = pd.DataFrame(all_deviations_data)
    if not summary_df.empty:
        summary_df['date'] = pd.to_datetime(summary_df['date']) 
        summary_df.sort_values(by=['date', 'agg_method', 'norm_method', 'metric_method'], inplace=True)
        summary_csv_path = os.path.join(summary_output_dir, "all_dates_max_deviation_summary.csv")
        try:
            summary_df.to_csv(summary_csv_path, index=False, float_format='%.6f')
            log_message(f"\nComprehensive summary of max absolute deviations saved to: {summary_csv_path}")
        except Exception as e:
            log_message(f"ERROR: Could not save comprehensive summary CSV. Error: {e}")
    else:
        log_message("WARNING: Summary DataFrame is empty. No data was processed or found.")

    log_message(f"\n--- Generating Trend Plots for Max Deviations by Aggregation Method ---")
    if not summary_df.empty:
        line_styles = ["-", "--", "-.", ":"] 
        markers = ["o", "s", "X", "D", "^", "v"] 
        
        for agg_method in AGGREGATION_METHODS:
            plt.figure(figsize=(20, 12)) 
            
            agg_df = summary_df[summary_df['agg_method'] == agg_method].copy()
            
            if agg_df.empty or agg_df['max_abs_deviation'].isnull().all():
                log_message(f"No plottable data for aggregation method {agg_method}.")
                plt.close() 
                continue

            unique_norm_methods_in_plot = sorted(agg_df['norm_method'].dropna().unique())
            unique_metric_methods_in_plot = sorted(agg_df['metric_method'].dropna().unique())

            if not unique_norm_methods_in_plot or not unique_metric_methods_in_plot:
                log_message(f"Not enough unique norm/metric methods with data for {agg_method} to plot.")
                plt.close()
                continue
                
            palette = sns.color_palette("husl", n_colors=len(unique_norm_methods_in_plot))
            
            collected_legend_handles = []
            collected_legend_labels = []
            
            for i, norm_method_val in enumerate(unique_norm_methods_in_plot):
                norm_df = agg_df[agg_df['norm_method'] == norm_method_val]
                if norm_df.empty:
                    continue
                for j, metric_method_val in enumerate(unique_metric_methods_in_plot):
                    metric_df = norm_df[norm_df['metric_method'] == metric_method_val]
                    
                    # Critical check: only plot if there's actual data
                    if metric_df.empty or metric_df['max_abs_deviation'].isnull().all():
                        continue 
                    
                    plot_label = f"{norm_method_val}_{metric_method_val}"
                    
                    sns.lineplot(
                        data=metric_df, 
                        x='date', 
                        y='max_abs_deviation', 
                        label=plot_label, 
                        marker=markers[j % len(markers)],
                        markersize=10, 
                        linestyle=line_styles[j % len(line_styles)],
                        color=palette[i % len(palette)], 
                        linewidth=1.5 + (j * 0.1),
                        ci=None
                    )

            ax = plt.gca()
            handles, labels = ax.get_legend_handles_labels()
            
            unique_labels_map = dict(zip(labels, handles))
            collected_legend_labels = list(unique_labels_map.keys())
            collected_legend_handles = list(unique_labels_map.values())


            if not collected_legend_handles:
                log_message(f"No legend items to display for aggregation method {agg_method} after plotting attempts.")
                plt.close()
                continue

            languages = {
                "en": {
                    "title": f"Max Absolute Deviation Trend for Aggregation: {agg_method}",
                    "xlabel": "Date",
                    "ylabel": "Maximum Absolute Deviation Score",
                    "legend_title": "Norm_Metric",
                    "file_suffix": "_en"
                },
                "lt": {
                    "title": f"Maksimalaus absoliutaus nuokrypio tendencija agregavimui: {agg_method.replace('_', ' ')}", 
                    "xlabel": "Data",
                    "ylabel": "Maksimalaus absoliutaus nuokrypio balas",
                    "legend_title": "Norm_Metrika",
                    "file_suffix": "_lt"
                }
            }

            for lang_code, lang_texts in languages.items():
                plt.title(lang_texts["title"], fontsize=20, pad=20)
                plt.xlabel(lang_texts["xlabel"], fontsize=16, labelpad=15)
                plt.ylabel(lang_texts["ylabel"], fontsize=16, labelpad=15)
                
                plt.xticks(rotation=45, ha='right', fontsize=12) 
                plt.yticks(fontsize=12) 
                plt.grid(True, linestyle='--', alpha=0.7) 

                if collected_legend_handles:
                    num_legend_items = len(collected_legend_labels)
                    legend_cols = 1
                    if num_legend_items > 12: legend_cols = 2
                    if num_legend_items > 24: legend_cols = 3

                    ax.legend(handles=collected_legend_handles, labels=collected_legend_labels, 
                              title=lang_texts["legend_title"], 
                              bbox_to_anchor=(1.02, 1), loc='upper left', 
                              borderaxespad=0., fontsize=9, title_fontsize=11, 
                              ncol=legend_cols)
                    
                    right_margin = 0.83
                    if legend_cols == 2: right_margin = 0.78
                    if legend_cols == 3: right_margin = 0.70
                    plt.tight_layout(rect=[0, 0, right_margin, 0.96]) 
                else:
                    plt.tight_layout(rect=[0,0,0.95,0.96]) 

                plot_filename = f"max_dev_trend_agg_{agg_method}{lang_texts['file_suffix']}.png"
                plot_output_path = os.path.join(plots_output_dir, plot_filename)
                try:
                    plt.savefig(plot_output_path, bbox_inches='tight') 
                    log_message(f"Saved trend plot: {plot_output_path}")
                except Exception as e:
                    log_message(f"ERROR: Could not save plot {plot_output_path}. Error: {e}")
            
            plt.close() 
    else:
        log_message("Summary DataFrame is empty. Cannot generate trend plots.")

    log_message(f"\n--- Overall Max Deviation Visualization process complete ---")
    log_message(f"Processed {processed_files_count} deviation files for summary statistics.")
    log_message(f"Visualizations and summary saved in: {os.path.abspath(VISUALIZATIONS_DIR)}")

if __name__ == "__main__":
    if not os.path.isdir(DAILY_DEVIATIONS_DIR):
        print(f"ERROR: Daily deviations directory not found at '{os.path.abspath(DAILY_DEVIATIONS_DIR)}'. "
              "Please ensure your analysis output files (deviations_*.csv) exist there.")
    else:
        visualize_all_dates_max_deviations()

    print(f"\nScript execution finished. Check '{MASTER_LOG_FILE}' for detailed output.")
    print(f"Visualizations and summary CSV should be in '{os.path.abspath(VISUALIZATIONS_DIR)}'")

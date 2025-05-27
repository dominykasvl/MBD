import pandas as pd
from sklearn.preprocessing import StandardScaler, normalize, MinMaxScaler
import numpy as np 

def normalize_activity_matrix_standardscaler(host_activity_df):
    """
    Normalizes the host activity matrix using StandardScaler (row-wise).
    """
    if host_activity_df.empty:
        print("Input DataFrame for StandardScaler normalization is empty.")
        return pd.DataFrame()

    if host_activity_df.shape[1] < 2:
        print(f"Warning: StandardScaler requires >= 2 time points. Returning zeros.")
        return pd.DataFrame(0, index=host_activity_df.index, columns=host_activity_df.columns)

    scaler = StandardScaler()
    scaled_data = []
    for index, row in host_activity_df.iterrows():
        row_values = row.values
        row_reshaped = row_values.reshape(-1, 1)
        if np.all(row_values == row_values[0]):
            scaled_row_flattened = np.zeros_like(row_values, dtype=float)
        else:
            scaled_row = scaler.fit_transform(row_reshaped)
            scaled_row_flattened = scaled_row.flatten()
        scaled_data.append(scaled_row_flattened)

    normalized_df = pd.DataFrame(scaled_data, index=host_activity_df.index, columns=host_activity_df.columns)
    return normalized_df

def normalize_activity_matrix_l2(host_activity_df):
    """
    Normalizes the host activity matrix using L2 normalization (row-wise).
    """
    if host_activity_df.empty:
        print("Input DataFrame for L2 normalization is empty.")
        return pd.DataFrame()

    l2_normalized_data = normalize(host_activity_df, norm='l2', axis=1)
    normalized_df = pd.DataFrame(l2_normalized_data, 
                                 index=host_activity_df.index, 
                                 columns=host_activity_df.columns)
    return normalized_df

def normalize_activity_matrix_minmax(host_activity_df):
    """
    Normalizes the host activity matrix using MinMaxScaler (row-wise).
    Scales each host's activity to the range [0, 1].
    """
    if host_activity_df.empty:
        print("Input DataFrame for MinMax normalization is empty.")
        return pd.DataFrame()

    scaler = MinMaxScaler()
    scaled_data = []
    for index, row in host_activity_df.iterrows():
        row_values = row.values
        row_reshaped = row_values.reshape(-1, 1)
        
        # Check if all values are the same (range is zero)
        if np.all(row_values == row_values[0]):
            scaled_row_flattened = np.zeros_like(row_values, dtype=float)
        else:
            scaled_row = scaler.fit_transform(row_reshaped)
            scaled_row_flattened = scaled_row.flatten()
            
        scaled_data.append(scaled_row_flattened)

    normalized_df = pd.DataFrame(scaled_data, index=host_activity_df.index, columns=host_activity_df.columns)
    return normalized_df

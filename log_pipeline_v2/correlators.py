import pandas as pd
from sklearn.metrics.pairwise import cosine_similarity, euclidean_distances, manhattan_distances
from scipy.stats import pearsonr, spearmanr, kendalltau

def calculate_host_cosine_similarity(normalized_activity_df):
    """
    Calculates the pairwise cosine similarity between hosts based on their
    normalized activity vectors.
    """
    if normalized_activity_df.empty:
        print("Input DataFrame for cosine similarity is empty.")
        return pd.DataFrame()
        
    if normalized_activity_df.isnull().values.any():
        print("Warning: Normalized activity data for cosine similarity contains NaNs. Filling with 0.")
        normalized_activity_df = normalized_activity_df.fillna(0)

    similarity_matrix = cosine_similarity(normalized_activity_df)
    
    similarity_df = pd.DataFrame(
        similarity_matrix,
        index=normalized_activity_df.index,
        columns=normalized_activity_df.index
    )
    return similarity_df

def calculate_host_euclidean_distance_matrix(activity_df_or_normalized_df):
    """
    Calculates the pairwise Euclidean distance between hosts based on their
    activity vectors (can be raw or normalized).
    """
    if activity_df_or_normalized_df.empty:
        print("Input DataFrame for Euclidean distance is empty.")
        return pd.DataFrame()
        
    if activity_df_or_normalized_df.isnull().values.any():
        print("Warning: Activity data for Euclidean distance contains NaNs. Filling with 0.")
        activity_df_or_normalized_df = activity_df_or_normalized_df.fillna(0)

    distance_matrix = euclidean_distances(activity_df_or_normalized_df)
    
    distance_df = pd.DataFrame(
        distance_matrix,
        index=activity_df_or_normalized_df.index,
        columns=activity_df_or_normalized_df.index
    )
    return distance_df

def calculate_host_manhattan_distance_matrix(activity_df_or_normalized_df):
    """
    Calculates the pairwise Manhattan (L1) distance between hosts based on their
    activity vectors (can be raw or normalized).
    """
    if activity_df_or_normalized_df.empty:
        print("Input DataFrame for Manhattan distance is empty.")
        return pd.DataFrame()
        
    if activity_df_or_normalized_df.isnull().values.any():
        print("Warning: Activity data for Manhattan distance contains NaNs. Filling with 0.")
        activity_df_or_normalized_df = activity_df_or_normalized_df.fillna(0)

    # Calculate Manhattan distances
    distance_matrix = manhattan_distances(activity_df_or_normalized_df)
    
    distance_df = pd.DataFrame(
        distance_matrix,
        index=activity_df_or_normalized_df.index,
        columns=activity_df_or_normalized_df.index
    )
    return distance_df

def calculate_rank_correlation(activity_df, method='pearson'):
    """
    Calculates pairwise correlation (Pearson, Spearman, or Kendall) between hosts.
    Note: Pandas .corr() calculates column-wise correlation. We need row-wise.
    So we transpose the DataFrame.
    """
    if activity_df.empty:
        print(f"Input DataFrame for {method} correlation is empty.")
        return pd.DataFrame()
        
    if activity_df.isnull().values.any():
        print(f"Warning: Activity data for {method} correlation contains NaNs. Filling with 0.")
        activity_df = activity_df.fillna(0)
        
    # Transpose so hosts become columns for pandas .corr()
    activity_df_t = activity_df.transpose()
    
    # Calculate correlation matrix
    # Pandas handles cases where variance is zero by returning NaN
    correlation_matrix = activity_df_t.corr(method=method)
    
    return correlation_matrix

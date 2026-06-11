import pandas as pd

SELECTED_FEATURES = ['ContentRating', 'LastUpdated', 'days_since_last_update', 'highest_android_version', 'privacy_policy_link', 'TwoStarRatings', 'CurrentVersion', 'isSpamming', 'max_downloads_log', 'OneStarRatings', 'FourStarRatings', 'ThreeStarRatings', 'lowest_android_version', 'STORAGE', 'FiveStarRatings', 'LenWhatsNew', 'AndroidVersion', 'developer_address', 'developer_website', 'intent', 'PHONE', 'LOCATION', 'DeveloperCategory', 'ReviewsAverage', 'Genre']
data = pd.read_csv('/shared/evanroot/manifests_dir/paper_replication/corrected_permacts.csv')
my_data = data[SELECTED_FEATURES]
print(my_data.shape)
print(my_data[:10])
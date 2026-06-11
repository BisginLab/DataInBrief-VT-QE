import csv
from pathlib import Path
from random import sample

import json
from pprint import pprint

import matplotlib.pyplot as plt

PAST_DATA_PATH = '/shared/henrysfiles/Android-Data/virustotal_results.csv'
api_json_files = list(Path('/shared/frankzha/data/json_reports').glob('eapks*/*.json'))

hash2malicious = {}
for f in api_json_files:
    r = f.read_text()
    stats_idx = r.find('}{"stats"') + 1
    stats = json.loads(r[stats_idx:])['stats']
    hash2malicious[f.name] = stats['suspicious'] + stats['malicious']

past_malicious_nums = []
curr_malicious_nums = []

found = 0
diff = 0
n = 0
with open(PAST_DATA_PATH, 'r') as f:
    reader = csv.reader((line.replace('\0','') for line in f), delimiter=",")
    for row in reader:
        n += 1
        if not row:
            continue
        hash_name = f'{row[1]}.json'
        curr_malicious_n = hash2malicious.get(hash_name)
        if curr_malicious_n is None:
            continue
        found += 1
        past_malicious_n = int(row[-2]) + int(row[-6])
        diff += (past_malicious_n != curr_malicious_n)
        
        curr_malicious_nums.append(curr_malicious_n)
        past_malicious_nums.append(past_malicious_n)
        
print(f'{found} applications were compared')
print(diff)
print(f'n: {n}')



def visualize_result_comparison(threshold: int = 1):
    fig, ax = plt.subplots(figsize=(7.8, 10))
    
    past_harmful_n = past_benign_n = 0
    curr_harmful_n = curr_benign_n = 0
    for p_n, c_n in zip(past_malicious_nums, curr_malicious_nums):
        if p_n >= threshold:
            past_harmful_n += 1
        else:
            past_benign_n += 1
        
        if c_n >= threshold:
            curr_harmful_n += 1
        else:
            curr_benign_n += 1        

    # Define the categories and values
    categories = ['Benign', 'Malicious']
    values_first = [past_benign_n, curr_benign_n]
    values_second = [past_harmful_n, curr_harmful_n]

    # Plot the side-by-side bars
    fig, ax = plt.subplots()

    # Bar width
    bar_width = 0.4

    # Positions of the bars
    x = range(len(categories))

    # Create the side-by-side bar plot
    bars1 = ax.bar([pos - bar_width / 2 for pos in x], values_first, width=bar_width, label='First', color='skyblue')
    bars2 = ax.bar([pos + bar_width / 2 for pos in x], values_second, width=bar_width, label='Second', color='lightgreen')

    for bar, label in zip(bars1, ['Past']*2):
        ax.text(bar.get_x() + bar.get_width() / 2, 1, label, ha='center')
    for bar, label in zip(bars2, ['Current']*2):
        ax.text(bar.get_x() + bar.get_width() / 2, 1, label, ha='center')
        
    for bar, value in zip(bars1, [past_benign_n, curr_benign_n]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, str(value), ha='center')
    for bar, value in zip(bars2, [past_harmful_n, curr_harmful_n]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, str(value), ha='center')
        
    # Add labels, title, and legend
    ax.set_xticks(x)
    ax.set_xticklabels(categories)    
    ax.set_title(f'Past vs. Current Scan Reports (t = {threshold})',
                 fontsize=16)
    ax.set_xlabel('Types of Applications', fontsize=14)
    ax.set_ylabel('Number of Applications', fontsize=14)
    

    # Adjust y-axis limits to accommodate labels below the bars
    ax.set_ylim(-1, n + 1)

    plt.tight_layout()
    plt.savefig(f'comparison (t = {threshold}).png', dpi=300)
    plt.close()


visualize_result_comparison(1)
for t in range(5, 51, 5):
    visualize_result_comparison(t)
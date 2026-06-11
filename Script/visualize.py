from pathlib import Path
from random import sample

import json
from pprint import pprint

import matplotlib.pyplot as plt

api_json_files = list(Path('/shared/frankzha/data/json_reports').glob('eapks*/*.json'))

undetected = []
harmless = []
harmful = []
# random_sample = sample(api_json_files, 4e5)
for f in api_json_files:
    r = f.read_text()
    stats_idx = r.find('}{"stats"') + 1
    stats = json.loads(r[stats_idx:])['stats']
    
    undetected.append(stats['undetected'])
    harmless.append(stats['harmless'])
    harmful.append(stats['suspicious'] + stats['malicious'])
    
print('harmless count:', sum(harmless))  # This turns out to be 0!
print('harmful count:', sum(harmful))
print('# of harmful apps:', sum(bool(d) for d in harmful))
# Print the ratio of undetected vs. detected apps
print('detected ratio:', sum(undetected) / sum(harmless + harmful))
# Print the number of harmful apps

output_histogram_path = "harmful_counts_histogram.png"

# Plotting the histogram

def graph_distribution():
    fig, ax = plt.subplots(figsize=(15, 10))
    counts, bins, patches = ax.hist(harmful, bins=[0, 1, 10, 20, 30, 40, 50], color='skyblue', edgecolor='black', rwidth=0.8)

    # Add count labels to each bar
    total = sum(counts)
    for count, bin_center in zip(counts, (bins[:-1] + bins[1:]) / 2):
        percentage = (count / total) * 100 if total > 0 else 0
        # Ensure the label appears, even for bars with 0 height
        y_position = count + 1000 if count > 0 else 500
        ax.text(bin_center, y_position, f"{int(count)}\n({percentage:.2f}%)", ha='center', fontsize=12)

    # Adding titles and labels
    ax.set_title("Distribution of Harmful Counts", fontsize=14)
    ax.set_xlabel("Harmful Count Range", fontsize=12)
    ax.set_ylabel("Number of Apps", fontsize=12)

    # Set x-axis ticks to ensure "1" is displayed
    ax.set_xticks([0, 1, 2, 10, 20, 30, 40, 50])

    # Save the histogram to a file
    plt.tight_layout()
    plt.savefig(output_histogram_path, dpi=300)
    plt.show()




def graph_malicious_vs_benign(threshold: int = 1):
    """Create a histogram that plots the number of malicious apps vs. benign apps
    
    :param threshold: The number of scanners that label an app malicious in order for it
                      to be classified as such
    """
    fig, ax = plt.subplots(figsize=(7.8, 10))
    
    harmful_n = benign_n = 0
    N = len(api_json_files)
    for n in harmful:
        if n >= threshold:
            harmful_n += 1
        else:
            benign_n += 1
    
    numbers = [benign_n, harmful_n]
    types = ['Benign Apps', 'Malicious Apps']
    
    ax.tick_params(axis='x', labelsize=14) 

    for i, n in enumerate(numbers):
        plt.text(i, n + 1, f'{n} ({n/N:.3%})', ha='center', va='bottom', fontsize=14)
        
    plt.bar(types, numbers)
    plt.title(f'Barplot of No. of Benign vs. Malicious Applications (t = {threshold})')
    
    ax.set_title(f'Barplot of No. of Benign vs. Malicious Applications (t = {threshold})',
                 fontsize=16)
    ax.set_xlabel('Type of Applications', fontsize=14)
    ax.set_ylabel('Number of Applications', fontsize=14)
    
    # Save the histogram to a file
    plt.tight_layout()
    plt.savefig(f'threshold {threshold}.png', dpi=300)
    
    
    # plt.show()
    
# graph_malicious_vs_benign(1)
# print(1, 'done')
# for t in range(5, 51, 5):
#     graph_malicious_vs_benign(t)
#     print(t, 'done')
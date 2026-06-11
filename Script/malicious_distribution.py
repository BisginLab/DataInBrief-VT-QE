from pathlib import Path
from random import sample
import math

from collections import Counter
import pickle

import json
from pprint import pprint

import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

ax = plt.figure().gca()
ax.yaxis.set_major_locator(MaxNLocator(integer=True))

with open('saved_malicious_counts.pkl', 'rb') as f:
    malicious_counts = pickle.load(f)
    
harmful_counts = [cnt for cnt in malicious_counts if cnt >= 1]

# Create frequency map
frequency_map = dict(Counter(harmful_counts))

pairs = list(frequency_map.items())
for cnt, freq in pairs:
    if cnt > 25:
        frequency_map[25] += freq
        frequency_map.pop(cnt)

# Extract values and their frequencies
values = list(frequency_map.keys())
frequencies = list(frequency_map.values())
print('Finish 1')

# Plot the bar graph
plt.figure(figsize=(18, 6))
plt.bar(values, frequencies, color='skyblue', edgecolor='black', width=1.0)  # Plot bar chart with no gaps
plt.xlabel('Malicious Count', fontsize=16)
plt.ylabel('Frequency', fontsize=16)
plt.title('Bar Graph of Distribution of Number of Malicious Counts', fontsize=20)
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.yscale('log', base=10)
plt.xticks(range(min(values), max(values)+1),
           labels=list(filter(str, range(min(values), max(values)))) + ['≥25'],
           fontsize=14)
plt.savefig('Bar_Graph_of_Data_Points.png', dpi=300)
plt.show()

print('Finish 2')
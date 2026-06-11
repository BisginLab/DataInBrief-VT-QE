import requests

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
API_KEY = 'c031c25e22b76066f30d1331e1edcfbd6fd9da095945526fb9c29cd48c2182a0'
# Replace 'FILE_HASH' with the SHA-256, SHA-1, or MD5 hash of the file you want to analyze
FILE_HASH = '24f05da105834088c604c0a2bd4987f092ad3d743d86b7200d835a61e490bc28'

# VirusTotal API endpoint for file reports
url = f'https://www.virustotal.com/api/v3/files/{FILE_HASH}'

# Set up the headers with your API key
headers = {
    'x-apikey': API_KEY
}

# Make the GET request to the VirusTotal API
response = requests.get(url, headers=headers)

# Check if the request was successful
if response.status_code == 200:
    # Parse the JSON response
    data = response.json()
    # Access the 'crowdsourced_ai_results' field
    print(data)
    # ai_results = data.get('data', {}).get('attributes', {}).get('crowdsourced_ai_results', {})

    if ai_results:
        for engine, result in ai_results.items():
            print(f"Engine: {engine}")
            print(f"Verdict: {result.get('ai_verdict', 'N/A')}")
            print(f"Analysis: {result.get('ai_analysis', 'N/A')}\n")
    else:
        print("No AI-generated results available for this file.")
else:
    print(f"Error: Unable to retrieve data (status code {response.status_code})")

import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# Load model and scaler
model = joblib.load('phishing_model.pkl')
scaler = joblib.load('scaler.pkl')


def extract_features(url):
    parsed_url = urlparse(url)
    
    def count_occurrences(s, char):
        return s.count(char)
    
    def get_min_length(words):
        return min([len(word) for word in words], default=0)
    
    def get_max_length(words):
        return max([len(word) for word in words], default=0)
    
    def get_avg_length(words):
        return sum(len(word) for word in words) / len(words) if words else 0
    
    words_url = re.findall(r'\w+', url)
    words_host = re.findall(r'\w+', parsed_url.netloc)
    words_path = re.findall(r'\w+', parsed_url.path)

    # Extracting only the required features
    features = {
        'length_url': len(url),
        'length_hostname': len(parsed_url.netloc),
        'ip': 1 if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', parsed_url.netloc) else 0,
        'nb_dots': count_occurrences(url, '.'),
        'nb_qm': count_occurrences(url, '?'),
        'nb_eq': count_occurrences(url, '='),
        'nb_slash': count_occurrences(url, '/'),
        'nb_www': count_occurrences(parsed_url.netloc, 'www'),
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url),
        'ratio_digits_host': sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc),
        'tld_in_subdomain': 1 if any(tld in parsed_url.netloc.split('.')[0] for tld in ['.com', '.org', '.net', '.info', '.biz']) else 0,
        'prefix_suffix': 1 if '-' in parsed_url.netloc else 0,
        'shortest_word_host': get_min_length(words_host),
        'longest_words_raw': get_max_length(words_url),
        'longest_word_path': get_max_length(words_path),
        'phish_hints': 1 if re.search(r'login|signin|secure|account|update|password|banking', url) else 0,
        'nb_hyperlinks': count_occurrences(url, 'http'),
        'ratio_intHyperlinks': 1 if 'https' in url else 0,
        'empty_title': 0,  # Placeholder, actual extraction would require HTML parsing
        'domain_in_title': 0,  # Placeholder, actual extraction would require HTML parsing
        'domain_age': 0,  # Placeholder, requires WHOIS lookup
        'google_index': 0,  # Placeholder, requires API call to check indexing
        'page_rank': 0,  # Placeholder, requires external service/API
    }

    return [features.get(col, 0) for col in [
        'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_qm', 'nb_eq', 'nb_slash', 'nb_www', 'ratio_digits_url', 
        'ratio_digits_host', 'tld_in_subdomain', 'prefix_suffix', 'shortest_word_host', 'longest_words_raw', 
        'longest_word_path', 'phish_hints', 'nb_hyperlinks', 'ratio_intHyperlinks', 'empty_title', 
        'domain_in_title', 'domain_age', 'google_index', 'page_rank'
    ]]

# Streamlit app
st.title('Phishing URL Detection')

url_input = st.text_input('Enter URL to check for phishing:')

if st.button('Check URL'):
    if url_input:
        features = extract_features(url_input)
        features_scaled = scaler.transform([features])
        prediction = model.predict(features_scaled)
        
        if prediction == 1:
            st.write('The URL is likely phishing.')
        else:
            st.write('The URL is legitimate.')
    else:
        st.write('Please enter a URL.')

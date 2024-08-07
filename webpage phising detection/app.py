import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# Load model and scaler
model = joblib.load('phishing_model.pkl')
scaler = joblib.load('scaler.pkl')

# Define the feature columns used in the model
feature_columns = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq',
    'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn',
    'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url',
    'ratio_digits_host', 'punycode', 'shortening_service', 'path_extension', 'phish_hints', 'domain_in_brand',
    'brand_in_subdomain', 'brand_in_path', 'suspecious_tld'
]

# Feature extraction function
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

    features = {
        'length_url': len(url),
        'length_hostname': len(parsed_url.netloc),
        'ip': 1 if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', parsed_url.netloc) else 0,
        'nb_dots': count_occurrences(url, '.'),
        'nb_hyphens': count_occurrences(url, '-'),
        'nb_at': count_occurrences(url, '@'),
        'nb_qm': count_occurrences(url, '?'),
        'nb_and': count_occurrences(url, '&'),
        'nb_or': count_occurrences(url, '|'),
        'nb_eq': count_occurrences(url, '='),
        'nb_underscore': count_occurrences(url, '_'),
        'nb_tilde': count_occurrences(url, '~'),
        'nb_percent': count_occurrences(url, '%'),
        'nb_slash': count_occurrences(url, '/'),
        'nb_star': count_occurrences(url, '*'),
        'nb_colon': count_occurrences(url, ':'),
        'nb_comma': count_occurrences(url, ','),
        'nb_semicolumn': count_occurrences(url, ';'),
        'nb_dollar': count_occurrences(url, '$'),
        'nb_space': count_occurrences(url, ' '),
        'nb_www': count_occurrences(parsed_url.netloc, 'www'),
        'nb_com': count_occurrences(parsed_url.netloc, '.com'),
        'nb_dslash': count_occurrences(url, '//') - 1,
        'http_in_path': 'http' in parsed_url.path,
        'https_token': int('https' in parsed_url.netloc),
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url),
        'ratio_digits_host': sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc),
        'punycode': 1 if re.search('xn--', url) else 0,
        'shortening_service': 1 if re.search(
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|'
            r'migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|'
            r'ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|'
            r'wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|'
            r'q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|xlinkz\.info|'
            r'prettylinkpro\.com|scrnch\.me|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', parsed_url.netloc) else 0,
        'path_extension': 1 if re.search(r'\.\w+$', parsed_url.path) else 0,
        'phish_hints': 1 if re.search(r'login|signin|secure|account|update|password|banking', url) else 0,
        'domain_in_brand': 1 if re.search(r'paypal|apple|ebay|amazon|google|microsoft', parsed_url.netloc) else 0,
        'brand_in_subdomain': 1 if re.search(r'paypal|apple|ebay|amazon|google|microsoft', parsed_url.netloc.split('.')[0]) else 0,
        'brand_in_path': 1 if re.search(r'paypal|apple|ebay|amazon|google|microsoft', parsed_url.path) else 0,
        'suspecious_tld': 1 if re.search(r'\.(tk|ml|ga|cf|gq)', parsed_url.netloc) else 0,
    }

    return [features.get(col, 0) for col in feature_columns]

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

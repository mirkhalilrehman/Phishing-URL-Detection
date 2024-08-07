Phishing URL Detection with Machine Learning
Overview
This project aims to detect phishing URLs using various machine learning algorithms. The dataset includes features extracted from URLs, such as lengths, counts of special characters, and presence of certain patterns. The project utilizes multiple classifiers and fine-tunes them to achieve optimal performance. Additionally, it features a Streamlit web application that allows users to test URLs in real-time and receive predictions on whether they are phishing attempts or legitimate.

Key Features
Data Preprocessing: Handles feature scaling, encoding, and irrelevant feature removal.
Model Training and Evaluation:
Implements multiple classifiers, including Logistic Regression, Random Forest, Gradient Boosting, SVM, and KNN.
Uses GridSearchCV for hyperparameter tuning to optimize model performance.
Evaluates models using metrics such as accuracy, precision, recall, F1-score, and confusion matrix.
Streamlit Application:
Provides a user-friendly interface for testing URLs.
Displays predictions along with detailed information on the URL analysis.
Installation
To run the project locally, follow these steps:

Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/phishing-url-detection.git
cd phishing-url-detection
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Run the Streamlit app:

bash
Copy code
streamlit run app.py
Dataset
The dataset consists of URLs with features like:

Length of URL and hostname
Counts of special characters (dots, hyphens, etc.)
Presence of specific patterns
Sample Data
plaintext
Copy code
URL: http://www.crestonwood.com/router.php
Features: length_url=37, length_hostname=19, nb_dots=3, nb_hyphens=0, ...
Label: legitimate

URL: http://shadetreetechnology.com/V4/validation/a111aedc8ae390eabcfa130e041a10a4
Features: length_url=77, length_hostname=23, nb_dots=1, nb_hyphens=0, ...
Label: phishing
Results
The best-performing models and their parameters:

Logistic Regression: Best Parameters: {'C': 0.1}, Best Score (CV): 0.83, Test Accuracy: 0.84
Random Forest: Best Parameters: {'max_depth': 20, 'n_estimators': 100}, Best Score (CV): 0.90, Test Accuracy: 0.89
Gradient Boosting: Best Parameters: {'learning_rate': 0.1, 'n_estimators': 200}, Best Score (CV): 0.89, Test Accuracy: 0.88
SVM: Best Parameters: {'C': 10, 'kernel': 'rbf'}, Best Score (CV): 0.88, Test Accuracy: 0.87
KNN: Best Parameters: {'n_neighbors': 5, 'p': 1}, Best Score (CV): 0.88, Test Accuracy: 0.89
Contributing
Feel free to submit issues or pull requests to improve the project. Contributions are welcome!

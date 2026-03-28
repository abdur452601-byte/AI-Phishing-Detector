import pandas as pd
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
import os
import re

def train_model():
    print("Loading data and training the AI model...")
    file_path = os.path.join('data', 'emails.csv')
    
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: Could not find {file_path}. Please make sure your CSV is in the 'data' folder.")
        return None, None

    # 1. Prepare the data
    # Your dataset is already vectorized! We just need to separate features from the target.
    # We skip the first column ('Email No.') and the last column ('Prediction') to get the words.
    word_columns = df.columns[1:-1]
    
    X = df[word_columns]  # Features: The 3,000 columns of word counts
    y = df['Prediction']  # Target: 1 for spam, 0 for safe

    # 2. Split data for training and testing
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Train the model directly (No pipeline needed!)
    model = MultinomialNB()
    model.fit(X_train, y_train)
    
    # 4. Check accuracy
    accuracy = model.score(X_test, y_test)
    print(f"Model trained successfully! Accuracy: {accuracy * 100:.2f}%\n")
    
    return model, word_columns

def main():
    print("=== Welcome to the AI Phishing Detector ===")
    
    model, word_columns = train_model()
    if model is None:
        return

    # Command-line loop for the user
    while True:
        user_input = input("Paste an email to check (or type 'exit' to quit): \n> ")
        
        if user_input.lower() == 'exit':
            print("Exiting Phishing Detector. Goodbye!")
            break
            
        if user_input.strip() == "":
            print("Please enter some text.")
            continue
            
        # Transform the user's raw text into the 3,000-column format the AI expects
        # First, extract all words from the input
        words_in_input = re.findall(r'\b\w+\b', user_input.lower())
        
        # Create a dictionary filled with zeros for all 3,000 known dataset words
        input_data = {word: 0 for word in word_columns}
        
        # Count the occurrences of words in the user's input
        for word in words_in_input:
            if word in input_data:
                input_data[word] += 1
                
        # Convert it to a DataFrame format matching the training data
        input_df = pd.DataFrame([input_data])
        
        # Make a prediction
        prediction = model.predict(input_df)
        
        if prediction[0] == 1:
            print("\n🚨 WARNING: This email looks like a PHISHING/SPAM attempt!\n")
        else:
            print("\n✅ SAFE: This email appears to be legitimate.\n")

if __name__ == "__main__":
    main()
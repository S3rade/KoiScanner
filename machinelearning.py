import nltk
nltk.download('punkt')
from random import shuffle
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
import matplotlib.pyplot as plt
from wordcloud import WordCloud
from math import log, sqrt
import pandas as pd
import numpy as np
import re

mails = pd.read_csv('data.csv', encoding = 'latin-1')
ds = mails.sample(frac=1).reset_index(drop=True) # To randomize the dataset
ds.head() # To show dataset is Randomized

ds['label'].value_counts() # Show how many "bad" & "good" urls

totalMails = 344821 + 75643
# To spilt Training Data to 75% and Testing Data into 25%
trainIndex, testIndex = list(), list()
for i in range(ds.shape[0]):
    if np.random.uniform(0, 1) < 0.75:
        trainIndex += [i]
    else:
        testIndex += [i]
trainData = ds.loc[trainIndex]
testData = ds.loc[testIndex]

#To show 75% of data has been seperated
trainData.reset_index(inplace = True)
trainData.drop(['index'], axis = 1, inplace = True)
trainData.head()

trainData['label'].value_counts()

#To show 25% of data has been seperated
testData.reset_index(inplace = True)
testData.drop(['index'], axis = 1, inplace = True)
testData.head()

testData['label'].value_counts()

#To tokenize the dataset
def process_message(message, lower_case = True, stem = True, stop_words = True, gram = 2):
    if lower_case:
        message = message.lower()
    words = word_tokenize(message)
    words = [w for w in words if len(w) > 2]
    if gram > 1:
        w = []
        for i in range(len(words) - gram + 1):
            w += [' '.join(words[i:i + gram])]
        return w
    if stop_words:
        sw = stopwords.words('english')
        words = [word for word in words if word not in sw]
    if stem:
        stemmer = PorterStemmer()
        words = [stemmer.stem(word) for word in words]   
    return words

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


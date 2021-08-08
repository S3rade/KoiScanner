from KoiScanner_withUI import API_key
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
from collections import UserList
import tkinter as tk
from tkinter import ttk
from tkinter.constants import END, W
import win32com.client
import imaplib
import email
from email.header import decode_header
import webbrowser
import os
import sys
import whois
import requests
import time
import json
from tldextract import tldextract
import joblib
import pyfiglet

url_list = ["url"]
df = pd.read_csv('malicious.csv', usecols=url_list)

mails = pd.read_csv('data.csv', encoding = 'latin-1')
ds = mails.sample(frac=1).reset_index(drop=True) # To randomize the dataset


# Connect to inbox
username = 'tpmpuser123@gmail.com'
password = 'Tp@mpuser999'
mail_server = 'imap.gmail.com'
imap_server = imaplib.IMAP4_SSL(host=mail_server)
imap_server.login(username, password)
imap_server.select('Inbox')  # Default is `INBOX`

search_criteria = 'ALL'
charset = None  # All
respose_code, message_numbers_raw = imap_server.search(charset, search_criteria)
message_numbers = message_numbers_raw[0].split()

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

#Train the model
class SpamClassifier(object):
    def __init__(self, trainData, method = 'tf-idf'):
        self.x, self.labels = trainData['url'], trainData['label']
        self.method = method

    def train(self):
        self.calc_TF_and_IDF()
        if self.method == 'tf-idf':
            self.calc_TF_IDF()
        else:
            self.calc_prob()

    def calc_prob(self):
        self.prob_spam = dict()
        self.prob_ham = dict()
        for word in self.tf_spam:
            self.prob_spam[word] = (self.tf_spam[word] + 1) / (self.spam_words + \
                                                                len(list(self.tf_spam.keys())))
        for word in self.tf_ham:
            self.prob_ham[word] = (self.tf_ham[word] + 1) / (self.ham_words + \
                                                                len(list(self.tf_ham.keys())))
        self.prob_spam_mail, self.prob_ham_mail = self.spam_mails / self.total_mails, self.ham_mails / self.total_mails 


    def calc_TF_and_IDF(self):
        noOfMessages = self.x.shape[0]
        self.spam_mails, self.ham_mails = self.labels.value_counts()[1], self.labels.value_counts()[0]
        self.total_mails = self.spam_mails + self.ham_mails
        self.spam_words = 0
        self.ham_words = 0
        self.tf_spam = dict()
        self.tf_ham = dict()
        self.idf_spam = dict()
        self.idf_ham = dict()
        for i in range(noOfMessages):
            message_processed = process_message(self.x[i])
            count = list() #To keep track of whether the word has ocured in the message or not.
                           #For IDF
            for word in message_processed:
                if self.labels[i]:
                    self.tf_spam[word] = self.tf_spam.get(word, 0) + 1
                    self.spam_words += 1
                else:
                    self.tf_ham[word] = self.tf_ham.get(word, 0) + 1
                    self.ham_words += 1
                if word not in count:
                    count += [word]
            for word in count:
                if self.labels[i]:
                    self.idf_spam[word] = self.idf_spam.get(word, 0) + 1
                else:
                    self.idf_ham[word] = self.idf_ham.get(word, 0) + 1

    def calc_TF_IDF(self):
        self.prob_spam = dict()
        self.prob_ham = dict()
        self.sum_tf_idf_spam = 0
        self.sum_tf_idf_ham = 0
        for word in self.tf_spam:
            self.prob_spam[word] = (self.tf_spam[word]) * log((self.spam_mails + self.ham_mails) \
                                                          / (self.idf_spam[word] + self.idf_ham.get(word, 0)))
            self.sum_tf_idf_spam += self.prob_spam[word]
        for word in self.tf_spam:
            self.prob_spam[word] = (self.prob_spam[word] + 1) / (self.sum_tf_idf_spam + len(list(self.prob_spam.keys())))
            
        for word in self.tf_ham:
            self.prob_ham[word] = (self.tf_ham[word]) * log((self.spam_mails + self.ham_mails) \
                                                          / (self.idf_spam.get(word, 0) + self.idf_ham[word]))
            self.sum_tf_idf_ham += self.prob_ham[word]
        for word in self.tf_ham:
            self.prob_ham[word] = (self.prob_ham[word] + 1) / (self.sum_tf_idf_ham + len(list(self.prob_ham.keys())))
            
    
        self.prob_spam_mail, self.prob_ham_mail = self.spam_mails / self.total_mails, self.ham_mails / self.total_mails 
                    
    def classify(self, processed_message):
        pSpam, pHam = 0, 0
        for word in processed_message:                
            if word in self.prob_spam:
                pSpam += log(self.prob_spam[word])
            else:
                if self.method == 'tf-idf':
                    pSpam -= log(self.sum_tf_idf_spam + len(list(self.prob_spam.keys())))
                else:
                    pSpam -= log(self.spam_words + len(list(self.prob_spam.keys())))
            if word in self.prob_ham:
                pHam += log(self.prob_ham[word])
            else:
                if self.method == 'tf-idf':
                    pHam -= log(self.sum_tf_idf_ham + len(list(self.prob_ham.keys()))) 
                else:
                    pHam -= log(self.ham_words + len(list(self.prob_ham.keys())))
            pSpam += log(self.prob_spam_mail)
            pHam += log(self.prob_ham_mail)
        return pSpam >= pHam
    def predict(self, testData):
            result = dict()
            for (i, message) in enumerate(testData):
                processed_message = process_message(message)
                result[i] = int(self.classify(processed_message))
            return result

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()        
        self.create_widgets()

    def create_widgets(self):
        paddings = {'padx': 5, 'pady': 5 }
        self.fullEmailScanner = tk.Button(self,**paddings)
        self.fullEmailScanner["text"]= "Scan Full Email"
        self.fullEmailScanner["command"] = self.onload
        self.fullEmailScanner.grid(column=0 ,row=1)

        self.urlScanner = tk.Button(self,**paddings)
        self.urlScanner["text"]= "Scan URL Only"
        self.urlScanner["command"] = self.scanner
        self.urlScanner.grid(column=1 ,row=1)

        self.quit = tk.Button(self, text="QUIT", fg="red",command=self.master.destroy,**paddings)
        self.quit.grid(column=2 ,row= 1)       

    def onload(self):
        newWindow = tk.Toplevel(root)
        newWindow.geometry('500x200')
        newWindow.title("KoiScanner Results")
        maliciouslinks= tk.Listbox(newWindow,width=100,height=20)
        paddings = {'padx': 5, 'pady': 5}
        for message_number in message_numbers:
            response_code, message_data = imap_server.fetch(message_number, '(RFC822)')
            for response in message_data:
                #print(response)
                if isinstance(response, tuple):
                    
                    # parse a bytes email into a message object
                    msg = email.message_from_bytes(response[1])
                    subject = msg.get("Subject", None)
                    getFrom = msg.get("From", None)
                    #getFrom = getFrom.split()
                    #getFrom = getFrom[-1].strip('<>')
                    returnPath = msg.get("Return-Path", None)
                    returnPath = returnPath.strip('<>')
                    receivedSPF = msg.get("Received-SPF", None).split()
                    
                    # if the email message is multipart
                    if msg.is_multipart():
                        # iterate over email parts
                        for part in msg.walk():
                            # extract content type of email
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            try:
                                # get the email body
                                body = part.get_payload(decode=True).decode()
                                for link in df["url"]:
                                    for letters in body.split():
                                        if link == letters:
                                            parameters = {'apikey': API_key, 'resource': link} #VirusTotal only can check each link
                                            response= requests.get(url=url_list, params=parameters) # 4 times per minute!
                                            json_response = json.loads(response.text)
                                            if json_response['response_code'] <= 0:
                                                getstatus = "empty"
                                            elif json_response['response_code'] >= 1:
                                                if json_response['positives'] <= 0:
                                                    getstatus = "positive"
                                                else:
                                                    getstatus = "malicious"
                                                    maliciouslinks.insert(END,link)
                                            if getstatus == "malicious":
                                                checkIP = whois.whois(link)
                                                test = checkIP.get("domain_name", None)
                                                imap_server.create('malicious')
                                                imap_server.store(message_number, '+X-GM-LABELS', 'malicious')
                                                imap_server.store(message_number, '+FLAGS', '\Deleted')  # read mail remove from inbox
                                                imap_server.expunge()
                                                print("Subject:", subject)
                                                print("From:", getFrom)
                                                print("Domain name that is malicious:", test)
                                                print("Found email with malicious link!")
                                                print("Malicious link:", letters)
                                                print("")
                                        elif receivedSPF[0] != "pass":
                                            imap_server.create('malicious')
                                            imap_server.store(message_number, '+X-GM-LABELS', 'malicious')
                                            imap_server.store(message_number, '+FLAGS', '\Deleted')  # read mail remove from inbox
                                            imap_server.expunge()
                                            print("Subject:", subject)
                                            print("From:", getFrom)
                                            print("SPF Status:", receivedSPF[0], ". Not secure.")
                                        else:
                                            continue
                            
                            
                            except:
                                pass
                    
        Displaytext2 = tk.Label(newWindow, text="The Following Links are malicious according to VirusTotal !",**paddings)
        Displaytext2.pack()
        maliciouslinks.pack()

        imap_server.close()
        imap_server.logout()

        

    def scanner(self):
        
        newWindow2 = tk.Toplevel(root)
        newWindow2.geometry('400x230')
        newWindow2.title("KoiScanner for URL Link")

        def scan_url():
            results_scanner = "False"

            urltoscan = user_input.get()
            for result in df["url"]:
                for letters in urltoscan.split():
                    if result == letters:
                        parameters = {'resource': result} #VirusTotal only can check each link
                        response= requests.get(url=result, param=parameters) # 4 times per minute!
                        json_response = json.loads(response.text)
                        if json_response['response_code'] <= 0:
                            getstatus = "empty"
                        elif json_response['response_code'] >= 1:
                            if json_response['positives'] <= 0:
                                getstatus = "good"
                            else:
                                getstatus = "bad"
                                if getstatus == "bad":
                                    results_scanner="True"

            newWindow3 = tk.Toplevel(newWindow2)
            newWindow3.geometry('400x230')
            newWindow3.title("KoiScanner for URL Link RESULTS")

            if results_scanner == "True":
                tk.Label(newWindow3, text="The Link IS Malicious").pack()
            else:
               tk.Label(newWindow3, text="The Link is NOT Malicious").pack()
            tk.Button(newWindow3, text="QUIT", fg="red",command=newWindow3.destroy).pack()

        tk.Label(newWindow2, text="Please Enter the Link Below!").pack()
        user_input = tk.StringVar(newWindow2)
        entry = tk.Entry(newWindow2, textvariable=user_input).pack()
        button1 = tk.Button(newWindow2,text='Scan the URL', command=scan_url).pack()
        
        tk.Button(newWindow2, text="QUIT", fg="red",command=newWindow2.destroy).pack()
        

    def exit(self):
        root.destroy()


root = tk.Tk()
root.title("KoiScanner")
root.geometry('400x230')
bg = tk.PhotoImage(file = "C:/xampp/htdocs/KoiScanner-main/images/title_logo2.png")
canvas1 = tk.Canvas( root, width = 300, height = 100)  
canvas1.pack(fill = "both", expand = True)
canvas1.create_image( 0, 0, image = bg,anchor = "nw")

app = Application(master=root)
app.mainloop()


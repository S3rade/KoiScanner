from collections import UserList
import tkinter as tk
from tkinter.constants import END, W
from tkinter.ttk import *
import pandas
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
from whiteBlacklist import WhiteBlackApp
import joblib
import pyfiglet

col_list = ["url"]
df = pandas.read_csv('malicious.csv', usecols=col_list)

API_key = '9a620234276d322d185e00b59e25242ec06464b994c556d392d2ded861f2e9fe'
url = 'https://www.virustotal.com/vtapi/v2/url/report'
parameters = {'apikey': API_key, 'resource': df}
response= requests.get(url=url, params=parameters)
json_response= json.loads(response.text)

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



class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        self.fullEmailScanner = tk.Button(self)
        self.fullEmailScanner["text"]= "Scan Full Email"
        self.fullEmailScanner["command"] = self.onload
        self.fullEmailScanner.grid(column=1 ,row=1)

        self.urlScanner = tk.Button(self)
        self.urlScanner["text"]= "Scan URL Only"
        self.urlScanner["command"] = self.scanner
        self.urlScanner.grid(column=2 ,row=1)

        self.quit = tk.Button(self, text="QUIT", fg="red",command=self.master.destroy)
        self.quit.grid(column=5 ,row= 1)
        

    def onload(self):
        newWindow = tk.Toplevel(root)
        newWindow.geometry('500x200')
        newWindow.title("KoiScanner Results")
        maliciouslinks= tk.Listbox(newWindow,width=100,height=20)
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
                                            response= requests.get(url=url, params=parameters) # 4 times per minute!
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
                    
        Displaytext2 = tk.Label(newWindow, text="The Following Links are malicious according to VirusTotal !")
        Displaytext2.pack()
        retreivingePrint=tk.Label(newWindow, text="Retreiving Emails")
        retreivingePrint.pack()
        scanningPrint=tk.Label(newWindow, text="Scanning Emails")
        scanningPrint.pack()
        maliciouslinks.pack()

        imap_server.close()
        imap_server.logout()

        

    def scanner(self):
        
        newWindow2 = tk.Toplevel(root)
        newWindow2.geometry('500x200')
        newWindow2.title("KoiScanner for URL Link")

        def scan_url():
            results_scanner = "False"

            urltoscan = user_input.get()
            for link in df["url"]:
                for letters in urltoscan.split():
                    if link == letters:
                        parameters = {'apikey': API_key, 'resource': link} #VirusTotal only can check each link
                        response= requests.get(url=url, params=parameters) # 4 times per minute!
                        json_response = json.loads(response.text)
                        if json_response['response_code'] <= 0:
                            getstatus = "empty"
                        elif json_response['response_code'] >= 1:
                            if json_response['positives'] <= 0:
                                getstatus = "positive"
                            else:
                                getstatus = "malicious"
                                if getstatus == "malicious":
                                    results_scanner="True"

            newWindow3 = tk.Toplevel(newWindow2)
            newWindow3.geometry('500x200')
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
root.geometry('500x200')
app = Application(master=root)
app.mainloop()

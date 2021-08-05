# -*- coding: utf-8 -*-
import telebot
from telebot.types import CallbackQuery
import credentials
import telegram
import datetime
import pytz
import json
import traceback


# This checks Received-SPF(Sender Policy Framework) and check malicious link with the csv to the message body.
# This includes VirusTotal API and Whois domain lookup

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

bot = telebot.TeleBot(credentials.bot_token)

URL_TO_RECEIVE = {'URL': ""}

bot.state = None

URL_SCANNER = 1




@bot.message_handler(commands=['start'])
def start_command(message):
    bot.send_message(
       message.chat.id,
       'Greetings! Welcome to KoiScanner Telegram API Bot \n' +
       'To Scan Possibile Malicious URL, Press /scan_url.\n' +
       'To Scan All Emails, Press /scan_emails.\n '
       'To get help press /help.',
       
   )

@bot.message_handler(commands=['help'])
def help_command(message):
   keyboard = telebot.types.InlineKeyboardMarkup()
   keyboard.add(
       telebot.types.InlineKeyboardButton(
           'Message the developer', url='telegram.me/Serade'
       )
   )
   bot.send_message(
       message.chat.id,
       '1) To Scan Possibile Malicious URL, Press /scan_url.\n' +
       '2) To Scan All Emails, Press /scan_emails.\n' +
       'THIS BOT IS STILL IN BETA STAGE SO PLEASE FORGIVE ME IF IT IS NOT WORKING SO WELL',
       reply_markup=keyboard
   )

@bot.message_handler(commands=['scan_emails'])
def scan_email_command(message):
   bot.send_message(
       message.chat.id,
       'This May take a while.\n'
   ) 
   scan_email(message)

def scan_email(message):
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
    
    testing=[]
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
                                                    testing.append(link)

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
                        
    imap_server.close()
    imap_server.logout()
    time.sleep(100)
    bot.send_message(
       message.chat.id,
       'The follwing Links are Malicious.\n'+ format(testing)
        
    ) 


@bot.message_handler(commands=['scan_url'])
def scan_email_command(message):
   global URL_TO_RECEIVE
   URL_TO_RECEIVE = {'URL': ""}
   bot.send_message(
       message.chat.id,
       'Please Paste the URL!\n' +
       'To Cancel, reply /cancel'
   )
   bot.state =  URL_SCANNER

@bot.message_handler(commands=['cancel'])
def test(message):
    bot.send_message(
        message.chat.id,
        'Cancelled' +
        'Type /help to see your options again' 
    )
    bot.state = None   

@bot.message_handler(func=lambda msg:bot.state==URL_SCANNER)
def get_title(message):

    URL_TO_RECEIVE['URL'] = message.text
    URL_TO_SCAN = URL_TO_RECEIVE['URL']
    bot.send_message(message.chat.id, ' Scanning the Link now! Please Wait!')
    bot.state = None

    url_scanner(message,URL_TO_SCAN)

def url_scanner(message,URL_TO_SCAN):

    col_list = ["url"]
    df = pandas.read_csv('malicious.csv', usecols=col_list)
    API_key = '9a620234276d322d185e00b59e25242ec06464b994c556d392d2ded861f2e9fe'
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    parameters = {'apikey': API_key, 'resource': df}
    response= requests.get(url=url, params=parameters)
    json_response= json.loads(response.text)

    results_scanner = "False"
    urltoscan = URL_TO_SCAN
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

    if results_scanner == "True":
        bot.send_message(
        message.chat.id,
       'The Link IS Malicious. \n' + 'To scan another link please reply /scan_url !'      
       )
    
    else:
        bot.send_message(
        message.chat.id,
       'The Link IS NOT Malicious. \n' + 'To scan another link please reply /scan_url !'  
       )
    

bot.polling(none_stop=True)

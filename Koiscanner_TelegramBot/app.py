from __future__ import print_function
import telebot
from telebot.types import CallbackQuery
import credentials
import json

import matplotlib.pyplot as plt
from wordcloud import WordCloud
from math import log, sqrt
import pandas as pd
import numpy as np


# This checks Received-SPF(Sender Policy Framework) and check malicious link with the csv to the message body.
# This includes VirusTotal API and Whois domain lookup

import cloudmersive_virus_api_client
from cloudmersive_virus_api_client.rest import ApiException
import cloudmersive_validate_api_client
from cloudmersive_validate_api_client.rest import ApiException
from pprint import pprint
from collections import UserList
import datetime
import pandas
import imaplib
import email
import pytz
import re
import os
from email.header import decode_header
import whois
import requests
import webbrowser
import urllib.parse
from urllib.error import HTTPError

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
       '\n' +
       'Email Scanner is in DEVELOPMENT so if this command is ran, it will check against a existing account that cant be changed \n'+
       '\n'+
       'To Scan All Emails, Press /scan_emails.\n ' +
       '\n'+
       'THIS BOT IS STILL IN BETA STAGE SO PLEASE FORGIVE ME IF IT IS NOT WORKING SO WELL \n' +
       'To get help press /help.'
       
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
       'Click The Button "Message the Developer" if you have any questions. :) '+
       '\n'+
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
    timenow = datetime.datetime.now(pytz.timezone('Asia/Singapore'))
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
    
    maliciousLinks=[]
    maliciousAttachments=[]
    numberofcountedmail = 0
    for message_number in message_numbers:
            response_code, message_data = imap_server.fetch(message_number, '(RFC822)')
            for response in message_data:
                #print(response)
                if isinstance(response, tuple):
                    # parse a bytes email into a message object
                    msg = email.message_from_bytes(response[1])
                    subject = msg.get("Subject", None)
                    getFrom = msg.get("From", None)
                    getTo = msg.get("To", None)
                    getDate = msg.get("Date", None)
                    getID = msg.get("Message-ID", None)
                    getSPF = msg.get("Received-SPF", None)
                    getSPFIP = re.search(r"(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)", getSPF)
                    try:
                        getSPFIPmatch = getSPFIP[0]
                    except TypeError:
                        pass    
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
                            except:
                                pass
                            if "attachment" in content_disposition:
                                # download attachment
                                filename = part.get_filename()
                                print(filename)
                                if filename:
                                    folder_name = getID[4:-1]
                                    folder_namereplace1 = folder_name.replace(".", "_")
                                    folder_namereplace2 = folder_namereplace1.replace("@", "_")
                                    if not os.path.isdir(folder_namereplace2):
                                        # make a folder for this email (named after getID)
                                        os.mkdir(folder_namereplace2)
                                    filepath = os.path.join(folder_namereplace2, filename)
                                    # download attachment and save it
                                    open(filepath, "wb").write(part.get_payload(decode=True))
                                    
                                    # Configure API key authorization: Apikey
                                    configuration = cloudmersive_virus_api_client.Configuration()
                                    configuration.api_key['Apikey'] = '2c418a13-77a2-40e5-bc5b-9e9995ad7ff5'

                                    # create an instance of the API class
                                    api_instance = cloudmersive_virus_api_client.ScanApi(cloudmersive_virus_api_client.ApiClient(configuration))
                                    input_file = folder_namereplace2+'/'+filename # file | Input file to perform the operation on.
                                    allow_executables = True # bool | Set to false to block executable files (program code) from being allowed in the input file.  Default is false (recommended). (optional)
                                    allow_invalid_files = True # bool | Set to false to block invalid files, such as a PDF file that is not really a valid PDF file, or a Word Document that is not a valid Word Document.  Default is false (recommended). (optional)
                                    allow_scripts = True # bool | Set to false to block script files, such as a PHP files, Python scripts, and other malicious content or security threats that can be embedded in the file.  Set to true to allow these file types.  Default is false (recommended). (optional)
                                    allow_password_protected_files = True # bool | Set to false to block password protected and encrypted files, such as encrypted zip and rar files, and other files that seek to circumvent scanning through passwords.  Set to true to allow these file types.  Default is false (recommended). (optional)
                                    allow_macros = True # bool | Set to false to block macros and other threats embedded in document files, such as Word, Excel and PowerPoint embedded Macros, and other files that contain embedded content threats.  Set to true to allow these file types.  Default is false (recommended). (optional)
                                    allow_xml_external_entities = True # bool | Set to false to block XML External Entities and other threats embedded in XML files, and other files that contain embedded content threats.  Set to true to allow these file types.  Default is false (recommended). (optional)
                                    #restrict_file_types = 'restrict_file_types_example' # str | Specify a restricted set of file formats to allow as clean as a comma-separated list of file formats, such as .pdf,.docx,.png would allow only PDF, PNG and Word document files.  All files must pass content verification against this list of file formats, if they do not, then the result will be returned as CleanResult=false.  Set restrictFileTypes parameter to null or empty string to disable; default is disabled. (optional)
                                    
                                    try:
                                        # Advanced Scan a file for viruses
                                        api_responses = api_instance.scan_file_advanced(input_file, allow_executables=allow_executables, allow_invalid_files=allow_invalid_files, allow_scripts=allow_scripts, allow_password_protected_files=allow_password_protected_files, allow_macros=allow_macros, allow_xml_external_entities=allow_xml_external_entities)
                                        api_response = {}
                                        for x in str(api_responses).split(","):
                                            api_response[x.split(": ")[0].split("'")[1]] = x.split(": ")[1]
                                        if api_response['clean_result'] == 'True':
                                            attachmentclean = "The attachment is clean"
                                        else:
                                            maliciousAttachments.append(input_file)
                                        if api_response['contains_executable'] == 'False':
                                            attachmentexecutable = "The attachment does not contain any executable"
                                        else:
                                            attachmentexecutable = "The attachment contained an executable"
                                            maliciousAttachments.append(input_file)
                                        if api_response['contains_invalid_file'] == 'False':
                                            attachmentinvalid = "The attachment does not contain any invalid file"
                                        else:
                                            attachmentinvalid = "The attachment contained an invalid file!"
                                            maliciousAttachments.append(input_file)
                                        if api_response['contains_macros'] == 'False':
                                            attachmentmacros = "The attachment contains no embedded Macros of other embedded threats"
                                        else:
                                            attachmentmacros = "The attachment contained embedded Macros of other embedded threats!"
                                            maliciousAttachments.append(input_file)
                                        if api_response['contains_password_protected_file'] == 'False':
                                            attachmentprotected = "The attachment does not contain a password protected or encrypted file"
                                        else:
                                            attachmentprotected = "The attachment contained a password protected or encrypted file!"
                                            maliciousAttachments.append(input_file)
                                        if api_response['contains_xml_external_entities'] == 'False':
                                            attachmentxml = "The attachment does not contain embedded XML External Entity threats"
                                        else:
                                            maliciousAttachments.append(input_file)
                                        if api_response['found_viruses'] == 'None':
                                            attachmentviruses = "The attachment contained no viruses"
                                        else:
                                            maliciousAttachments.append(input_file)
                                    except ApiException as e:
                                        print("Exception when calling ScanApi->scan_file_advanced: %s\n" % e)
                                    
                            #elif content_type == "text/plain" in content_disposition:
                            elif content_type == "text/plain" and "attachment" not in content_disposition:
                                for link in df["url"]:
                                    for letters in body.split():
                                        if link == letters:
                                            #VirusTotal API
                                            parameters = {'apikey': API_key, 'resource': link} #VirusTotal only can check each link
                                            response= requests.get(url=url, params=parameters) # 4 times per minute!
                                                
                                            if response.text == None or response.text == '':
                                                pass
                                            else:
                                                json_response = json.loads(response.text)
                                                if json_response['response_code'] <= 0:
                                                    getstatus = "empty"
                                                elif json_response['response_code'] >= 1:
                                                    if json_response['positives'] <= 0:
                                                        getstatus = "positive"
                                                    else:
                                                        numofpositivescan = json_response['positives']
                                                        
                                                        # Use Cloudmersive API
                                                        configuration = cloudmersive_validate_api_client.Configuration()
                                                        configuration.api_key['Apikey'] = '2c418a13-77a2-40e5-bc5b-9e9995ad7ff5'

                                                        # create an instance of the API class
                                                        api_instance12 = cloudmersive_validate_api_client.IPAddressApi(cloudmersive_validate_api_client.ApiClient(configuration))
                                                        ipvalue = str(getSPFIP) # str | IP address to process, e.g. \"55.55.55.55\".  The input is a string so be sure to enclose it in double-quotes.
                                                        #ipvalue = str("2a01:4f8:251:657::2") #can use IPv6
                                                        try:
                                                            # Get intelligence on an IP address
                                                            api_response1 = api_instance12.i_p_address_ip_intelligence(ipvalue)
                                                            #pprint(api_response1)
                                                            api_response_check_ip = {}
                                                            for check_ip_sender in str(api_response1).split(","):
                                                                api_response_check_ip[check_ip_sender.split(": ")[0].split("'")[1]] = check_ip_sender.split(": ")[1]
                                                            if api_response_check_ip['is_bot'] == 'False':
                                                                senderipbot = "The sender is not a bot!"
                                                            else:
                                                                senderipbot = "The sender is a bot!"
                                                                maliciousLinks.append(letters)
                                                            if api_response_check_ip['is_threat'] == 'False':
                                                                senderipthreat = "The sender IP address is not a known threat"
                                                            else:
                                                                senderipthreat = "The sender IP address is a known threat!"
                                                                maliciousLinks.append(letters)
                                                            if api_response_check_ip['is_tor_node'] == 'False':
                                                                senderiptor = "The sender IP is not a known Tor exit node which enables anonymous communication"
                                                            else:
                                                                senderiptor = "The sender IP is a known Tor exit node which enables anonymous communication!"
                                                                maliciousLinks.append(letters)
                                                            if api_response_check_ip['location'] == 'None':
                                                                senderiplocation = "The sender IP does not seem to have a location"
                                                                maliciousLinks.append(letters)
                                                            else:
                                                                senderiplocation = "The sender IP address has a location: "+api_response_check_ip['location']
                                                            if api_response_check_ip['region_area'] == 'None':
                                                                senderipregion = "The sender IP does not seem to have a region area"
                                                                maliciousLinks.append(letters)
                                                            else:
                                                                senderipregion = "The sender IP address region area: "+api_response_check_ip['region_area']
                                                            if api_response_check_ip['subregion_area'] == 'None':
                                                                senderipsubregion = "The sender IP does not seem to have a subregion area"
                                                                maliciousLinks.append(letters)
                                                            else:
                                                                senderipsubregion = "The sender IP address subregion area: "+api_response_check_ip['subregion_area']
                                                        except ApiException as e:
                                                            print("Exception when calling IPAddressApi->i_p_address_ip_intelligence: %s\n" % e)   
                                                        
                                                        #Use ipqualityscore API
                                                        ipqualityscorescan = str(link)
                                                        ipqualityscorescan = ipqualityscorescan.replace(':', '%3A')
                                                        ipqualityscorescan = ipqualityscorescan.replace('/', '%2F')
                                                        ipqualityscorescan = ipqualityscorescan.replace(' ', '%20')
                                                        ipqualityscorescan = ipqualityscorescan.replace('~', '%7E')
                                                        ipqualityscorescan = ipqualityscorescan.replace('-', '%2D')
                                                        ipqualityapi_key = "TDroJChf66VYvaWJMLnMsg9UnlQ6rsgS"
                                                        ipqualityscorescan1 = "https://ipqualityscore.com/api/json/url/"+ipqualityapi_key+"/"+ipqualityscorescan
                                                        print(ipqualityscorescan1)
                                                        with urllib.request.urlopen(ipqualityscorescan1) as urlquality:
                                                            try:
                                                                ipqualitydata = json.loads(urlquality.read().decode())
                                                                print(ipqualitydata)
                                                                print(ipqualitydata['phishing'])
                                                                print(ipqualitydata['malware'])
                                                                print(ipqualitydata['suspicious'])
                                                                if ipqualitydata['unsafe'] == True:
                                                                    maliciousLinks.append(letters)
                                                                else:
                                                                    ipqualitydataunsafe = "The domain is clean!"
                                                                ipqualitydataDomain = ipqualitydata['domain']
                                                                ipqualitydataServer = ipqualitydata['server']
                                                                ipqualitydataContenttype = ipqualitydata['content_type']
                                                                if ipqualitydata['status_code'] == 200:
                                                                    ipqualitydataStatuscode = "The domain is a valid website!"
                                                                else:
                                                                    maliciousLinks.append(letters)
                                                                if ipqualitydata['dns_valid'] == True:
                                                                    ipqualitydataDNS = "The domain has valid DNS records!"
                                                                else:
                                                                    maliciousLinks.append(letters)
                                                                if ipqualitydata['spamming'] == True:
                                                                    maliciousLinks.append(letters)
                                                                else:
                                                                    ipqualitydataSpamming = "The domain of the malicious URL is not associated with email SPAM or abusive email addresses!"
                                                                if ipqualitydata['malware'] == True:
                                                                    maliciousLinks.append(letters)
                                                                else:
                                                                    ipqualitydataMalware = "The malicious URL is not associated with malware or viruses"
                                                                if ipqualitydata['phishing'] == True:
                                                                    maliciousLinks.append(letters)
                                                                else:
                                                                    ipqualitydataPhishing = "The malicious URL is not associated with malicious phishing behavior"
                                                                if ipqualitydata['suspicious'] == True:
                                                                    maliciousLinks.append(letters)
                                                                else:
                                                                    ipqualitydataSuspicious = "The malicious URL is not suspected of being malicious or used for phishing or abuse"
                                                                ipqualitydataRiskscore = "The IPQS risk score which estimates the confidence level for malicious URL detection, 85 for high risk, 100 for accurate:"+str(ipqualitydata['risk_score'])
                                                                ipqualitydataCategory = ipqualitydata['category']
                                                                ipqualitydataDomainage = ipqualitydata['domain_age']
                                                            except HTTPError:
                                                                print("Website has been taken down or gone!")
                                                                pass
                                                    
                                                        imap_server.create('malicious')
                                                        imap_server.store(message_number, '+X-GM-LABELS', 'malicious')
                                                        imap_server.store(message_number, '+FLAGS', '\Deleted')  # read mail remove from inbox
                                                        imap_server.expunge() 
                                                        numberofcountedmail += 1
                                                        #logemails = []
                                                        #loggeddata = [getID, receivedSPF[0], getSPFIPmatch, subject, getFrom, getTo, getDate, letters]
                                                        #logemails.append(loggeddata)
                                                        #logdf = pandas.DataFrame(logemails, columns = ['messageid', 'spf', 'ipadd', 'subject', 'from', 'to', 'date', 'maliciouslink'])
                                                        #logdf.to_csv("emaillogs.csv", mode = 'a', header = False, index = False)
                                                        
                                                        #For sandbox testing environment
                                                        #Must have an account first to test out, API no clue on how to make it work
                                                        urltest = "https://live.browserstack.com/dashboard?try_live_url=https%3A%2F%2Fbtwebbusinesss.weebly.com%2F#os=Windows&os_version=10&browser=Edge&browser_version=92.0&zoom_to_fit=true&full_screen=true&resolution=responsive-mode&url="+link+"&speed=1"
                                                        webbrowser.open(urltest,new=2)
                                                        
                                        elif receivedSPF[0] != "pass":
                                            print("Subject:", subject)
                                            print("From:", getFrom)
                                            print("SPF Status:", receivedSPF[0], ". Not secure.")
                                            print("To:",getTo)
                                            print("Date:",getDate)
                                            print("ID",getID)
                                            print("SPF:",getSPF)
                                            imap_server.create('malicious')
                                            imap_server.store(message_number, '+X-GM-LABELS', 'malicious')
                                            imap_server.store(message_number, '+FLAGS', '\Deleted')  # read mail remove from inbox
                                            imap_server.expunge()
                                        else:
                                            continue
                    else:
                        if receivedSPF[0] != "pass":
                            print("Subject:", subject)
                            print("From:", getFrom)
                            print("SPF Status:", receivedSPF[0], ". Not secure.")
                            print("To:",getTo)
                            print("Date:",getDate)
                            print("ID",getID)
                            print("SPF:",getSPF)
                            imap_server.create('malicious')
                            imap_server.store(message_number, '+X-GM-LABELS', 'malicious')
                            imap_server.store(message_number, '+FLAGS', '\Deleted')  # read mail remove from inbox
                            imap_server.expunge()
                        else:
                            continue
    
    maliciousLinks = [list(set(maliciousLinks))]
    maliciousAttachments = [list(set(maliciousAttachments))]
    if maliciousLinks == []: 
        bot.send_message(
        message.chat.id,
        'There are No Malicious Links.'
        )
    else :
        bot.send_message(
        message.chat.id,
        'The follwing Links are Malicious.\n'+ format(maliciousLinks)
        )

    if maliciousAttachments == []:
        bot.send_message(
        message.chat.id,
        'There are No Malicious Attachments.'
        )
    else :
        bot.send_message(
        message.chat.id,
        'The follwing Attachments are Malicious.\n'+ format(maliciousAttachments)
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
def get_URL(message):

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

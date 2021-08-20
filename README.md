# KoiScanner

Phishing Emails has been one of the most popular attack vectors for cyber criminals. The emails sent may contain malicious links that once clicked will lead to a website that will steal login credentials or financial information of users. 

KoiScanner is a protective aid product which allows users to scan their emails for malicious URLS. This scan can be regularly set by users or on demand via Google Chrome extension, Executable UI or via instant messaging software,Telegram.This will help separate the malicious emails(including malicious urls that are caught and blacklisted) from your regular inbox.

To solve this issue, our proposed solution is to create a google extension that will scan emails for malicious urls. Our project will scan emails on a regular basis or on demand if the user chooses to do so. By implementing our project it helps the user to prevent any loss of data by ensuring that any malicious urls are caught and blacklisted.

# Disclaimers
Some Products are not working, Some API Keys have been removed and require your edits to make it work. 
If there are API Keys that require any changes, it will be stated in their own respective README.MD Files in thier own FOLDER.
Fair Warning This is just a BETA Programme. 

# Folder/Filename and It's Purposes

1) `KoiScanner_ML` are implemented Machine Learning Codes that collapsed and is not a working product.

2) `KoiScanner_UI` contains the codes that does not have Machine Learning and just regular API checking.

3) `KoiScanner_Chrome_Extension` contains the codes and scripts for the google chrome Extension.

4) `KoiScanner_TelegramBot` contains the codes of KoiScanner_UI but adjusted to accomodate for the convicence.

5) `Data.csv` is the dataset that contains both MALICIOUS AND NON-MALICIOUS URL.

6) `Malicious.csv` is the dataset that contain ONLY MALICIOUS URL. 

# Use Case Diagrams

For better clarity, please download the Images from the Images Folder.

## KoiScanner GUI and Google Chrome Extension Use Case Diagram

![Use Diagram KoiScanner Gui and Chrome](https://github.com/Serade12/KoiScanner/blob/main/Images/KOISCANNER.png)

## KoiScanner Telegram Bot Use Case Diagram

![Use Diagram KoiScanner Telegram](https://github.com/Serade12/KoiScanner/blob/main/Images/Telegram_Bot.png)

# Data Flow Diagram

This is the Data Flow Diagram for KoiScanner GUI, Chrome Extension & Telegram Bot

![Data Flow Diagram](https://github.com/Serade12/KoiScanner/blob/main/Images/DataFlow.JPG)



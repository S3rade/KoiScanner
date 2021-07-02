# KoiScanner
KoiScanner is a Software that scans for Phishing Emails. 
You get it when you get it :p

How does it work: 

When an email is sent, 
1. KoiScanner will make a copy in a temp folder 
2. Conduct a scan against a exisiting blacklisted ip and email addresses.(Meanwhile, The email will not be placed on pause and not be delivered)
3. Once the scan is not on blacklist, the email will be delivered to the user.
4. If the email is on the blacklist, the original email will be placed into a quarentine area to be review by the user where it can either be whitelisted for future.
5. If the email is on the whitelist, the original email will be sent and the copy will be deleted.
6. In a scenrio where the email is an actual spam and managed to get pass to the end user, they can mark these email as spam/junk/phishing. 
7. When the user mark these email we can use the data collected by the user to add such email and its signatures to the blacklist with the aid of machine learning. 
8. Then the AI will then update the existing list of blacklist or add it to the user's list of whitelist emails.  

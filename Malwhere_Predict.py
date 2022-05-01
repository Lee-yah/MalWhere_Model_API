# -*- coding: utf-8 -*-
"""
Created on Sat Apr 23 11:54:25 2022

@author: Leah J
"""





#user_input = "http://www.jardinerie-beloeil.be/index.php?option=com_morfeoshow&task=view&gallery=3&Itemid=100"


import xgboost as xgb
from xgboost import XGBClassifier

import io
import pandas as pd
from tld import get_tld


def Malwhere_predict(user_input):
       
        
   #Load saved Model
   model2 = xgb.XGBClassifier(n_estimators= 100)
   model2.load_model("model_sklearn.json")
    
  #get the URL
        
   user_input = io.StringIO(user_input)
        
   df2 = pd.DataFrame(user_input, columns=['url']) 
        
      
  #GET fetures
   df2['use_of_ip'] = df2['url'].apply(lambda i: having_ip_address(i))
   df2['abnormal_url'] = df2['url'].apply(lambda i: abnormal_url(i))
   df2['count-www'] = df2['url'].apply(lambda i: i.count('www'))
   df2['count_dir'] = df2['url'].apply(lambda i: no_of_dir(i))
   df2['count_embed_domian'] = df2['url'].apply(lambda i: no_of_embed(i))
   df2['short_url'] = df2['url'].apply(lambda i: shortening_service(i))
   df2['count-https'] = df2['url'].apply(lambda i : i.count('https'))
   df2['count-http'] = df2['url'].apply(lambda i : i.count('http'))
   df2['http_or_https'] = df2['url'].apply(lambda i: http_or_https(i))
   df2['count.'] = df2['url'].apply(lambda i: i.count('.'))
   df2['count@'] = df2['url'].apply(lambda i: i.count('@'))
   df2['count%'] = df2['url'].apply(lambda i: i.count('%'))
   df2['count?'] = df2['url'].apply(lambda i: i.count('?'))
   df2['count-'] = df2['url'].apply(lambda i: i.count('-'))
   df2['count/'] = df2['url'].apply(lambda i: i.count('/'))
   df2['count#'] = df2['url'].apply(lambda i: i.count('#'))
   df2['count&'] = df2['url'].apply(lambda i: i.count('&'))
   df2['count;']= df2['url'].apply(lambda i: i.count(';'))
   df2['count_'] = df2['url'].apply(lambda i: i.count('_'))
   df2['count='] = df2['url'].apply(lambda i: i.count('='))
   df2['url_length'] = df2['url'].apply(lambda i: len(str(i)))
   df2['hostname_length'] = df2['url'].apply(lambda i: len(urlparse(i).netloc))
   df2['sus_url'] = df2['url'].apply(lambda i: suspicious_words(i))
   df2['fd_length'] = df2['url'].apply(lambda i: fd_length(i))
   df2['tld'] = df2['url'].apply(lambda i: get_tld(i,fail_silently=True))
   df2['tld_length'] = df2['tld'].apply(lambda i: tld_length(i))
   df2['path_length'] = df2['url'].apply(lambda i: path_length(i))
   df2['path_to_urllength_ratio'] =  df2['path_length']/df2['url_length']
   df2['count-lowercase']= df2['url'].apply(lambda i: count_lowercase(i))
   df2['lower_to_urllength_ratio'] = df2['count-lowercase']/df2['url_length']
   df2['count_uppercase'] =  df2['url'].apply(lambda i: count_uppercase(i))
   df2['upper_to_urllength_ratio'] = df2['count_uppercase']/df2['url_length']
   df2['count-digits']= df2['url'].apply(lambda i: digit_count(i))
   df2['digit_to_urllength_ratio'] = df2['count-digits']/df2['url_length']
   df2['count-letters']= df2['url'].apply(lambda i: letter_count(i))
   df2['letters_to_urllength_ratio'] = df2['count-letters']/df2['url_length']
   df2['count-specchar']= df2['url'].apply(lambda i: spechar_count(i))
   df2['specchar_to_urllength_ratio'] = df2['count-specchar']/df2['url_length']

    
   df2 = df2.drop("tld",1)
    
   #make the suitable dataframe for predictions.
   X = df2[[
        'use_of_ip',
        'abnormal_url',
       'count.', 
        'count-www', 
       'count@',
       'count_dir', 
       'count_embed_domian', 
       'short_url', 
    #       'count-https',
    #       'count-http', 
        'count%', 'count?','count-', 
       'count=',
         
        
      'count/',
     'count#',
     'count&', 
       'count;',
      'count_', 
        'path_length',
        'path_to_urllength_ratio',
        'count_uppercase',
        'count-lowercase',
     #      'upper_to_urllength_ratio',
     #      'lower_to_urllength_ratio',
       'letters_to_urllength_ratio',
       'digit_to_urllength_ratio',
       'specchar_to_urllength_ratio',
     #      'count-specchar',
         'http_or_https',
       
       'url_length',
       'hostname_length',
         'sus_url', 
       'fd_length', 
      'tld_length', 
      'count-digits',
    #      'count-letters'
       ]]
    
   y_pred = model2.predict(X)
   prediction = str(y_pred)
   return prediction
    


#GET FEATURES FUNCTIONS START (32)


#Feature #1
import re
#Use of IP or not in domain
def having_ip_address(url):
    
    regex1=  '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|' #IPv4
    regex2=  '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.)|'#IPv4
     #IPv6
 #   regex3=  '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
    regex3=  '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|'
#   regex4=  '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}'
    regexList = [regex1,regex2,regex3]
    for regex in regexList:
        match = re.search(regex,url)
    
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

#Feature #2
from urllib.parse import urlparse
#if hostname is paired with the host in the db
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
    


def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')
#Feature #6

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')
#Feature #7


def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0


def http_or_https(url):
    urlprotocol = urlparse(url).scheme
    if urlprotocol == 'http':
        return 2
    elif urlprotocol == 'https':
        return 0
    else:
        return 1
        


#Feature #17
def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr|porn|Anniversary|Promo',
                      url)
    if match:
        return 1
    else:
        return 0

#Feature #18
#pip install tld



#Importing dependencies


#import os

#First Directory Length
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0


#Feature #19
#Length of Top Level Domain

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1


#Feature #27 PATHLength 
def path_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath)
    except:
        return -1


#Feature  count_lowercase
def count_lowercase(url):
    lowercase = 0
    for i in url:
        if i.islower():
            lowercase= lowercase + 1
    return lowercase




#Feature #29,30 PATHLength not yet
def count_uppercase(url):
    upper=sum(c.isupper() for c in url)
    try:
        return upper
    except:
        return -1




#Feature #20
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


#Feature #21
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


#Feature #32 not yet
def spechar_count(url):
    specchar=sum(not c.isalnum() for c in url)
    return specchar


#END of feature get function


#prediction = print(Malwhere_predict(user_input))

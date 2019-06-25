import requests
import numpy as np
import pandas as pd
import os
import time
import argparse
from time import sleep
from bs4 import BeautifulSoup

#Error messages 
INVALID_FILETYPE_MSG = "Error: Invalid file format. %s must be a .txt file."
INVALID_PATH_MSG = "Error: Invalid file path/name. Path %s does not exist."


def read_js_list():
    global data
    with open('lp.txt','r') as fp:
        dataa=fp.read()
    dataa=str(dataa)
    dataa=dataa.replace('\n',' ')
    dataa=dataa.replace('\t',' ')
    data=(dataa.split(' '))
    return data

#HTML parser
def html_parser(url,soup):

    soup_str=str(soup)                                                 #Converting the BeautifulSoup object into string 
    
    length_of_doc=len(soup_str)                                        #Finding the total length of the document
    
    iframes=soup.find_all('iframe')                                    #Finding the number of iframes
    no_of_iframes=len(iframes)
    
    iframe_src=[url+i["src"] for i in soup.find_all("iframe",src=True)] #Number of iframes links
    no_of_iframelinks=len(iframe_src)

    js_src=[url+i["src"] for i in soup.find_all("script",src=True)]     #Number of Javascript links
    no_of_jslinks=len(js_src)

    hyperlinks=soup.find_all('a')                                       #Finding the number of hyperlinks
    no_of_hyperlinks=len(hyperlinks)
    
    tags=[]                                                             #Finding the types and number of tags 
    for tag in soup.find_all(True):
        tags.append(tag.name)
    uniq,counts=np.unique(tags,return_counts=True)
    tag_n_count=dict(zip(uniq,counts))

    tag_types=len(uniq)
    
    j=0                                                            #Finding the number of symmetrical and assymmetrical HTML tags
    utag_count=0
    stag_count=0
    for i in tag_n_count:
        if(tag_n_count[i]%2!=0):
            utag_count=(utag_count)+(tag_n_count[i])
        else:
            stag_count=stag_count+(tag_n_count[i])
            
    hidden_objs=soup_str.count('"hidden"')                              #Finding the number of hidden objects occurences
    
    concat=soup_str.count('concat')                                     #Finding the number of string concatenation functions
    
    html['Length_of_document']=html['Length_of_document']+length_of_doc
    print('\nLength of the document is : ',length_of_doc)

    html['No_of_iframes']=html['No_of_iframes']+no_of_iframes
    print('\nNumber of iframes : ',no_of_iframes)

    html['No_of_iframelinks']=html['No_of_iframelinks']+no_of_iframelinks
    print('\nNo. of iframes links : ',no_of_iframelinks)

    html['No_of_jslinks']=html['No_of_jslinks']+no_of_jslinks
    print('\nNo. of javascript links : ',no_of_jslinks)

    html['No_of_hyperlinks']=html['No_of_hyperlinks']+no_of_hyperlinks
    print('\nNumber of hyperlinks is : ',no_of_hyperlinks)

    html['Types_of_tags']=html['Types_of_tags']+tag_types
    print('\nThe types of tags is :',tag_types)
    
    html['Unsymmetrical_tags']=html['Unsymmetrical_tags']+utag_count
    html['Symmetrical_tags']=html['Symmetrical_tags']+stag_count
    print('\nThe number of assymmetrical HTML tags to symmetrical tags is : ',utag_count,':',stag_count)

    html['Hidden_objects']=html['Hidden_objects']+hidden_objs
    print('\nThe number of hidden objects occurences is : ',hidden_objs)

    html['No_of_concatenation']=html['No_of_concatenation']+concat
    print('Concatenation : ',concat)
    
    ###Extracting the client side javascript features
    
    data=read_js_list()                     #Reading in the js keywords into a list

    a=0
    for x in data:                          #Counting the number of javascript keywords
        a=a+soup_str.count(str(x))


    escape=soup_str.count('escape')
    unescape=soup_str.count('unescape')  
    link=soup.find_all('link')
    linko=len(link)
    execo=soup_str.count('execo')
    search=soup_str.count('search')
    evalo=soup_str.count('eval')
    decode=soup_str.count('decodeURI')
    encode=soup_str.count('encodeURI')
    concat=soup_str.count('concat')
    
    js['Keywords']=js['Keywords']+a
    print('No. of keywords is : ',a)

    js['escape']=js['escape']+escape
    print('Escape : ',escape)

    js['unescape']=js['unescape']+unescape
    print('Unescape : ',unescape)

    js['link']=js['link']+linko
    print('Link : ',linko)

    js['execo']=js['execo']+execo
    print('Exec : ',execo)

    js['search']=js['search']+search
    print('Search : ',search)

    js['eval']=js['eval']+evalo
    print('Eval : ',evalo)

    js['decode']=js['decode']+decode
    print('decodeURI : ',decode)

    js['encode']=js['encode']+encode
    print('encodeURI : ',encode)

    js['concat']=js['concat']+concat
    print('Concatenation : ',concat)
            
    return 0

#Javascript parser for associated files
def jsparser_links(url,r):
    
    soup=opening_url(url,r)
    
    if(soup==0):
        return 0 
    
    soup_str=str(soup)                                        #Converting the BeautifulSoup object into string 
    
    data=read_js_list()                                                #Reading in the js keywords into a list
    
    length_of_jsdoc=len(soup_str)                                     #Finding the total length of the document
    
    iframes=soup.find_all('iframe')                                              #Finding the number of iframes
    no_of_jsiframes=len(iframes)

    a=0
    for x in data:                                                             #Counting the number of keywords
        a=a+soup_str.count(str(x))
    
    escape=soup_str.count('escape')
    unescape=soup_str.count('unescape')  
    link=soup.find_all('link')
    linko=len(link)
    execo=soup_str.count('execo')
    search=soup_str.count('search')
    evalo=soup_str.count('eval')
    decode=soup_str.count('decodeURI')
    encode=soup_str.count('encodeURI')
    concat=soup_str.count('concat')
 
    js['Length_of_document']=js['Length_of_document']+length_of_jsdoc
    print('Length of the document : ',length_of_jsdoc)
    
    js['No_of_iframes']=js['No_of_iframes']+no_of_jsiframes
    print('Number of iframes : ',no_of_jsiframes)
    
    js['Keywords']=js['Keywords']+a
    print('No. of keywords is : ',a)
    
    js['escape']=js['escape']+escape
    print('Escape : ',escape)

    js['unescape']=js['unescape']+unescape
    print('Unescape : ',unescape)
    
    js['link']=js['link']+linko
    print('Link : ',linko)
    
    js['execo']=js['execo']+execo
    print('Exec : ',execo)

    js['search']=js['search']+search
    print('Search : ',search)
    
    js['eval']=js['eval']+evalo
    print('Eval : ',evalo)
    
    js['decode']=js['decode']+decode
    print('decodeURI : ',decode)
    
    js['encode']=js['encode']+encode
    print('encodeURI : ',encode)

    js['concat']=js['concat']+concat
    print('Concatenation : ',concat)
   
    return 0



#Function which calls the html and javascript parser
def parsero(url,r):
    
    soup=opening_url(url,r)                                            #Page retrieval request through the function call
    
    if(soup==0):
        return 0
    html_parser(url,soup)                            #Function called for the parsing of the necessary HTML elements

    iframe_src=[i["src"] for i in soup.find_all("iframe",src=True)]            #Finding the related iframe files
    js_src=[i["src"] for i in soup.find_all("script",src=True)]            #Finding the related javascript files   

    ###Related iframe scraping        
    if(len(iframe_src)):
        for irr in iframe_src:                                                     #Looping through the iframes serially
            if(url.count(irr)<=1):
                ur=url+str(irr)
                parsero(ur,r)
            
    ###Related javascript scraping
    print(len(js_src))
    if(len(js_src)):
        read_js_list()                                                #Reading in the js keywords into a list
        for jrr in js_src:                                      #Looping through the javascript files serially
            print('oneeeee')
            if(url.count(jrr)<=1):
                print('twooooo')
                ur=url+str(jrr)
                jsparser_links(ur,r)                               #Function called for the related javascript files parsing

    return 0

def opening_url(url,r):

    page=r.get(url)                                #Retrieving the page 
    
    if(page.status_code==200):                            #Check for the correct response
        print('Page ',url,' retrieve success')
        soup=BeautifulSoup(page.content,'html.parser')    #Making of the BeautifulSoup object
        
        return soup
    
    else:
        print('Page retrieve failure')
        time.sleep(0.2)
        return 0

def validate_file(file_name):
    
    if not valid_path(file_name):
        print(INVALID_PATH_MSG%(file_name))
        quit()
    
    elif not valid_filetype(file_name):
        print(INVALID_FILETYPE_MSG%(file_name))
        quit()
    
    return

def valid_filetype(file_name):
    
    return file_name.endswith('.txt')   # validate file type 

def valid_path(path):
    
    return os.path.exists(path)        # validate file path 

def check(file_name):              
    
    validate_file(file_name)          # validate the file name/path
    
    return 

def writingfile(df_html,df_js):
    with open('htmlFinal.csv','a') as fh:
        df_html.to_csv(fh,header=False)
    with open('jsFinal.csv','a') as fj:
        df_js.to_csv(fj,header=False)
    #filename="htmlFinal"
    #filename=filename+".csv"
    #df_html.to_csv(filename,index=False,sep=',')
    print('The file has been written with name')
    #filename="jsFinal"
    #filename=filename+".csv"
    #df_js.to_csv(filename,index=False,sep=',')
    print('The file has been written with name')
    return 

def main():
    
    #Defining the command line arguments
    parser=argparse.ArgumentParser()
    
    parser.add_argument('--url',type=str,help='Specify the file containing urls to be scraped')
    parser.add_argument('--filename',type=str,help='Specify url to be scraped')
    parser.add_argument('--proxy',type=str,help='Specify proxy or not')
    
    args=parser.parse_args()
    
    if(args.url is None and args.filename is None):              #If neither the url or filename is provided then it quits
        print('URL or filename not specified')
        quit()

    r=requests.session()                                                     #Creating a session for all the page requests
    
    if(args.proxy is not None):                                             #Checking if the proxy is user provided or not
        proxies={'http':args.proxy}
        r.proxies.update(proxies)
    
    global html
    global js
    slno=1
    html=dict.fromkeys(['URL','Length_of_document','No_of_iframes','No_of_iframelinks','No_of_jslinks',
                        'No_of_hyperlinks','Types_of_tags','Unsymmetrical_tags','Symmetrical_tags','Hidden_objects',
                        'No_of_concatenation','Category'],0)
    js=dict.fromkeys(['URL','Length_of_document','No_of_iframes','Keywords','escape','unescape','link','execo',
                      'search','eval','decode','encode','concat','Category'],0)
    
    #Defining the dataframes for the html and javascript features
    df_html=pd.DataFrame(columns=['URL','Length_of_document','No_of_iframes','No_of_iframelinks','No_of_jslinks',
                                  'No_of_hyperlinks','Types_of_tags','Unsymmetrical_tags','Symmetrical_tags','Hidden_objects',
                                  'No_of_concatenation','Category'])
    df_js=pd.DataFrame(columns=['URL','Length_of_document','No_of_iframes','Keywords','escape','unescape','link','execo',
                                'search','eval','decode','encode','concat','Category'])

    if(args.url is not None):          #Checking if the user provided with the url
        parsero(args.url,r)
        df_html=df_html.append({'URL':args.url,'Length_of_document':html['Length_of_document'],
                               'No_of_iframes':html['No_of_iframes'],'No_of_iframelinks':html['No_of_iframelinks'],
                                'No_of_jslinks':html['No_of_jslinks'],'No_of_hyperlinks':html['No_of_hyperlinks'],
                                'Types_of_tags':html['Types_of_tags'],'Unsymmetrical_tags':html['Unsymmetrical_tags'],
                                'Symmetrical_tags':html['Symmetrical_tags'],'Hidden_objects':html['Hidden_objects'],
                                'No_of_concatenation':html['No_of_concatenation'],'Category':0},ignore_index=True)
        df_js=df_js.append({'URL':args.url,'Length_of_document':js['Length_of_document'],'No_of_iframes':js['No_of_iframes'],
                           'Keywords':js['Keywords'],'escape':js['escape'],'unescape':js['unescape'],'link':js['link'],
                           'execo':js['execo'],'search':js['search'],'eval':js['eval'],'decode':js['decode'],
                           'encode':js['encode'],'concat':js['concat'],'Category':0},ignore_index=True)
    
    if(args.filename is not None):                                         #Checking if the user provided with the filename
        check(args.filename)                                                #Checking for the validityof file type and path
        urls=[line.rstrip('\n') for line in open(args.filename)]                         #Extracting the urls form the file
        for ur in urls:
            if(ur.count('.')==1):
                ur='http://www.'+ur
                ur=ur+'/'
            elif(ur.count('.')>=2):
                ur='http://'+ur
                ur=ur+'/'
            parsero(ur,r)
            df_html=df_html.append({'URL':ur,'Length_of_document':html['Length_of_document'],'No_of_iframes':html['No_of_iframes'],
                           'No_of_iframelinks':html['No_of_iframelinks'],'No_of_jslinks':html['No_of_jslinks'],
                           'No_of_hyperlinks':html['No_of_hyperlinks'],'Types_of_tags':html['Types_of_tags'],
                           'Unsymmetrical_tags':html['Unsymmetrical_tags'],'Symmetrical_tags':html['Symmetrical_tags'],
                           'Hidden_objects':html['Hidden_objects'],'No_of_concatenation':html['No_of_concatenation'],
                           'Category':0},ignore_index=True)
            df_js=df_js.append({'URL':ur,'Length_of_document':js['Length_of_document'],'No_of_iframes':js['No_of_iframes'],
                           'Keywords':js['Keywords'],'escape':js['escape'],'unescape':js['unescape'],'link':js['link'],
                           'execo':js['execo'],'search':js['search'],'eval':js['eval'],'decode':js['decode'],
                           'encode':js['encode'],'concat':js['concat'],'Category':0},ignore_index=True)

            html=dict.fromkeys(['URL','Length_of_document','No_of_iframes','No_of_iframelinks','No_of_jslinks',
                                'No_of_hyperlinks','Types_of_tags','Unsymmetrical_tags','Symmetrical_tags','Hidden_objects',
                                'No_of_concatenation','Category'],0)
            js=dict.fromkeys(['URL','Length_of_document','No_of_iframes','Keywords','escape','unescape','link','execo',
                              'search','eval','decode','encode','concat','Category'],0)
            
            print('****************************** ',slno,'th WEBSITE SCRAPED  ******************************************')
            slno=slno+1
            time.sleep(0.2)
    writingfile(df_html,df_js)
    
if __name__=='__main__':
    main()

import re#-1 for phising or 1 for legitimate

#1.having_ip_address

def category1(url):
        
    match = re.search('[0-9]{1,3}[.]+?[0-9]{1,3}[.]+?[0-9]{0,3}[.]+?[0-9]{1,3}',url)
    file_obj = open(r'D:\AI\week3\Phishing\phishing5.txt','w')
    if match!=None:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')
    #2.url_length
    if len(url)<54:
        file_obj.write('1,')
    elif len(url)<=75 and len(url)>=54:
        file_obj.write('0,')
    else:
        file_obj.write('-1,')
    #3. Tiny_url
    if len(url)<22:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')
    #4.@_matching
    at_match = re.search('[@]+?',url)
    if at_match != None:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')
    #5.//_finding
    dble_slash_match = re.findall('//',url)
    if len(dble_slash_match)>1:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')
    #6. - finding
    dash_match = re.search('-',url)
    if dash_match:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')
    #7.https_ token in link
    https_match = re.search('https-',url)
    if https_match:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')
    
    file_obj.close()

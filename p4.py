import whois
import re
from bs4 import BeautifulSoup
import urllib.request


def category4(website):
        
    file_obj = open(r'D:\AI\week3\Phishing\phishing5.txt','a')
    #15Age of Domain
    
    whois_page = whois.whois(website)
    if whois_page:
        if type(whois_page.expiration_date) == list:
            if len(whois_page.expiration_date) > 1 and len(whois_page.creation_date) > 1:
                age_of_domain = (whois_page.expiration_date[0] - whois_page.creation_date[0]).days
        else:
            age_of_domain = (whois_page.expiration_date - whois_page.creation_date).days
    #print age_of_domain
        if age_of_domain >= 182:
            file_obj.write('1,')
        else:
            file_obj.write('-1,')
    #16DNS Record
        file_obj.write('1,')
    else:
        file_obj.write('-1,')
        
    #17Statistical-Reports Based Feature
    if type(whois_page.domain_name) == list:
        host_name = whois_page.domain_name[0].lower()
    elif type(whois_page.domain_name) == str:
        host_name = whois_page.domain_name.lower()
    
    page = urllib.request.urlopen('https://www.phishtank.com/phish_search.php?verified=u&active=y')
    soup = BeautifulSoup(page,'html.parser')
    #print len(trs)    
    tds = soup.findAll('td',{'class':'value'})
    for val in tds:
        match_link = re.search('([http]*[https]*:[-/?.a-z0-9A-Z]+)',str(val))
        if match_link:
            #print match_link.group()
            match_host_name = re.search(host_name,match_link.group())
            if match_host_name:
                #print 'phishing website'
                file_obj.write('-1,')
                break
            else:
                file_obj.write('1,')
                break
    
    #print tds,'\n'    
    file_obj.close()

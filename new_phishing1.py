# Purpose -
# Running this file (stand alone) - For extracting all the features from a web page for testing.
# Notes -
# 1 stands for legitimate
# 0 stands for suspicious
# -1 stands for phishing

from bs4 import BeautifulSoup
import urllib
import bs4
import re
import socket
import whois
#from whois import query
from datetime import datetime
import time
import requests
# https://breakingcode.wordpress.com/2010/06/29/google-search-python/
# Previous package structure was modified. Import statements according to new structure added. Also code modified.
from googlesearch import search

# This import is needed only when you run this file in isolation.
import sys

from patterns import *

# Path of your local server. Different for different OSs.

#1 IP Address
def having_ip_address(domain):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, domain)
    return -1 if match else 1

#2 URL length
def url_length(url):
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return -1

#3 TinyURL
def shortening_service(url):
    match = re.search(shortening_services, url)
    return -1 if match else 1

#4 Having “@" symbol in URL
def having_at_symbol(url):
    match = re.search('@', url)
    return -1 if match else 1

#5 Using “//" symbol
def double_slash_redirecting(url):
    # since the position starts from 0, we have given 6 and not 7 which is according to the document.
    # It is convenient and easier to just use string search here to search the last occurrence instead of re.
    pattern = "https://|http://"
    pre_pattern_match = re.search(pattern, url)

    if pre_pattern_match:
        #url = url[pre_pattern_match.end():]
        last_double_slash = url.rfind('//')
        return -1 if last_double_slash >6 else 1
    else:
        last_double_slash = url.rfind('//')
        if last_double_slash >= 0:
            return -1 
        else:
            return 1

#6 Having “-" in domain name
def prefix_suffix(domain):
    match = re.search('-', domain)
    return -1 if match else 1

#7 Dots in domain
def having_sub_domain(url):
    # Here, instead of greater than 1 we will take greater than 2 since the greater than 1 condition is when the
    # country domain dots are skipped
    # Accordingly other dots will increase by 1
    domain = get_hostname_from_url(url)
    if having_ip_address(domain) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    match2 = re.search('www.', url)
    if match2:
        pos = match2.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 2:
        return 1
    elif len(num_dots) == 3:
        return 0
    else:
        return -1


#8 Domain Registration length       
def domain_registration_length(domain):
    expiration_date = domain.expiration_date
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')
    if (domain.expiration_date == None):
        return -1
        
    registration_length = 0
    # Some domains do not have expiration dates. This if condition makes sure that the expiration date is used only
    # when it is present.
    type(expiration_date)
    if (isinstance(expiration_date, list)):
        expiration_date = min(expiration_date)
    else:
        expiration_date = expiration_date
    
    if expiration_date:
        registration_length = abs((expiration_date - today).days)
    #print(registration_length)
    return -1 if registration_length / 365 <= 1 else 1

#9 Favicon (Favorite Icon)
def favicon(wiki, soup, domain):
    for head in soup.find_all('head'):
        #print(head)
        for icon_link in soup.find_all('link', rel="shortcut icon"):# found in wikipedia
            if icon_link != None :
                #print(icon_link['href'])
                dots = [x.start(0) for x in re.finditer(r'\.', icon_link['href'])]
                return 1 if wiki in icon_link['href'] or len(dots) == 1 or domain in icon_link['href'] else -1
        for icon_link in soup.find_all('link', rel="image_src"):
            if icon_link != None :
                #print(icon_link['href'])
                dots = [x.start(0) for x in re.finditer(r'\.', icon_link['href'])]
                return 1 if wiki in icon_link['href'] or len(dots) == 1 or domain in icon_link['href'] else -1
           
    return 1


#10 “HTTPS" on domain
def https_token(url):
    match = re.search(http_https, url)
    if match and match.start() == 0:
        url = url[match.end():]
    match = re.search('http|https', url)
    return -1 if match else 1

#11 Request URL
def request_url(wiki, soup, domain):
    i = 0
    success = 0
    for img in soup.find_all('img', src=True):
        dots = [x.start() for x in re.finditer(r'\.', img['src'])]
        if wiki in img['src'] or domain in img['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for audio in soup.find_all('audio', src=True):
        dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
        if wiki in audio['src'] or domain in audio['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for embed in soup.find_all('embed', src=True):
        dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
        if wiki in embed['src'] or domain in embed['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for i_frame in soup.find_all('i_frame', src=True):
        dots = [x.start() for x in re.finditer(r'\.', i_frame['src'])]
        if wiki in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    try:
        percentage = ( success / float(i)) * 100
    except:
        return 1

    if percentage < 22.0:
        return 1
    elif 22.0 <= percentage < 61.0:
        return 0
    else:
        return -1

#12 Using <a>tags
def url_of_anchor(wiki, soup, domain):
    i = 0
    unsafe = 0
    for a in soup.find_all('a', href=True):
        # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and ::
        # might not be
        # there in the actual a['href']
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                wiki in a['href'] or domain in a['href']):
            unsafe = unsafe + 1
        i = i + 1
        # print a['href']
    try:
        percentage = (unsafe / float(i)) * 100
    except:
        return 1
    if percentage < 31.0:
        return 1
        # return percentage
    elif 31.0 <= percentage <= 67.0:
        return 0
    else:
        return -1


#13  Links in <Script> and <Link> tags
#wiki is the url
def links_in_tags(wiki, soup, domain):
    i = 0
    success = 0
    for link in soup.find_all('link', href=True):
        dots = [x.start() for x in re.finditer(r'\.', link['href'])]
        if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for script in soup.find_all('script', src=True):
        dots = [x.start() for x in re.finditer(r'\.', script['src'])]
        if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1
    try:
        percentage = (success / float(i)) * 100
    except:
        return 1

    if percentage < 17.0:
        return 1
    elif 17.0 <= percentage <= 81.0:
        return 0
    else:
        return -1

# 14 Server Form Handler (SFH)
# Have written conditions directly from word file..as there are no sites to test ######
def sfh(wiki, soup, domain):
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            return -1
        elif wiki not in form['action'] and domain not in form['action']:
            return 0
        else:
            return 1
        
    return 1


# 15 Submitting Information to Email
#PHP mail() function is difficult to retrieve, hence the following function is based on mailto
def submitting_to_email(soup):
    for form in soup.find_all('form', action=True):
        #print(form['action'])
        return -1 if "mailto:" in form['action'] else 1
    # In case there is no form in the soup, then it is safe to return 1.
    return 1

#16 Abnormal URL
def abnormal_url(domain, url):
    
    hostname = domain.domain_name
    type(hostname)
    if (isinstance(hostname, list)):
        hostname = hostname[1]
    else:
        hostname = hostname

    if (hostname != None):
        match = re.search(hostname, url)
        return 1 if match else -1
    return -1

        
# 17 IFrame Redirection
def i_frame(soup):
    for i_frame in soup.find_all('iframe'):
        a = i_frame.get('height')
        b = i_frame.get('width')
        c = i_frame.get('frameborder')
        if a == "0" and b == "0" and c == "0":
            return -1
        if a == "0" or b == "0" or c == "0":
            return 0

    return 1

#18 Age of Domain
def age_of_domain(domain):
    #domain = whois.whois(domain)
    creation_date = domain.creation_date
    expiration_date = domain.expiration_date
    ageofdomain = 0
    if (domain.creation_date == None or domain.expiration_date == None):
        return -1
    type(creation_date)
    type(expiration_date)
    if (isinstance(creation_date, list)):
        b = creation_date[1]
    else:
        b = creation_date

    if (isinstance(expiration_date, list)):
        a = expiration_date[1]
    else:
        a = expiration_date


    ageofdomain= abs(a - b).days
    if ageofdomain/30 < 6:
       return -1
    else:
        return 1
# 19 DNS (Domain Name System) record
def DNS(domain):
    try:
        socket.gethostbyname(domain)
        return 1
    except socket.error:
        return -1

# 20 Website Traffic	
def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']

    except TypeError:
        return -1
    rank = int(rank)
    return 1 if rank < 100000 else 0


#21 Google Index
def google_index(url):

    for link in search(url, stop=1):
        if (isinstance(link, str)):
            return 1
    return -1

#22 Statistical-Reports Based Feature
def statistical_report(url, hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        return -1
    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ip_match = re.search(
        '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
        ip_address)
    if url_match:
        return -1
    elif ip_match:
        return -1
    else:
        return 1


def get_hostname_from_url(url):
    hostname = url
    # TODO: Put this pattern in patterns.py as something like - get_hostname_pattern.
    pattern = "https://www.|http://www.|https://|http://|www."
    pre_pattern_match = re.search(pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]
            post_pattern_match = re.search(":", hostname)
            if post_pattern_match:
                hostname = hostname[:post_pattern_match.start()]

    return hostname


# TODO: Put the DNS and domain code into a function.


def main(url):
    
   # with open(LOCALHOST_PATH + DIRECTORY_NAME + '/markup.txt', 'r') as file:
    #    soup_string = file.read()
    
    status = []
    hostname = get_hostname_from_url(url)
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -999
        
    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
  #      "name": hostname
    })

     #Extracts global rank of the website
    try:
        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        global_rank = -1
    
        

    

    status.append(having_ip_address(hostname))
    status.append(url_length(url))
    status.append(shortening_service(url))
    status.append(having_at_symbol(url))
    status.append(double_slash_redirecting(url))
    status.append(prefix_suffix(hostname))
    status.append(having_sub_domain(url))

    dns = 1
    try:
        domain = whois.whois(hostname)
    except:
        dns = -1
    
    status.append(-1 if dns == -1 else domain_registration_length(domain))

    status.append(-1 if soup == -999 else favicon(url, soup, hostname))
    status.append(https_token(url))
    status.append(-1 if soup == -999 else request_url(url, soup, hostname))
    status.append(-1 if soup == -999 else url_of_anchor(url, soup, hostname))
    status.append(-1 if soup == -999 else links_in_tags(url, soup, hostname))
    status.append(-1 if soup == -999 else sfh(url, soup, hostname))
    status.append(-1 if soup == -999 else submitting_to_email(soup))

    status.append(-1 if dns == -1 else abnormal_url(domain, url))
    
    status.append(-1 if soup == -999 else i_frame(soup))

    status.append(-1 if dns == -1 else age_of_domain(domain))

    status.append(DNS(hostname))

    status.append(-1 if soup == -999 else web_traffic(soup))
    status.append(google_index(url))
    status.append(statistical_report(url, hostname))

   # print('\n1. Having IP address\n2. URL Length\n3. URL Shortening service\n4. Having @ symbol\n'
    #      '5. Having double slash\n6. Having dash symbol(Prefix Suffix)\n7. Having multiple subdomains\n'
     #     '8. SSL Final State\n9. Domain Registration Length\n10. Favicon\n11. HTTP or HTTPS token in domain name\n'
      #    '12. Request URL\n13. URL of Anchor\n14. Links in tags\n15. SFH\n16. Submitting to email\n17. Abnormal URL\n'
       #   '18. IFrame\n19. Age of Domain\n20. DNS Record\n21. Web Traffic\n22. Google Index\n23. Statistical Reports\n')
    #print('n1. Having IP address\n2. URL Length\n3. URL Shortening service\n4. Having @ symbol'
     #     '\n5. Having double slash\n6. Having dash symbol(Prefix Suffix)\n7. Having multiple subdomains\n9. Domain Registration Length\n10. Favicon\n12.'
      #   ' HTTP or HTTPS token in domain name\n''13. Request URL\n14. URL of Anchor\n15. Links in tags\n16. SFH\n17. Submitting to email\n18. Abnormal URL'
       #   '\n23 IFrame\n24. Age of Domain\n25. DNS Record\n26. Web Traffic\n'
        #  '28. Google Index\n30.Statistical Reports')
    #print(status)
    return status




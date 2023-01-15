import ipaddress
import re
import urllib
import urllib.request
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import whois

def dns(url):
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    return dns

# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip

# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
    if "@" in url:
        at = 1    
    else:
        at = 0    
    return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1            
  return length

# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth+1
    return depth
#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

# 12.Web traffic (Web_Traffic)
def web_traffic(url):
  try:
    #Filling the whitespaces in the URL if any
    url = urllib.parse.quote(url)
    rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
        "REACH")['RANK']
    rank = int(rank)
  except TypeError:
        return 1
  if rank <100000:
    return 1
  else:
    return 0

def ServerFormHandler(url):
    try:
        if len(BeautifulSoup(requests.get(url).text, 'html.parser').find_all('form', action=True))==0:
            return 1
        else :
            for form in BeautifulSoup(requests.get(url).text, 'html.parser').find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif getDomain(url) not in form['action']:
                    return 0
                else:
                    return 1
    except:
        return -1

# 22. UsingPopupWindow
def UsingPopupWindow(url):
    try:
        if re.findall(r"alert\(", requests.get(url).text):
            return 1
        else:
            return -1
    except:
        return -1

# 18.Checks the number of forwardings (Web_Forwards)    
def forwarding(url):
    try:
        response = requests.get(url)
        if response == "":
            return 1
        else:
            if len(response.history) <= 2:
                return 0
            else:
                return 1
    except:
        return 1


# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(url):
    try:
        response = requests.get(url)
        if response == "":
            return 1
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                return 1
            else:
                return 0
    except:
        return 1

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
def domainAge(domain_name):
    try:
        whois_response = whois.whois(domain_name)
        creation_date = whois_response.creation_date
        expiration_date = whois_response.expiration_date
        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
            try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                age = 1
            else:
                age = 0
        return age
    except:
        return 1

def iframe(url):
    try:
        response = requests.get(url)
    except:
        response = ""
    
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1

# 14.End time of domain: The difference between termination time and current time (Domain_End) 
def domainEnd(domain_name):
    try:
        whois_response = whois.whois(domain_name)
        expiration_date = whois_response.expiration_date
        if isinstance(expiration_date,str):
            try:
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None):
            return 1
        elif (type(expiration_date) is list):
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if ((end/30) < 6):
                end = 0
            else:
                end = 1
        return end
    except:
        return 1

# 11. NonStdPort
def NonStdPort(domain_name):
    try:
        port = domain_name.split(":")
        if len(port)>1:
            return -1
        return 1
    except:
        return -1

# 1.Domain of the URL (Domain) 
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.",domain):
        domain = domain.replace("www.","")
    return domain

def mouseOver(url): 
    try:
        response = requests.get(url)
    except:
        response = ""

    if response == "" :
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0

def forwarding(url):
    try:
        response = requests.get(url)
    except:
        response = ""

    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1

def prefixSuffix(url):
        if '-' in urlparse(url).netloc:
            return 1            # phishing
        else:
            return 0            # legitimate
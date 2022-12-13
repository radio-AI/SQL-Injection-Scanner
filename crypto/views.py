from django.shortcuts import render
from django.http import HttpResponse

import sys,  re,  urllib, string
import urllib.request as urllib2
from urllib.request import Request,  urlopen,  URLError,  HTTPError
from urllib.parse import urlparse


def URL_TESTING(Site_URL):
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
    Get_URL = urllib2.Request(Site_URL)
    Get_URL.add_header("User-Agent",  user_agent)

    print ("[i] Checking if a connection can be established...")
    try:
        http_URL_test = urllib2.urlopen(Get_URL)
    except (HTTPError):
        print ("[!] The connection couldn't be established.")
        print ("[!] Error code: ",  re.code)
        print ("[!] Exiting now!")
        print ("")
        print ("")
        sys.exit(1)
    except (URLError):
        print ("[!] The connection couldn't be established.")
        print ("[!] Reason: ",  re.reason)
        print ("[!] Exiting now!")
        print ("")
        print ("")
        sys.exit(1)
    else:
        print ("[i] Connected to target! URL seems to be valid.")
    return

def URL_SCANNING(Site_URL):
    SQL_ERR_1 = "You have an error in your SQL syntax"
    SQL_ERR_2 = "supplied argument is not a valid MySQL result resource"
    SQL_ERR_3 = "check the manual that corresponds to your MySQL"
    PARM_EQ = "="
    PARM_SGN_1 = "?"
    PARM_SGN_2 = "&"
    TRIGGER_ERR_1 = "'"
    TRIGGER_ERR_2 = "-1"

    VULN_PARAM = {}
    exploit_urls = list()

    user_agent = "MMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36" 
    Get_URL = urllib2.Request(Site_URL)
    Get_URL.add_header("User-Agent",  user_agent)

    try:
        CALL_HTTP = urllib2.urlopen(Get_URL)
    except (HTTPError):
        print ("[!] The connection could not be established.")
        print ("[!] Error code: ", re.code)
        print ("[!] Exiting now!")
        print ("")
        print ("")
        sys.exit(1)
    except (URLError):
        print ("[!] The connection could not be established.")
        print ("[!] Reason: ",  re.reason)
        print ("[!] Exiting now!")
        print ("")
        print ("")
        sys.exit(1)  

    FULL_HTML_CODE = CALL_HTTP.read()
    FULL_HTML_CODE = FULL_HTML_CODE.decode('ISO-8859-1')

    PARSED_URL = urlparse(Site_URL)
    print ("")
    print ("[i] Server/Domain is:",  PARSED_URL.netloc)
    if len(PARSED_URL.path) == 0:
        print ("[!] The URL doesn't contain a script")
    else:
        print ("[i] Detected the path to the script:",  PARSED_URL.path)
    if len(PARSED_URL.query) == 0:
        print ("[!] The URL doesn't contain a query string")
    else:
        print ("[i] Detected the URL query string:",  PARSED_URL.query)
        print ("")

    SRCH_SQL_ERR_1 = re.findall(SQL_ERR_1, FULL_HTML_CODE)
    if len(SRCH_SQL_ERR_1) != 0:
        print ("[!] SQL error in the original URL/website found.")
        print ("[!] There might be problems exploiting this website (if it is vulnerable).")
    
    SRCH_SQL_ERR_2 = re.findall(SQL_ERR_2,  FULL_HTML_CODE)
    if len(SRCH_SQL_ERR_2) != 0:
        print ("[!] SQL error in the original URL/website found.")
        print ("[!] There might be problems exploiting this website (if it is vulnerable).")
    
    SRCH_SQL_ERR_3 = re.findall(SQL_ERR_3,  FULL_HTML_CODE)
    if len(SRCH_SQL_ERR_3) != 0:
        print ("[!] SQL error in the original URL/website found.")
        print ("[!] There might be problems exploiting this website (if it is vulnerable).")

    if PARM_SGN_1 in Site_URL and PARM_EQ in Site_URL:
        print ("[i] It seems that the URL contains at least one parameter.")
        print ("[i] Trying to find also another parameters...")

        if PARM_SGN_2 in PARSED_URL.query and PARM_EQ in PARSED_URL.query:
            print ("[i] Also found at least one other parameter in the URL.")
        else:
            print ("[i] No other parameters were found.")
        
    else:
        print ("")
        print ("[!] It seems that there is no parameter in the URL.")
        print ("[!] Please provide an URL with a script and query string.")
        print ("[!] Example: target/index.php?cat=1&article_id=2")
        print ("[!] Exiting now!")
        return ("Enter Proper URL")
        print ("")
        print ("")
        sys.exit(1)

    PARAMS = dict([part.split('=') for part in PARSED_URL[4].split('&')])

    PARAM_CNTR = len(PARAMS)

    print ("[i] The following", PARAM_CNTR, "parameter(s) was/were found:")
    print ("[i]",  PARAMS)
    print ("[i] Starting to scan the provided URL(s) for SQL injection vulnerabilities.")
    print ("")

    for index, item in enumerate(PARAMS):
        print ("[i] Probing parameter \"",  item, "\"...")

        QUERY_FOR_REPLACE = "".join(PARSED_URL[4:5])
        MODIFIED_QUERY = QUERY_FOR_REPLACE.replace(PARAMS[item],  TRIGGER_ERR_1)

        TRIGGER_URL_1_P1 = "".join(PARSED_URL[0:1]) + "://"
        TRIGGER_URL_1_P2 = "".join(PARSED_URL[1:2])
        TRIGGER_URL_1_P3 = "".join(PARSED_URL[2:3])  + "?"  
        TRIGGER_URL_1_P4 = "".join(MODIFIED_QUERY)  
        TRIG_URL_1 = TRIGGER_URL_1_P1 + TRIGGER_URL_1_P2 + TRIGGER_URL_1_P3 + TRIGGER_URL_1_P4

        try:
            HTTP_CALL_TRIGGER_1 = urllib2.urlopen(TRIG_URL_1)
        except (HTTPError):
            print ("[!] The connection could not be established.")
            print ("[!] Error code: ",  re.code)
        except (URLError):
            print ("[!] The connection could not be established.")
            print ("[!] Reason: ",  re.reason)

        HTML_CALL_TRIGGER_1 = HTTP_CALL_TRIGGER_1.read()
        HTML_CALL_TRIGGER_1 = HTML_CALL_TRIGGER_1.decode('ISO-8859-1')

        SRCH_SQL_ERR_TRIGG_1 = re.findall(SQL_ERR_1, HTML_CALL_TRIGGER_1)
        SRCH_SQL_ERR_TRIGG_2 = re.findall(SQL_ERR_2, HTML_CALL_TRIGGER_1)
        SRCH_SQL_ERR_TRIGG_3 = re.findall(SQL_ERR_3, HTML_CALL_TRIGGER_1)

        if len(SRCH_SQL_ERR_TRIGG_1) == 0 and len(SRCH_SQL_ERR_TRIGG_2) == 0 and len(SRCH_SQL_ERR_TRIGG_3) == 0:

            MODIFIED_QUERY = QUERY_FOR_REPLACE.replace(PARAMS[item],  TRIGGER_ERR_2)
            TRIGGER_URL_2_P1 = "".join(PARSED_URL[0:1]) + "://"
            TRIGGER_URL_2_P2 = "".join(PARSED_URL[1:2]) 
            TRIGGER_URL_2_P3 = "".join(PARSED_URL[2:3])  + "?"
            TRIGGER_URL_2_P4 = "".join(MODIFIED_QUERY)  
            TRIG_URL_2 = TRIGGER_URL_2_P1 + TRIGGER_URL_2_P2 + TRIGGER_URL_2_P3 + TRIGGER_URL_2_P4
            try:
                http_request_trigger_2 = urllib2.urlopen(TRIG_URL_2)
            except (HTTPError):
                print ("[!] The connection could not be established.")
                print ("[!] Error code: ",  re.code)
            except (URLError):
                print ("[!] The connection could not be established.")
                print ("[!] Reason: ",  re.reason)

            HTML_CALL_TRIGGER_2 = http_request_trigger_2.read()
            HTML_CALL_TRIGGER_2 = HTML_CALL_TRIGGER_2.decode('ISO-8859-1')
            SRCH_SQL_ERR_TRIGG_1 = re.findall(SQL_ERR_1, HTML_CALL_TRIGGER_2)
            SRCH_SQL_ERR_TRIGG_2 = re.findall(SQL_ERR_2, HTML_CALL_TRIGGER_2)
            SRCH_SQL_ERR_TRIGG_3 = re.findall(SQL_ERR_3, HTML_CALL_TRIGGER_2)

            if len(SRCH_SQL_ERR_TRIGG_1) == 0 and len(SRCH_SQL_ERR_TRIGG_2) == 0 and len(SRCH_SQL_ERR_TRIGG_3) == 0:
                print ("[i] The parameter \"",  item,  "\" doesn't seem to be vulnerable.")
                return ("Return no SQL injection vulnerability ")
        
        else:
            print ("[+] Found possible SQL injection vulnerability! Parameter:", item)
            VULN_PARAM[index+1] = item
            return ("Found possible SQL injection vulnerability! Parameter:", item)

    if len(VULN_PARAM) != 0:
        print ("")
        print ("[#] Displaying a short report for the provided URL:")
        print ("[#] At least one parameter seems to be vulnerable. ")
        print (VULN_PARAM)
        
    else:
        print ("")
        print ("[#] Displaying a short report for the provided URL:")
        print ("[#] No SQL injection vulnerabilities found")
        print ("Your Website is secure from SQL Injection.")
        return ("Return no SQL injection vulnerability ")

    print ("")
    print ("[i] That's it. Bye!")
    print ("")
    print ("")


def main(Site_URL):
    URL_TESTING(Site_URL)

    x = URL_SCANNING(Site_URL)
    return x



def index(request):
    print(request.method)
    if(request.method=="POST"):
        search_input = request.POST.get('search')
        print(search_input)
        x = main(search_input)
        print(x)
        # return HttpResponse(x)
        return render(request,'index1.html',{"x":x})
    # return render()
        
    return render(request, 'index.html')
    # return HttpResponse("Hello world!")



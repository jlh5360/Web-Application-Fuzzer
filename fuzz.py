# Name:  Jonathan Ho
# Project:  Web Application Fuzzer


import sys
import requests
import urllib.parse
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import mechanicalsoup
import argparse
import warnings




#Creates and returns Command-Line Interface
def parse_args():
    parser = argparse.ArgumentParser(usage = "fuzz.py [discover | test] <URL> <OPTIONS>", description = "One of the most helpful tools that a security-minded software developer can have is a fuzz-testing tool, or a fuzzer. A fuzzer is a type of exploratory testing tool used for finding weaknesses in a program by scanning its attack surface.")
    subparsers = parser.add_subparsers(dest = "command", help = "Commands: discover or test")
    
    #Subparser for "discover" command
    parser_discover = subparsers.add_parser("discover", usage = "fuzz.py discover <URL> <OPTIONS>", help = "Output a comprehensive, human-readable list of all discovered inputs to the system. Techniques include both crawling and guessing.")
    parser_discover.add_argument("url", help = "The URL of the web application to test", type = str)
    
    #Discover options
    parser_discover.add_argument("--custom-auth", help = "Signal that the fuzzer should use hard-coded authentication for a specific application (e.g. dvwa).", type = str)
    parser_discover.add_argument("--common-words", help = "Newline-delimited file of common words to be used in page guessing. Required.", type = str, required = True)
    # parser_discover.add_argument("--extensions", help = "Newline-delimited file of path extensions, e.g. \".php\". Optional. Defaults to \".php\" and the empty string if not specified", type = str, required = None, default = ".php")
    parser_discover.add_argument("--extensions", help = "Newline-delimited file of path extensions, e.g. \".php\". Optional. Defaults to \".php\" and the empty string if not specified", type = str, required = None)
    
    #Subparser for "test" command
    parser_test = subparsers.add_parser("test", usage = "fuzz.py test <URL> <OPTIONS>", help = "Discover all inputs, then attempt a list of exploit vectors on those inputs. Report anomalies that could be vulnerabilities.")
    parser_test.add_argument("url", help = "The URL of the web application to test", type = str)

    #Test options
    parser_test.add_argument("--custom-auth", help = "Signal that the fuzzer should use hard-coded authentication for a specific application (e.g. dvwa).", type = str)
    parser_test.add_argument("--common-words", help = "Newline-delimited file of common words to be used in page guessing. Required.", type = str, required = True)
    parser_test.add_argument("--extensions", help = "Newline-delimited file of path extensions, e.g. \".php\". Optional. Defaults to \".php\" and the empty string if not specified", type = str, required = None, default = ".php")
    parser_test.add_argument("--vectors", help = "Newline-delimited file of common exploits to vulnerabilities. Required.", type = str, required = True)
    parser_test.add_argument("--sanitized-chars", help = "Newline-delimited file of characters that should be sanitized from inputs. Defaults to just < and >", type = str, default = ["<", ">"])
    parser_test.add_argument("--sensitive", help = "Newline-delimited file data that should never be leaked. It's assumed that this data is in the application's database (e.g. test data), but is not reported in any response. Required.", required = True)
    parser_test.add_argument("--slow", help = "Number of milliseconds considered when a response is considered \"slow\". Optional. Default is 500 milliseconds", type = int, required = None, default = 500)
    
    #Need to retreive the arguments
    args = parser.parse_args()

    return args


#Setup and login process for the DVWA custom-auth
#       This is the initial part of discover's functionality. But you don't need to fully implement discover as part of part 0.
#       You just need to implement enough to login to the dvwa page, create the database, and then set the security to low.
def setup_login_dvwa(base_url):
    #1.  Go to {URL}/setup.php where {URL} is the given url from the command line that points to a DVWA instance
    browser = mechanicalsoup.StatefulBrowser()   #Create a MechanicalSoup browser
    setup_url = urljoin(base_url, "setup.php")   #Create the setup URL by joining the base URL and "setup.php"
    browser.open(setup_url)   #Opens/goes to the setup URL
    
    #2.  “Click” on the Create/Reset Database (i.e. submit the form)
    # browser.select_form("form")   #Select the form to reset the database
    #                               #Use "form" for when there is only one (1) form on the webpage
    browser.select_form('form[action="#"]')   #Select the form to reset the database
    # browser.submit_selected()
    browser.submit_selected("create_db")   #Submits/"Clicks" on the selected form, specifically the button name "create_db"

    #3.  Go to {URL}, and it will forward you to the login page
    login_url = urljoin(base_url, "login.php")   #Create the login URL by joining the base URL and "login.php"
    browser.open(login_url)   #Opens/goes to the login URL

    #4.  Enter in “admin” and “password”
    # browser.select_form("form")   #Select the form to reset the database
    #                               #Use "form" for when there is only one (1) form on the webpage
    browser.select_form('form[action="login.php"]')   #Select the form to reset the database
    browser["username"] = "admin"   #Input "admin" in the selected form, specifically the button name "username"
    browser["password"] = "password"   #Input "admin" in the selected form, specifically the button name "password"

    #5.  “Click” Login (i.e. submit the form)
    # browser.submit_selected()
    browser.submit_selected("Login")   #Submits/"Clicks" on the selected form, specifically the button name "Login"    

    #6.  Go to the DVWA Security page ({URL}/security.php)
    security_url = urljoin(base_url, "security.php")   #Create the security URL by joining the base URL and "security.php"
    browser.open(security_url)

    #7.  Select “Low” and submit the form
    # browser.select_form("form")   #Select the form to reset the database
    #                               #Use "form" for when there is only one (1) form on the webpage
    browser.select_form('form[action="#"]')   #Select the form to reset the database
    browser["security"] = "low"
    # browser.submit_selected()
    browser.submit_selected("seclev_submit")   #Submits/"Clicks" on the selected form, specifically the button name "seclev_submit"

    #8.  Begin your fuzzing operations. (See rest of instructions)
    home_url = urljoin(base_url, 'index.php')   #Create the home index URL by joining the base URL and "index.php"
    browser.open(home_url)
    print(browser.get_current_page())   #Print/Output the HTML code of the home URL to confirm login

    return browser


#Extracts all links from the HTML content of a given URL
def get_links(url, browser):
    browser.open(url)
    if (browser.get_current_page() is not None):
        return browser.links()
    else:
        print("[ERROR] Failed to retrieve linked from " + url + ".")
        return[]


def get_forms(url, browser):
    try:
        response = browser.open(url)
        if (str(response) == "<Response [200]>"):   #Check if the response is successful
            content_type = response.headers.get("content-type", "").lower()

            if (("text/html" in content_type) or ("text/css" in content_type) or ("application/javascript" in content_type)):
                soup = BeautifulSoup(response.content, "html.parser")   #Parses the HTML content
                forms = []  #List to store forms

                #Extract all forms
                for form in soup.find_all("form"):
                    form_data = {
                        "action": form.get("action"),
                        "method": form.get("method"),
                        "inputs": []
                    }
                    
                    for input_tag in form.find_all("input"):
                        form_data["inputs"].append({
                            "name": input_tag.get("name"),
                            "type": input_tag.get("type"),
                            "value": input_tag.get("value")
                        })
                    
                    forms.append(form_data)
                
                return forms
        
        #Returns the empty list
        return []
    except requests.exceptions.RequestException:
        #Returns an empty list if there's an error during the request
        return []


def get_cookies(browser):
    #Extract and returns cookies from the current session
    current_cookies = browser.session.cookies
    return current_cookies


#Scrapes/Crawls the exterior of a non-DVWA web application
#       If you give it a non-dvwa page, it should just "crawl the exterior of the webapp" meaning it should just grab the local
#       links on the page, look for any input forms it can find, print those out/print the page out-- but it won't go any deeper
#       (i.e., it won't crawl anything/open any links yet). Essentially, it just familiarizes itself with any non-dvwa page it
#       is given via url (e.g., localhost, rit.edu, etc).
def scrape_page(absolute_base_domain, base_url, url, visited_links, browser):
    #Prevent crawling the same link repeatedly
    if url in visited_links:
        return
        
    # Mark this URL as visited
    visited_links.add(url)

    #1.  Grab the local links on the page
    links = get_links(url, browser)   #Extract links using get_links() function

    #2.  Look for any input forms it can find
    forms = get_forms(url, browser)   #Extract forms using get_forms() function

    #3.  Print those out/print the page out
    print("[+] Crawling links on " + url + ":")
    for link in links:
        base_domain2 = urlparse(url).netloc
        absolute_url = urljoin(url, link.get("href"))
        if (absolute_base_domain == base_domain2):
            if (absolute_url.startswith(base_url)):
                if (absolute_url not in visited_links):
                    print("\tFound link: " + absolute_url)
                    scrape_page(absolute_base_domain, base_url, absolute_url, visited_links, browser)   #Recursively crawl found links

    # print()   #Prints a new line

    print("[+] Crawling forms on " + url + ":")
    for form in forms:
        print("\tFound form: action=" + str(form['action']) + ", method=" + str(form['method']))
        for input_field in form["inputs"]:
            print("\t\tInput name: " + str(input_field['name']) + ", type: " + str(input_field['type']) + ", value: " + str(input_field['value']))

    #4.  Extract and print cookies from the current session
    print("[+] Crawling cookies on " + url + ":")
    current_cookies = get_cookies(browser)
    for cookie in current_cookies:
        print("\t\tCookie name: " + cookie.name + ", value: " + cookie.value)


#Load a newline-delimited file and return a list of non-empty lines
def load_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]   #Read non-empty lines
    except FileNotFoundError:
        print("[ERROR] The file " + file_path + " was not found.")
        return
    except IOError:
        print("[ERROR] An error occurred while reading the file " + file_path + ".")
        return


#==================================== Page Guessing ====================================
#Discover all pages by combining common words with extensions
def discover_pages(base_url, common_words_file, extensions_file):
    common_words = load_file(common_words_file)   #Load common words from the specified file
    discovered_links = set()

    if (isinstance(extensions_file, str) and extensions_file != "" and extensions_file != None):
        extensions = load_file(extensions_file)   #Load extensions from the specified file
        # print("Pages Successfully Guessed:")
        # print("********************************************")

        #Guess pages using combinations of common words and extensions
        for word in common_words:
            for extension in list(extensions):
                guessed_url = urljoin(base_url, word + extension)   #Form the full guess URL
                response = requests.head(guessed_url)   #Use HEAD to check if it exists
                if (response.status_code == 200):
                    print("[+] Discovered page: " + guessed_url)
                    discovered_links.add(guessed_url)   #Add to discovered links
    elif (extensions_file == None):
        extensions = ""
        # print("Pages Successfully Guessed:")
        # print("********************************************")

        #Guess pages using combinations of common words and extensions
        for word in common_words:
            guessed_url = urljoin(base_url, word + ".php")   #Form the full guess URL with the ".php" default
            response = requests.head(guessed_url)   #Use HEAD to check if it exists
            if (response.status_code == 200):
                print("[+] Discovered page: " + guessed_url)
                discovered_links.add(guessed_url)   #Add to discovered links
    
    # print()
        
    return discovered_links   #Return all discovered links


#Discovers inputs through crawling and guessing
def fuzz_discover(browser, base_url, common_words_file, extensions_file):
    visited_links = set()   #Set to keep track of visited links

    absolute_base_domain = urlparse(base_url).netloc

    #Discover pages by guessing
    discovered_links = discover_pages(base_url, common_words_file, extensions_file)

    #Crawl the links found in the initial discovery
    for link in discovered_links:
        # scrape_page(link, visited_links)
        scrape_page(absolute_base_domain, base_url, link, visited_links, browser)   #Pass the browser
        
    #Additionally, check the base URL itself for inputs
    inputs = parse_url(base_url)
    print("[+] Inputs discovered at base URL: " + str(inputs))

    #Check cookies from the session
    cookies = get_cookies(browser)
    # print(f"[+] Cookies discovered: {cookies}")
    print("[+] Cookies discovered: " + str(cookies))


#==================================== Parse URLs ====================================
def parse_url(url):
    parsed_url = urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    inputs = list(query_params.keys())   #Keys from the query (input names)
    
    return inputs


def main():
    # At the start of your script to suppress specific warnings
    warnings.filterwarnings("ignore", category=UserWarning, module='bs4.builder')

    #Set args to Command-Line Interface (CLI)
    args = parse_args()
    
    #If command is "discover"
    if (args.command == "discover"):
        #If custom-auth is dvwa
        if (args.custom_auth == "dvwa"):
            #Perform the custom DVWA authentication sequence
            print("================================================================================")
            print("[+] Using custom DVWA authentication for " + args.url + ".")
            print("================================================================================\n\n")
            browser = setup_login_dvwa(args.url)   #Calls/executes this function for the DVWA custom auth with the user's input of URL

            print()
            print()
            print()
            print()

            fuzz_discover(browser, args.url, args.common_words, args.extensions)
        else:
            #Crawl the exterior of the non-DVWA web application
            print("================================================================================")
            print("[+] Crawling exterior of " + args.url + ".")
            print("================================================================================\n\n")
            # scrape_page(args.url)
            
            browser = mechanicalsoup.StatefulBrowser()   #Create a MechanicalSoup browser
            fuzz_discover(browser, args.url, args.common_words, args.extensions)   #Start the discover process
    #Else if command is "test"
    elif (args.command == "test"):
        #WILL UPDATE THIS FOR / IN THE UPCOMING FUZZER 1 & 2 (PARTS 1 & 2)
        print("WORK-IN PROGRESS  |  NOT YET IMPLEMENTED when only 'discover' is for Fuzzer 0 (Part 0)")


if __name__ == "__main__":
    main()
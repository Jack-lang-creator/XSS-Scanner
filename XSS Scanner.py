import requests
from pprint import pprint
from bs4  import BeautifulSoup as bs
from urllib.parse import urljoin

def  get_forms(url):
    soup = bs(requests.get(url).content,"html parser")
    return soup.find_all("form")
def  get_form_details(form):
    #get  all the form details
    details = {}
    #get the form action  of the target url
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method","get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("input","text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type,"name": input_name})
        #put everything in the dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details    
def submit_form(form_details,url,value):
    target_url  = urljoin(url,form_details["actions"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")    
        if input_name and input_value:
            data[input_name] = input_value
    if  form_details["method"] == "post":
         return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)
def scan_xss(url):
    """
    Given a `url`, it prints all XSS vulnerable forms and 
    returns True if any is vulnerable, False otherwise
    """
    # get all the forms from the URL
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    return is_vulnerable     



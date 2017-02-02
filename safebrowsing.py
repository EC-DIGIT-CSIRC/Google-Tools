#
# Search domain and URL inside Google SafeBrowing DB
#
# Author: David DURVAUX
# Copyright: EC DIGIT CSIRC - April 2016
#
# TODO:
#    - Improve/review proxy support
#    - Improved output support
#
# Version 0.3
#
# Changes
#    - Add functions to create Opener object and bug fix (2017-02-02)
#
import urllib
import urllib2
import os
import argparse
import csv
import sys

# Variables and settings
gsbapi = ""
gsbclientn = "AUTOPSIT"
gsbclientv = "0.2"
gsbversion = "3.1"  # see https://developers.google.com/safe-browsing/lookup_guide#AQuickExamplePOSTMethod
gsburl = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=%s&key=%s&appver=%s&pver=%s"
directory = "./out"

# Google Safe Browsing Code
GSB_ALL_CLEAN = 204
GSB_SOME_BAD = 200

# Output information
outfile = sys.stdout

def getHuntingResult(urls=[], proxy=None):
    """
        Query Google Safe Browsing through API.

        Google Safe Browsing is queried for all urls
        stored in urls array.

        If a proxy is required, proxy parameter
        received a Opener object set with right
        proxy parameter.  The Opener object is returned
        by function getOpenerWithProxy() or getOpenerWithProxyFromString()
    """
    # Some funcky thinks
    # Create an OpenerDirector with support for Basic HTTP Authentication...
    if proxy is not None:
        urllib2.install_opener(proxy)
    lastcode = GSB_ALL_CLEAN
    iteration = 0

    for i in range(0, len(urls) / 500 + 1):

        subset = urls[500*i:(500*(i+1))-1]

        try:
            query = str(len(subset))
            for url in subset:
               query += "\n" + urllib.quote(url)
            url = gsburl % (gsbclientn, gsbapi, gsbclientv, gsbversion)
            req = urllib2.Request(url, query)
            response = urllib2.urlopen(req)
            code = response.getcode()
            response.close()

            # Handle results
            if(code == GSB_ALL_CLEAN):
                continue  #this is the default code
            elif(code == GSB_SOME_BAD):
                lastcode = GSB_SOME_BAD
                print "AT LEAST ONE of the queried URLs are matched in this subset.\nCurrent result:\n%s" % results
            else:
                lastcode = code
        except Exception as e:
            print "ERROR: Failed to retrieve results from Google Safe Browsing :'("
            print (e)
            #print sys.exc_info()[0]
            return None

    # Handle final results
    if(lastcode == GSB_ALL_CLEAN):
        print "All URLs are clean"
    elif(lastcode == GSB_SOME_BAD):
        print "AT LEAST ONE of the queried URLs are matched"
    else:
        print "At least one of the step failed with code: %s" % lastcode
    return lastcode


def getOpenerWithProxy(proxy_addr, proxy_usr = None, proxy_pwd = None):
    """
        Return a Opener object based on 3 parameters:

        - proxy_addr with format <host>:<port> which defined the Proxy address and port
        - proxy_usr which is the proxy user if required or None
        - proxy_pwd which is the porxy password if required or None
    """
    try:
        proxy = None
        if(proxy_usr is not None and proxy_pwd is not None):
            proxy = urllib2.ProxyHandler({'https' : 'http://%s:%s@%s' % (proxy_usr, proxy_pwd, proxy_addr)})
        else:
            proxy = urllib2.ProxyHandler({'https' : 'http://%s' % (proxy_addr)})
        opener = urllib2.build_opener(proxy)
        return opener
    except Exception as e:
        print("FAILED TO CREATED OPENER")
        print(e)
        return None


def getOpenerWithProxyFromString(proxy_str):
    """
        Return a Opener object based on a proxy string with format
        http://[<user>]:[<password>]@<address>:<port>

        This method was made especially for user from API
    """
    try: 
        proxy = urllib2.ProxyHandler({'https' : proxy_str})
        opener = urllib2.build_opener(proxy)
        return opener
    except Exception as e:
        print("FAILED TO CREATED OPENER FROM STRING: %s" % proxy_str)
        print(e)
        return None


def main():
    """
        Calling the script and options handling
    """

    # Argument definition
    parser = argparse.ArgumentParser(description='Retrieve results of VirusTotal Hunting.')
    
    # Google Safe Browsing Options options
    parser.add_argument('-api', '--api', help='VirusTotal API key')

    # Proxy Settings
    parser.add_argument('-puri', '--proxy_uri', help='Proxy URI')
    parser.add_argument('-pusr', '--proxy_user', help='Proxy User')
    parser.add_argument('-ppwd', '--proxy_password', help='Proxy User')

    # Input options
    parser.add_argument('-in', '--input', help='File with the list of domains URLs to search')

    # Output options
    parser.add_argument('-out', '--output', help='File to store result (by default stdout) -- CURRENTLY NOT IMPLEMENTED')

    # Parse command line
    args = parser.parse_args()

    # Parse Proxy Options
    proxy = None
    if args.proxy_uri:
        proxy_usr = None
        proxy_pwd = None
        proxy_uri = args.proxy_uri

        if args.proxy_user:
            proxy_usr = args.proxy_user

        if args.proxy_password:
            proxy_pwd = args.proxy_password

        proxy = getOpenerWithProxy(proxy_uri, proxy_usr, proxy_pwd)

    # Control output instead of stdout
    global outfile
    if args.output:
        outfile = args.outfile
    else:
        outfile = sys.stdout

    # API KEY
    global gsbapi
    if args.api:
        gsbapi = args.api


    # INPUT OPTIONS
    urls = []
    try:
        f = open(args.input, 'r')
        for url in f:
            urls.append(url)
        f.close()

    except:
        print("FATAL ERROR: impossible to read input file")

    # Check if minimum set of parameters is available
    if(gsbapi is None or len(urls) <= 0):
        print("ERROR: you need to specify at least an API key.  Use -h to get the manual.")
        return

    # Do all the magic now :)
    results = getHuntingResult(urls, proxy)
    print results #DEBUG -- TODO improve

# Call the main function of this script and trigger all the magic \o/
if __name__ == "__main__":
    main()
# That's all folk ;)

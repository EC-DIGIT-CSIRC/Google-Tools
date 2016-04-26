#
# Search domain and URL inside Google SafeBrowing DB
#
# Author: David DURVAUX
# Copyright: EC DIGIT CSIRC - April 2016
#
# TODO:
#    - Improve/review proxy support
#    - Improved output support
#    - Support for more than 500 URLs at once
#
# Version 0.1 
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
gsbclientv = "0.1"
gsbversion = "3.1"  # see https://developers.google.com/safe-browsing/lookup_guide#AQuickExamplePOSTMethod
gsburl = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=%s&key=%s&appver=%s&pver=%s"
directory = "./out"

# Proxy settings
proxy_uri = None
proxy_usr = None
proxy_pwd = None

# Output information
outfile = sys.stdout

def getHuntingResult(urls=[]):
    # Some funcky thinks
    # Create an OpenerDirector with support for Basic HTTP Authentication...
    if(proxy_uri is not None):
        proxy = None
        if(proxy_usr is not None and proxy_pwd is not None):
            proxy = urllib2.ProxyHandler({'https' : 'http://%s:%s@%s' % (proxy_usr, proxy_pwd, proxy_uri)})
        else:
            proxy = urllib2.ProxyHandler({'https' : 'http://%s' % (proxy_uri)})
        opener = urllib2.build_opener(proxy)
        urllib2.install_opener(opener)

    results = ""
    if(len(urls) > 500):
            print("ERROR: MAX 500 URLS at each time -- TO BE FIXED")
    else:
        try:
            query = str(len(urls))
            for url in urls:
               query += "\n" + urllib.quote(url)
            url = gsburl % (gsbclientn, gsbapi, gsbclientv, gsbversion)
            req = urllib2.Request(url, query)
            response = urllib2.urlopen(req)
            code = response.getcode()
            results = response.read()
            response.close()

            # Handle results
            if(code == 204):
                print "All URLs are clean"
            elif(code == 200):
                print "AT LEAST ONE of the queried URLs are matched"
            else:
                print "Other error: %s" % code
            return results
        except:
            print "ERROR: Failed to retrieve results from Google Safe Browsing :'("
            print sys.exc_info()[0]
            return None
    return results

def outputResults(results, outfile=sys.stdout):
    LDwriter = csv.writer(outfile)
    LDwriter.writerow(["# of detection", "YARA rule", "SHA1", "Binary type", "First seen", "Last seen"])
    if results is not None:
        for row in results:
            LDwriter.writerow(row)

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
    parser.add_argument('-out', '--output', help='File to store result (by default stdout')

    # Parse command line
    args = parser.parse_args()

    # Parse Proxy Options
    global proxy_uri
    global proxy_usr
    global proxy_pwd
    if args.proxy_uri:
        proxy_uri = args.proxy_uri

        if args.proxy_user:
            proxy_usr = args.proxy_user

        if args.proxy_password:
            proxy_pwd = args.proxy_user

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
    results = getHuntingResult(urls)
    print results #DEBUG -- TODO fix it
    #outputResults(results, outfile)

# Call the main function of this script and trigger all the magic \o/
if __name__ == "__main__":
    main()
# That's all folk ;)

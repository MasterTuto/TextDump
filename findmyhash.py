# -*- coding: iso-8859-1 -*-

########################################################################################################
### LICENSE
########################################################################################################
#
# findmyhash.py - v 1.1.2
#
# This script is under GPL v3 License (http://www.gnu.org/licenses/gpl-3.0.html).
#
# Only this source code is under GPL v3 License. Web services used in this script are under
# different licenses. 
#
# If you know some clause in one of these web services which forbids to use it inside this script,
# please contact me to remove the web service as soon as possible.
#
# Developed by JulGor ( http://laxmarcaellugar.blogspot.com/ )
# Mail: bloglaxmarcaellugar AT gmail DOT com
# twitter: @laXmarcaellugar
#

########################################################################################################
### IMPORTS
########################################################################################################

try:
	import sys
	import hashlib
	import urllib2
	import getopt
	from os import path
	from urllib import urlencode
	from re import search, findall
	from random import seed, randint
	from base64 import b64encode
	from cookielib import LWPCookieJar
	from bs4 import BeautifulSoup
	import requests
except ImportError:
	print """
Execution error:

  You required some basic Python libraries. 
  
  This application use: sys, hashlib, urllib, urllib2, os, re, random, getopt, base64 and cookielib.

  Please, check if you have all of them installed in your system.

"""
	sys.exit(1)

try:
	from httplib2 import Http
except:
	print """
Execution error:

  The Python library httplib2 is not installed in your system. 
  
  Please, install it before use this application.

"""
	sys.exit(1)
	
try:
	from libxml2 import parseDoc
except:
	print """
Execution error:

  The Python library libxml2 is not installed in your system. 
  
  Because of that, some plugins aren't going to work correctly.
  
  Please, install it before use this application.

"""



########################################################################################################
### CONSTANTS
########################################################################################################

MD4	= "md4"
MD5 	= "md5"
SHA1 	= "sha1"
SHA224	= "sha224"
SHA256 	= "sha256"
SHA384	= "sha384"
SHA512 	= "sha512"
RIPEMD	= "rmd160"
LM 	= "lm"
NTLM	= "ntlm"
MYSQL	= "mysql"
CISCO7	= "cisco7"
JUNIPER = "juniper"
GOST	= "gost"
WHIRLPOOL = "whirlpool"
LDAP_MD5 = "ldap_md5"
LDAP_SHA1 = "ldap_sha1"


USER_AGENTS = [
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Crazy Browser 1.0.5)",
	"curl/7.7.2 (powerpc-apple-darwin6.0) libcurl 7.7.2 (OpenSSL 0.9.6b)",
	"Mozilla/5.0 (X11; U; Linux amd64; en-US; rv:5.0) Gecko/20110619 Firefox/5.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b8pre) Gecko/20101213 Firefox/4.0b8pre",
	"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205",
	"Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)",
	"Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
	"Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00",
	"Opera/9.80 (X11; Linux i686; U; pl) Presto/2.6.30 Version/10.61",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.861.0 Safari/535.2",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.872.0 Safari/535.2",
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	]
	


########################################################################################################
### CRACKERS DEFINITION
########################################################################################################

class GROMWEB: 
	
	name = 		"gromweb"
	url = 		"http://md5.gromweb.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "https://md5.gromweb.com/?md5=%s" % (hashvalue)
		
		# Make the request
		response = requests.get(url)
		
		# Analyze the response
		html = None
		if response:
			html = response.text
		else:
			return None

		soup = BeautifulSoup(html, 'html.parser')

		for i in soup.find_all('em'):
			if i['class'] == [u'long-content', u'string']: return i.text

class MY_ADDR:
	
	name = 		"my-addr"
	url = 		"http://md5.my-addr.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php"
		
		# Build the parameters
		params = { "md5" : hashvalue,
			   "x" : '21',
			   "y" : '8' }
		
		# Make the request
		response = requests.post(url, data=params)
		
		# Analyze the response
		html = None
		if response:
			html = response.text
		else:
			return None
		
		match = search (r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", html)
		
		if match:
			return match.group().split('span')[2][3:-6]
		else:
			return None

class MD5DECRYPTION:
	
	name = 		"md5decryption"
	url = 		"http://md5decryption.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = self.url
		
		# Build the parameters
		params = { "hash" : hashvalue,
			   "submit" : "Decrypt It!" }
		
		# Make the request
		response = requests.post(url, data=params)
		
		# Analyze the response
		html = None
		if response:
			html = response.text
		else:
			return None
		
		match = search (r"Decrypted Text: </b>[^<]*</font>", html)
		
		if match:
			return match.group().split('b>')[1][:-7]
		else:
			return None

class HASHCRACK:
	
	name = 		"hashcrack"
	url = 		"http://hashcrack.com"
	supported_algorithm = [MD5, SHA1, MYSQL, LM, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://hashcrack.com/index.php"
		
		# Build the parameters
		params = { "auth" : "8272hgt",
			   "hash" : hashvalue,
			   "string" : "",
			   "Submit" : "Submit" }
		
		# Make the request
		response = requests.post( url, data=params )
		
		# Analyze the response
		html = None
		if response:
			html = response.text
		else:
			return None
		
		match = search (r'<div align=center>"[^"]*" resolves to</div><br><div align=center> <span class=hervorheb2>[^<]*</span></div></TD>', html)
		
		if match:
			return match.group().split('hervorheb2>')[1][:-18]
		else:
			return None

class REDNOIZE:
	
	name = 		"rednoize"
	url = 		"http://md5.rednoize.com"
	supported_algorithm = [MD5, SHA1]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		
		url = "http://hashtoolkit.com/reverse-hash/?hash=%s" % (hashvalue)
		
		# Make the request
		response = requests.get(url)
		
		# Analyze the response
		html = response.text
		soup = BeautifulSoup(html, 'html.parser')

		for i in soup.find_all('span'):
			if i.get("title") == 'decrypted md5 hash': return i.text
			
class CMD5:
	
	name = 		"cmd5"
	url = 		"http://www.cmd5.org"
	supported_algorithm = [MD5, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Look for hidden parameters
		response = requests.get( "http://www.cmd5.org/" )
		
		html = response.text
		
		soup = BeautifulSoup(html, 'html.parser')

		for i in soup.find_all('input'):
			if i.get("name") == "__VIEWSTATE":
				viewstate = i.get("value")

			if i.get("name") == "__VIEWSTATEGENERATOR":
				viewstategenerator = i.get("value")
			
			if i.get("name") == "ctl00$ContentPlaceHolder1$HiddenField1":
				got = i.get("value")
				ContentPlaceHolder1 = i.get("value") if got != None else ''
			
			if i.get("name") == "ctl00$ContentPlaceHolder1$HiddenField2":
				ContentPlaceHolder2 = i.get("value")
		
		# Build the URL
		url = "http://www.cmd5.org/"
		
		hash2 = ""
		if alg == MD5:
			hash2 = hashvalue
		else:
			if ':' in hashvalue:
				hash2 = hashvalue.split(':')[1]

		
		# Build the parameters
		params = { "__EVENTTARGET" : "",
			   "__EVENTARGUMENT" : "",
			   "__VIEWSTATE" : viewstate,
			   "__VIEWSTATEGENERATOR": viewstategenerator,
			   "ctl00$ContentPlaceHolder1$TextBoxInput" : hashvalue,
			   "ctl00$ContentPlaceHolder1$InputHashType" : "md5(unicode)",
			   "ctl00$ContentPlaceHolder1$Button1" : "decrypt",
			   "ctl00$ContentPlaceHolder1$HiddenField1" : ContentPlaceHolder1,
			   "ctl00$ContentPlaceHolder1$HiddenField2" : ContentPlaceHolder2 }
			   
		header = { "Referer" : "http://www.cmd5.org/" }
		
		# Make the request
		response = requests.post( url, data=params, headers=header )
		
		# Analyze the response
		html = None
		if response:
			html = response.text
		else:
			return None
		

		soup = BeautifulSoup(html, 'html.parser')
		found = soup.find_all(lambda tag: tag.get('id') == 'ctl00_ContentPlaceHolder1_LabelAnswer')[0].get_text()[:-14]
		
		return found if found else None

class MD5DECRYPT:
	
	name = 		"sans"
	url = 		"http://isc.sans.edu"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://www.md5decrypt.org"
		
		# Build the Headers with a random User-Agent
		response = requests.get(url)

		if response:
			html = response.text
		else:
			return None

		soup = BeautifulSoup(html, 'html.parser')

		match = soup.find_all(lambda tag: 'var jscheck=' in tag.text)
		
		jscheck = str(match[-1]).split("'")[1]
		hashvalue = b64encode(hashvalue)
		
		params = { "jscheck" : jscheck,
			   "value" : hashvalue,
			   "operation" : "MD5D" }
		
		url = "http://www.md5decrypt.org/index/process"
		# Make the request
		response = requests.post(url, data=params)

		if response:
			return dict(response.json())['body']
		else:
			return None

class CLAVEY:
	
	name = 		"sans"
	url = 		"http://descodificar.claveycontraseña.es"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://descodificar.claveycontraseña.es/%s.html" % (hashvalue)
		
		response = requests.get(url)
		html = response.text

		soup = BeautifulSoup(html, 'html.parser')
		divs = soup.find_all('div', {'class': 'ver'})
		divs = list(set(divs))
		
		return divs[0]['onclick'].split('\'')[1]

class MD5DECODER:
	
	name = 		"sans"
	url = 		"http://md5decoder.org"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "https://crackhash.com/"

		params = {
			'hash': hashvalue,
			'crack': 'crack'
		}

		response = requests.post(url, data=params)
		html = response.text

		soup = BeautifulSoup(html, 'html.parser')

		return soup.find_all('center')[0].get_text().split()[-1]


CRAKERS = [
		GROMWEB,
		MY_ADDR,
		MD5DECRYPTION,
		HASHCRACK,
		CMD5,
		MD5DECRYPT,
		CLAVEY,
		MD5DECODER]



########################################################################################################
### GENERAL METHODS
########################################################################################################

def configureCookieProcessor (cookiefile='/tmp/searchmyhash.cookie'):
	'''Set a Cookie Handler to accept cookies from the different Web sites.
	
	@param cookiefile Path of the cookie store.'''
	
	cookieHandler = LWPCookieJar()
	if cookieHandler is not None:
		if path.isfile (cookiefile):
			cookieHandler.load (cookiefile)
			
		opener = urllib2.build_opener ( urllib2.HTTPCookieProcessor(cookieHandler) )
		urllib2.install_opener (opener)



def do_HTTP_request (url, params={}, httpheaders={}):
	'''
	Send a GET or POST HTTP Request.
	@return: HTTP Response
	'''

	data = {}
	request = None
	
	# If there is parameters, they are been encoded
	if params:
		data = urlencode(params)

		request = urllib2.Request ( url, data, headers=httpheaders )
	else:
		request = urllib2.Request ( url, headers=httpheaders )
		
	# Send the request
	try:
		response = urllib2.urlopen (request)
	except:
		return ""
	
	return response


def printSyntax ():
	"""Print application syntax."""
	
	print """%s 1.1.2 ( http://code.google.com/p/findmyhash/ )

Usage: 
------

  python %s <algorithm> OPTIONS


Accepted algorithms are:
------------------------

  MD4       - RFC 1320
  MD5       - RFC 1321
  SHA1      - RFC 3174 (FIPS 180-3)
  SHA224    - RFC 3874 (FIPS 180-3)
  SHA256    - FIPS 180-3
  SHA384    - FIPS 180-3
  SHA512    - FIPS 180-3
  RMD160    - RFC 2857
  GOST      - RFC 5831
  WHIRLPOOL - ISO/IEC 10118-3:2004
  LM        - Microsoft Windows hash
  NTLM      - Microsoft Windows hash
  MYSQL     - MySQL 3, 4, 5 hash
  CISCO7    - Cisco IOS type 7 encrypted passwords
  JUNIPER   - Juniper Networks $9$ encrypted passwords
  LDAP_MD5  - MD5 Base64 encoded
  LDAP_SHA1 - SHA1 Base64 encoded
 
  NOTE: for LM / NTLM it is recommended to introduce both values with this format:
         python %s LM   -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7
         python %s NTLM -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7


Valid OPTIONS are:
------------------

  -h <hash_value>  If you only want to crack one hash, specify its value with this option.

  -f <file>        If you have several hashes, you can specify a file with one hash per line.
                   NOTE: All of them have to be the same type.
                   
  -g               If your hash cannot be cracked, search it in Google and show all the results.
                   NOTE: This option ONLY works with -h (one hash input) option.


Examples:
---------

  -> Try to crack only one hash.
     python %s MD5 -h 098f6bcd4621d373cade4e832627b4f6
     
  -> Try to crack a JUNIPER encrypted password escaping special characters.
     python %s JUNIPER -h "\$9\$LbHX-wg4Z"
  
  -> If the hash cannot be cracked, it will be searched in Google.
     python %s LDAP_SHA1 -h "{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA=" -g
   
  -> Try to crack multiple hashes using a file (one hash per line).
     python %s MYSQL -f mysqlhashesfile.txt
     
     
Contact:
--------

[Web]           http://laxmarcaellugar.blogspot.com/
[Mail/Google+]  bloglaxmarcaellugar@gmail.com
[twitter]       @laXmarcaellugar
""" % ( (sys.argv[0],) * 8 )



def crackHash (algorithm, hashvalue=None, hashfile=None):
	"""Crack a hash or all the hashes of a file.
	
	@param alg Algorithm of the hash (MD5, SHA1...).
	@param hashvalue Hash value to be cracked.
	@param hashfile Path of the hash file.
	@return If the hash has been cracked or not."""
	
	global CRAKERS
	
	# Cracked hashes will be stored here
	crackedhashes = []
	
	# Is the hash cracked?
	cracked = False
	
	# Only one of the two possible inputs can be setted.
	if (not hashvalue and not hashfile) or (hashvalue and hashfile):
		return False
	
	hashestocrack = [hashvalue]
	
	
	# Try to crack all the hashes...
	for activehash in hashestocrack:
		hashresults = []
		
		# Standarize the hash
		activehash = activehash.strip()
		if algorithm not in [JUNIPER, LDAP_MD5, LDAP_SHA1]:
			activehash = activehash.lower()
		
		# Initial message
		# print "\nCracking hash: %s\n" % (activehash)

		# Each loop starts for a different start point to try to avoid IP filtered
		begin = randint(0, len(CRAKERS)-1)
		
		for i in range(len(CRAKERS)):
			
			# Select the cracker
			cr = CRAKERS[ (i+begin)%len(CRAKERS) ]()
			
			# Check if the cracker support the algorithm
			if not cr.isSupported ( algorithm ):
				continue
			
			# Analyze the hash
			# print "Analyzing with %s (%s)..." % (cr.name, cr.url)
			
			# Crack the hash
			result = None
			try:
				result = cr.crack ( activehash, algorithm )
			# If it was some trouble, exit
			except:
				continue
			
			# If there is any result...
			cracked = 0
			if result:
				
				# If it is a hashlib supported algorithm...
				if algorithm in [MD4, MD5, SHA1,  SHA224, SHA384, SHA256, SHA512, RIPEMD]:
					# Hash value is calculated to compare with cracker result
					h = hashlib.new (algorithm)
					h.update (result)
					
					# If the calculated hash is the same to cracker result, the result is correct (finish!)
					if h.hexdigest() == activehash:
						hashresults.append (result)
						cracked = 2
				
				# If it is a half-supported hashlib algorithm
				elif algorithm in [LDAP_MD5, LDAP_SHA1]:
					alg = algorithm.split('_')[1]
					ahash =  decodestring ( activehash.split('}')[1] )
					
					# Hash value is calculated to compare with cracker result
					h = hashlib.new (alg)
					h.update (result)
					
					# If the calculated hash is the same to cracker result, the result is correct (finish!)
					if h.digest() == ahash:
						hashresults.append (result)
						cracked = 2
				
				# If it is a NTLM hash
				elif algorithm == NTLM or (algorithm == LM and ':' in activehash):
					# NTLM Hash value is calculated to compare with cracker result
					candidate = hashlib.new('md4', result.split()[-1].encode('utf-16le')).hexdigest()
					
					# It's a LM:NTLM combination or a single NTLM hash
					if (':' in activehash and candidate == activehash.split(':')[1]) or (':' not in activehash and candidate == activehash):
						hashresults.append (result)
						cracked = 2
				
				# If it is another algorithm, we search in all the crackers
				else:
					hashresults.append (result)
					cracked = 1
			
			# Had the hash cracked?
			if cracked:
				# print "\n***** HASH CRACKED!! *****\nThe original string is: %s\n" % (result)
				# If result was verified, break
				if cracked == 2:
					break
		
		
		# Store the result/s for later...
		if hashresults:
			
			# With some hash types, it is possible to have more than one result,
			# Repited results are deleted and a single string is constructed.
			resultlist = []
			for r in hashresults:
				if r not in resultlist:
					resultlist.append (r)
					
			finalresult = ""
			if len(resultlist) > 1:
				finalresult = ', '.join (resultlist)
			else:
				finalresult = resultlist[0]
			
			# Valid results are stored
			crackedhashes.append ( (activehash, finalresult) )
	
	
	# Loop is finished. File can need to be closed
	if hashfile:
		try:
			hashestocrack.close ()
		except:
			pass
		
	# Show a resume of all the cracked hashes
	# print "\nThe following hashes were cracked:\n----------------------------------\n"
	# print crackedhashes and "\n".join ("%s -> %s" % (hashvalue, result.strip()) for hashvalue, result in crackedhashes) or "NO HASH WAS CRACKED."
	# print
	
	return result




def searchHash (hashvalue):
	'''Google the hash value looking for any result which could give some clue...
	
	@param hashvalue The hash is been looking for.'''
	
	start = 0
	finished = False
	results = []
	
	sys.stdout.write("\nThe hash wasn't found in any database. Maybe Google has any idea...\nLooking for results...")
	sys.stdout.flush()
	
	while not finished:
		
		sys.stdout.write('.')
		sys.stdout.flush()
	
		# Build the URL
		url = "http://www.google.com/search?hl=en&q=%s&filter=0" % (hashvalue)
		if start:
			url += "&start=%d" % (start)
			
		# Build the Headers with a random User-Agent
		headers = { "User-Agent" : USER_AGENTS[randint(0, len(USER_AGENTS))-1] }
		
		# Send the request
		response = do_HTTP_request ( url, httpheaders=headers )
		
		# Extract the results ...
		html = None
		if response:
			html = response.read()
		else:
			continue
			
		resultlist = findall (r'<a href="[^"]*?" class=l', html)
		
		# ... saving only new ones
		new = False
		for r in resultlist:
			url_r = r.split('"')[1]
			
			if not url_r in results:
				results.append (url_r)
				new = True
		
		start += len(resultlist)
		
		# If there is no a new result, finish
		if not new:
			finished = True
		
	
	# Show the results
	if results:
		print "\n\nGoogle has some results. Maybe you would like to check them manually:\n"
		
		results.sort()
		for r in results:
			print "  *> %s" % (r)
		print
	
	else:
		print "\n\nGoogle doesn't have any result. Sorry!\n"


########################################################################################################
### MAIN CODE
########################################################################################################

def main(algorithm, hashvalue, googlesearch=False):
	"""Main method."""
	
	###################################################
	# Configure the Cookie Handler
	configureCookieProcessor()
	
	# Initialize PRNG seed
	seed()
	
	cracked = 0
	
	
	###################################################
	# Crack the hash/es
	cracked = crackHash(algorithm, hashvalue)
	
	return cracked
	
	
	###################################################
	# Look for the hash in Google if it was not cracked
	# if not cracked and googlesearch and not hashfile:
	# 	searchHash (hashvalue)



# Author: Nicolas Billy (nbilly@paloaltonetworks.com)
# Senior TAC engineer - Palo Alto Networks - January 2017

#Libraries import
import sys
import urllib2
import time
import ssl
import os
import argparse
from xml.etree import ElementTree
from datetime import datetime

#File class
class Tee(object):
    def __init__(self, *files):
        self.files = files
    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush() # If you want the output to be visible immediately
    def flush(self) :
        for f in self.files:
            f.flush()


#Constants
cfg = "url_cache.cfg"
history = "api_call.log"
endless = 1
poll_timer = 60
perf_thres= 300


#Debug flags and vars
poll_iter_tres_act=3 # number of polling before treshold is forced
poll_iter=0 #number of polling
debug=0
force_tres = 0 #force treshold activation after poll_iter_tres_act pollings
cache_cleaning =0

#Vars
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
delta = 0
no_delta =1
clear_cache = 0
vari = []

#Dictionary for url perf:
d_perf_avg = {'url_trie_lookup' : 0, 'url_trie_lru_perf':0 }
d_perf_avg_tmp = {'url_trie_lookup' : 0, 'url_trie_lru_perf':0 }


# Command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-d", help="Enable debug", action="store_true")
parser.add_argument("-f", help="Force reaching threshold", action="store_true")
parser.add_argument("-c", help="Clear MP/DP caches automatically when reaching threshold", action="store_true")
args = parser.parse_args()
if args.d:
	debug=1
if args.f:
	force_tres = 1
if args.c:
	cache_cleaning =0	


#Testing if configuration file exists; configure firewall profile otherwise
if os.path.isfile(cfg):
	yesno = raw_input("configuration file exists, do you want to use it? (y/n) ")
	if yesno!='y':
		exit()
else:
	yesno = raw_input("configuration file does not exist, do you want to configure a firewall? (y/n) ")
	if yesno=='y':
		IP = raw_input("Enter Firewall IP: ")
		KEY = raw_input("Enter a valid Firewall API key: ")
		f_cfg = open(cfg, "w")
		f_cfg.write("IP "+IP+"\n")
		f_cfg.write("KEY "+KEY+"\n")
		f_cfg.write("THRESHOLD "+str(perf_thres)+"\n")
		f_cfg.write("POLLING "+str(poll_timer)+"\n")
		f_cfg.close()
	else:
		exit()

#Read configuration file
f_cfg = open(cfg, "r")
for tuple in f_cfg:
        if tuple[0] != '#':
                vari=tuple.split()
                if vari[0] == 'IP':
                    f_ip = vari[1]
                elif vari[0] == 'KEY':
                    f_key = vari[1]
                elif vari[0] == 'THRESHOLD':
                    perf_thres = int(vari[1])
                elif vari[0] == 'POLLING':
                    poll_timer = int(vari[1])                       
f_cfg.close()

#URLs for API calls
api_q = "https://"+f_ip+"/api/?type=op&cmd=<show><running><url-cache><statistics></statistics></url-cache></running></show>&key="+f_key
api_clear_cache_DP= "https://"+f_ip+"/api/?type=op&cmd=<clear><url-cache><all></all></url-cache></clear>&key="+f_key
api_clear_cache_MP= "https://"+f_ip+"/api/?type=op&cmd=<delete><url-database><all></all></url-database></delete>&key="+f_key

#assert code
if debug:
	print "IP: "+f_ip
	print "Key: "+f_key
	print "API call: "+api_q
#end of assert


#Change stdout to be console and history file
f_history = open(history,"a")
sys.stdout = Tee(sys.stdout, f_history)

#MAIN LOOP
while endless == 1:

	#debug code to force treshold activation
	if force_tres:
		poll_iter+=1
	#end of debug	
	os.system('clear')
	print "# Timestamp: ", str(datetime.now()),"#"
	print
	if clear_cache:
		api_rc=urllib2.urlopen(api_clear_cache_DP, context=ctx)
		print("URL cache in DP has been cleared!")
		time.sleep(5)
		api_rc=urllib2.urlopen(api_clear_cache_MP, context=ctx)
		time.sleep(5)
		clear_cache=0
		print("URL cache in MP has been cleared!")
		print
		
	api_a=urllib2.urlopen(api_q, context=ctx)

	result=api_a.read()
	tab_result=str.split(result)
	
	#assert code
	if debug:
		print "Raw splitted response:"
		print tab_result
	#end of assert
	for index, t_elem in enumerate(tab_result):
		#assert code
		if debug:
			print "Index: ",index,"Elem: ",t_elem
			print d_perf_avg.keys()
		#end of assert		
		if t_elem in d_perf_avg.keys():
			i_value = int(tab_result[index+2])
			#debug code to force treshold activation
			if poll_iter==poll_iter_tres_act:
				i_value+=(perf_thres+1)
			#end of debug
			if i_value>int(d_perf_avg_tmp[t_elem]):
				d_perf_avg_tmp[t_elem]=i_value

	# Display Result dictionary

	print "URL cache performance monitoring"
	print

	for d_key in d_perf_avg.keys():
		#covering corner case where delta is exceeding threshold when getting initial performance value. 
		if no_delta==0:
			delta=d_perf_avg_tmp[d_key]-d_perf_avg[d_key]
		d_perf_avg[d_key]=d_perf_avg_tmp[d_key]
		print d_key,": ",d_perf_avg[d_key]," (delta: ",delta,")"
		if delta>perf_thres:
			if cache_cleaning:
				print "(WARNING: Performance degradation beyond threshold; URL caches will be cleared)"
				print
				clear_cache=1
			else:
				print "(WARNING: Performance degradation beyond threshold; Clear URL caches manually ASAP)"
				print
				
	#reset temp dictionary
	for d_key in d_perf_avg_tmp.keys():
		d_perf_avg_tmp[d_key]=0
	
	no_delta=0
	print	
	
	#Wait for next polling	
	time.sleep(poll_timer)
	
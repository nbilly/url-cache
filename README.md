# url_cache.py #

Python script checking MP/DP URL caches performance numbers (URL TRIE and LRU).

By default, the script does not take any actions. 
It does only display a warning message when performance delta between 2 poll 
is exceeding a threshold. (by default 200 CPU cycles)

You can use argument '-c' to clear MP/DP cache automatically when reaching threshold.
(#python url_cache.py -h for details)

Script is connecting on Firewall using API; A valid API key is necessary.
API key and Firewall IP will be requested when script is executed the first time.

A config file 'url_cache.cfg' will be created:

IP [FIREWALL IP]
KEY [API KEY]
THRESHOLD 200
POLLING 60
Threshold and Polling value can be changed manually if needed:

THRESHOLD : maximum delta value for performance results between 2 polls
POLLING : Firewall polling intervall in seconds


#!/usr/bin/python3
# -*- coding: utf-8 -*-

try:
	import requests, json, sys, os, colorama, argparse
	from bs4 import BeautifulSoup
	from columnar import columnar
	from colorama import Fore, Back, Style
	colorama.init()
except ImportError:
	print("$ python3 -m pip install requests, columnar, colorama, BeautifulSoup")
	exit(-1)

vuln = []
heading = ["Results", "Costs per 1000 requests"]

def safesearch_api(apikey, reason=False, poc=False):
	url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+apikey
	response = requests.post(url, headers={"content-type":"application/json"})
	if response.status_code == 403 and "SERVICE_DISABLED" in response.text:
		print(Fore.RED+"[X] NOT VULNERABLE SAFESEARCH API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.text+Style.RESET_ALL) if reason is True else None
	else:
		print(Fore.CYAN+"[+] VULNERABLE SAFESEARCH API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] SafeSearch API"+Style.RESET_ALL
		price = Fore.CYAN+"$2"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)

def staticmap_api(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key='+apikey
	response = requests.get(url)
	if response.status_code == 200:
		print(Fore.CYAN+"[+] VULNERABLE STATICMAP API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Staticmap API"+Style.RESET_ALL
		price = Fore.CYAN+"$2"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE STATICMAP API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.text+Style.RESET_ALL) if reason is True else None

def streetview_api(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key='+apikey
	response = requests.get(url)
	if response.status_code == 200:
		print(Fore.CYAN+"[+] VULNERABLE STREETVIEW API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Streetview API"+Style.RESET_ALL
		price = Fore.CYAN+"$7"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE STREETVIEW API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.text+Style.RESET_ALL) if reason is True else None

def directions_api(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE DIRECTIONS API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Directions API"+Style.RESET_ALL
		price = Fore.CYAN+"$5"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
		api2 = Fore.GREEN+"[-] Directions API (Adv.)"+Style.RESET_ALL
		price2 = Fore.CYAN+"$10"+Style.RESET_ALL
		yyy = [api2,price2]
		vuln.append(yyy)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE DIRECTIONS API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['error_message']+Style.RESET_ALL) if reason is True else None

def geocode_api(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE GEOCODE API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Geocode API"+Style.RESET_ALL
		price = Fore.CYAN+"$5"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE GEOCODE API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['error_message']+Style.RESET_ALL) if reason is True else None

def distance_matrix_api(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE DISTANCE MATRIX API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Distance Matrix API"+Style.RESET_ALL
		price = Fore.CYAN+"$5"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
		api2 = Fore.GREEN+"[-] Distance Matrix API (Adv.)"+Style.RESET_ALL
		price2 = Fore.CYAN+"$10"+Style.RESET_ALL
		yyy = [api2,price2]
		vuln.append(yyy)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE DISTANCE MATRIX API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['error_message']+Style.RESET_ALL) if reason is True else None

def find_place(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE FIND PLACE FROM TEXT API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Find Place from Text API"+Style.RESET_ALL
		price = Fore.CYAN+"$17"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE FIND PLACE FROM TEXT API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['error_message']+Style.RESET_ALL) if reason is True else None

def autocomplete_api(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE AUTOCOMPLETE API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Autocomplete API"+Style.RESET_ALL
		price = Fore.CYAN+"$2.83"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
		api2 = Fore.GREEN+"[-] Autocomplete API per session"+Style.RESET_ALL
		price2 = Fore.CYAN+"$17"+Style.RESET_ALL
		yyy = [api2,price2]
		vuln.append(yyy)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE AUTOCOMPLETE API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['error_message']+Style.RESET_ALL) if reason is True else None	

def elevation_api(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE ELEVATION API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Elevation API"+Style.RESET_ALL
		price = Fore.CYAN+"$5"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE ELEVATION API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['error_message']+Style.RESET_ALL) if reason is True else None

def timezone_api(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key='+apikey
	response = requests.get(url)
	if 'errorMessage' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE TIMEZONE API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Timezone API"+Style.RESET_ALL
		price = Fore.CYAN+"$5"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE TIMEZONE API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['errorMessage']+Style.RESET_ALL) if reason is True else None

def nearest_roads(apikey, reason=False, poc=False):
	url = 'https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key='+apikey
	response = requests.get(url)
	if 'error' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE NEAREST ROADS API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Nearest Roads API"+Style.RESET_ALL
		price = Fore.CYAN+"$10"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE NEAREST ROADS API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()["error"]["message"]+Style.RESET_ALL) if reason is True else None

def geolocation_api(apikey, reason=False, poc=False):
	url = 'https://www.googleapis.com/geolocation/v1/geolocate?key='+apikey
	post = {'considerIp': 'true'}
	response = requests.post(url, data=post)
	if "error" not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE GEOLOCATION API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Command: curl -ski -X POST '"+url+"' -d '{\"considerIp\":\"true\"}'"+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Geolocation API"+Style.RESET_ALL
		price = Fore.CYAN+"$5"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE GEOLOCATION API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()["error"]["message"]+Style.RESET_ALL) if reason is True else None

def route(apikey, reason=False, poc=False):
	url = 'https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key='+apikey
	response = requests.get(url)
	if 'error' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE ROUTE TO TRAVEL API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Route to Travel API"+Style.RESET_ALL
		price = Fore.CYAN+"$10"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE ROUTE TO TRAVEL API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()["error"]["message"]+Style.RESET_ALL) if reason is True else None

def speedlimit_api(apikey, reason=False, poc=False):
	url = 'https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key='+apikey
	response = requests.get(url)
	if 'error' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE SPEED LIMIT-ROADS API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Speed limit-roads API"+Style.RESET_ALL
		price = Fore.CYAN+"$20"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE SPEED LIMIT-ROADS API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()["error"]["message"]+Style.RESET_ALL) if reason is True else None

def place_details(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE PLACE DETAILS API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Place Details API"+Style.RESET_ALL
		price = Fore.CYAN+"$17"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE PLACE DETAILS API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()["error_message"]+Style.RESET_ALL) if reason is True else None

def nearby_search(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE NEARBY SEARCH-PLACES API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Nearby Search-Places API"+Style.RESET_ALL
		price = Fore.CYAN+"$32"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE NEARBY SEARCH-PLACES API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['error_message']+Style.RESET_ALL) if reason is True else None

def text_search(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key='+apikey
	response = requests.get(url)
	if 'error_message' not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE TEXT SEARCH-PLACES API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Text Search-Places API"+Style.RESET_ALL
		price = Fore.CYAN+"$32"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE TEXT SEARCH-PLACES API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()['error_message']+Style.RESET_ALL) if reason is True else None

def places_photo(apikey, reason=False, poc=False):
	url = 'https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key='+apikey
	response = requests.get(url, allow_redirects=False)
	if response.status_code == 302:
		print(Fore.CYAN+"[+] VULNERABLE PLACES PHOTO API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Link: "+url+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Places Photo API"+Style.RESET_ALL
		price = Fore.CYAN+"$7"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE PLACES PHOTO API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: Verbose responses are not enabled for this API, cannot determine the reason."+Style.RESET_ALL) if reason is True else None

def playable_locations(apikey, reason=False, poc=False):
	url = 'https://playablelocations.googleapis.com/v3:samplePlayableLocations?key='+apikey
	post = {'area_filter':{'s2_cell_id':7715420662885515264},'criteria':[{'gameObjectType':1,'filter':{'maxLocationCount':4,'includedTypes':['food_and_drink']},'fields_to_return': {'paths': ['name']}},{'gameObjectType':2,'filter':{'maxLocationCount':4},'fields_to_return': {'paths': ['types', 'snapped_point']}}]}
	response = requests.post(url, data=post)
	if "error" not in response.text:
		print(Fore.CYAN+"[+] VULNERABLE PLAYABLE LOCATIONS API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Command: curl -ski -X POST '"+url+"' -d '{\"area_filter\":{\"s2_cell_id\":7715420662885515264},\"criteria\":[{\"gameObjectType\":1,\"filter\":{\"maxLocationCount\":4,\"includeTypes\":[\"food_and_drink\"]},\"fields_to_return\":{\"paths\":[\"name\"]}},{\"gameObjectType\":2,\"filter\":{\"maxLocationCount\":4},\"fields_to_return\":{\"paths\":[\"types\",\"snapped_point\"]}}]}'"+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] Playable Locations API"+Style.RESET_ALL
		price = Fore.CYAN+"$10"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE PLAYABLE LOCATIONS API"+Style.RESET_ALL)
		print(Fore.YELLOW+"[!] Reason: "+response.json()["error"]["message"]+Style.RESET_ALL) if reason is True else None

def fcm_api(apikey, reason=False, poc=False):
	url = 'https://fcm.googleapis.com/fcm/send'
	post = {'registration_ids':['ABC']}
	heads = {'Content-Type': 'application/json', 'Authorization':'key='+apikey}
	response = requests.post(url, headers=heads, data=post)
	if response.status_code == 200:
		print(Fore.CYAN+"[+] VULNERABLE FCM API"+Style.RESET_ALL)
		print(Fore.MAGENTA+"PoC Command: curl -X POST '"+url+"' -d '{\"registration_ids\":[\"ABC\"]}' -H 'Content-Type: application/json' -H 'Authorization: key="+apikey+"'"+Style.RESET_ALL) if poc is True else None
		api = Fore.GREEN+"[-] FCM API"+Style.RESET_ALL
		price = Fore.CYAN+"https://abss.me/posts/fcm-takeover/"+Style.RESET_ALL
		xxx = [api,price]
		vuln.append(xxx)
	else:
		print(Fore.RED+"[X] NOT VULNERABLE FCM API"+Style.RESET_ALL)
		soup = BeautifulSoup(response.content, "lxml")
		title = str(soup.find("title"))
		print(Fore.YELLOW+"[!] Reason: "+title[7:-8]+Style.RESET_ALL) if reason is True else None

def js_api(apikey):
	html_file = open('jsapi_test.html', 'w+')
	html_file.write("<!DOCTYPE html><html><head><script src='https://maps.googleapis.com/maps/api/js?key="+apikey+"&callback=initMap&libraries=&v=weekly' defer></script><style type='text/css'>#map{height:100%;}html,body{height:100%;margin:0;padding:0;}</style><script>let map;function initMap(){map=new google.maps.Map(document.getElementById('map'),{center:{lat:-34.397,lng:150.644},zoom:8,});}</script></head><body><div id='map'></div></body></head></html>")
	html_file.close()
	print("\n")
	print("#"*15+" JS API TEST "+"#"*15)
	print(Fore.YELLOW+"[!] Open the jsapi_test.html to your browser!"+Style.RESET_ALL)
	print(Fore.RED+"[X] Sorry! Something went wrong."+Style.RESET_ALL)
	print(Fore.GREEN+"[+] Map is Loaded!"+Style.RESET_ALL)
	print("#"*43)

def banner():
	banner = """

	  ▄████  ███▄ ▄███▓ ▄▄▄       ██▓███    ██████     ▄▄▄       ██▓███   ██▓   ▄▄▄█████▓▓█████   ██████ ▄▄▄█████▓
	 ██▒ ▀█▒▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒▒██    ▒    ▒████▄    ▓██░  ██▒▓██▒   ▓  ██▒ ▓▒▓█   ▀ ▒██    ▒ ▓  ██▒ ▓▒
	▒██░▄▄▄░▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒░ ▓██▄      ▒██  ▀█▄  ▓██░ ██▓▒▒██▒   ▒ ▓██░ ▒░▒███   ░ ▓██▄   ▒ ▓██░ ▒░
	░▓█  ██▓▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒  ▒   ██▒   ░██▄▄▄▄██ ▒██▄█▓▒ ▒░██░   ░ ▓██▓ ░ ▒▓█  ▄   ▒   ██▒░ ▓██▓ ░ 
	░▒▓███▀▒▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░▒██████▒▒    ▓█   ▓██▒▒██▒ ░  ░░██░     ▒██▒ ░ ░▒████▒▒██████▒▒  ▒██▒ ░ 
	 ░▒   ▒ ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░    ▒▒   ▓▒█░▒▓▒░ ░  ░░▓       ▒ ░░   ░░ ▒░ ░▒ ▒▓▒ ▒ ░  ▒ ░░   
	  ░   ░ ░  ░      ░  ▒   ▒▒ ░░▒ ░     ░ ░▒  ░ ░     ▒   ▒▒ ░░▒ ░      ▒ ░       ░     ░ ░  ░░ ░▒  ░ ░    ░    
	░ ░   ░ ░      ░     ░   ▒   ░░       ░  ░  ░       ░   ▒   ░░        ▒ ░     ░         ░   ░  ░  ░    ░      
	      ░        ░         ░  ░               ░           ░  ░          ░                 ░  ░      ░           
"""
	print(banner)

def main():
	banner()
	parser = argparse.ArgumentParser(description='')
	parser.add_argument('-a', '--apikey', nargs='?', action="store", help='Google Maps API Key')
	parser.add_argument('-r', '--reason', default=False, action="store_true", help="Print Reason")
	parser.add_argument('-p', '--poc', default=False, action="store_true", help="Print PoC")
	parser.add_argument('-j', '--jsapi', default=False, action="store_true", help="Test JS API")
	args = parser.parse_args()

	if args.apikey:
		safesearch_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else safesearch_api(args.apikey)
		staticmap_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else staticmap_api(args.apikey)
		streetview_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else streetview_api(args.apikey)
		directions_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else directions_api(args.apikey)
		geocode_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else geocode_api(args.apikey)
		distance_matrix_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else distance_matrix_api(args.apikey)
		find_place(args.apikey, args.reason, args.poc) if args.poc or args.reason else find_place(args.apikey)
		autocomplete_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else autocomplete_api(args.apikey)
		elevation_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else elevation_api(args.apikey)
		timezone_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else timezone_api(args.apikey)
		nearest_roads(args.apikey, args.reason, args.poc) if args.poc or args.reason else nearest_roads(args.apikey)
		geolocation_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else geolocation_api(args.apikey)
		route(args.apikey, args.reason, args.poc) if args.poc or args.reason else route(args.apikey)
		speedlimit_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else speedlimit_api(args.apikey)
		place_details(args.apikey, args.reason, args.poc) if args.poc or args.reason else place_details(args.apikey)
		nearby_search(args.apikey, args.reason, args.poc) if args.poc or args.reason else nearby_search(args.apikey)
		text_search(args.apikey, args.reason, args.poc) if args.poc or args.reason else text_search(args.apikey)
		places_photo(args.apikey, args.reason, args.poc) if args.poc or args.reason else places_photo(args.apikey)
		playable_locations(args.apikey, args.reason, args.poc) if args.poc or args.reason else playable_locations(args.apikey)
		fcm_api(args.apikey, args.reason, args.poc) if args.poc or args.reason else fcm_api(args.apikey)
		if args.jsapi:
			js_api(args.apikey)
		print('\n')
		if vuln:
			tbl = columnar(vuln, heading, no_borders=True)
			print(tbl)
		print("*"*30)
		print("Reference for up-to-date pricing:")
		print("* https://cloud.google.com/maps-platform/pricing")
		print("* https://developers.google.com/maps/billing/gmp-billing")
		print("*"*30)
	else:
		print(Fore.RED+"Wrong Argument, Go Home.. your drunk Asshole!"+Style.RESET_ALL)
		exit(-1)

if __name__ == "__main__":
	main()

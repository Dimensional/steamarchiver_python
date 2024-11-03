#!/usr/bin/env python3
import json
from steam.client import SteamClient
import steam.webauth as wa
from steam.enums import EResult
from os import makedirs
from os.path import exists
from datetime import datetime
from dateutil.relativedelta import relativedelta

def auto_login(client, username="", password="", fallback_anonymous=True, relogin=True):
    assert(type(client) == SteamClient)
    makedirs("./auth", exist_ok=True)
    
    webauth = wa.WebAuth()
    
    ## If we are not signing in and doing anonymous access
    if username == "anonymous":
        client.anonymous_login()
        return
    # If we have set a username and password in command line
    if username != "" and password != "":
        LOGON_DETAILS = {
			'username' : username,
			'password' : password,
        }
        try:
            webauth.login(**LOGON_DETAILS)
        except wa.TwoFactorCodeRequired:
            webauth.login(code=input("Enter SteamGuard Code: "))
        except wa.EmailCodeRequired:
            webauth.login(code=input("Enter Email Code: "))
        
        # We are setting the auth file for refresh token storage
        keypath = "./auth/credentials.json"
        if exists(keypath):
            with open(keypath) as f:
                credentials = json.load(f)
            # the Expiration Date field is required in order
            # to update the day before the Refresh Token expires
            expirationDate = datetime.strptime(credentials['expires'], "%Y-%m-%d %H:%M:%S.%f")
            dateNow = datetime.now()
            
            # If the username does not match the one on file, we need to make a new one
            if credentials['username'] != webauth.username:
                credentials = {
					'expires': (datetime.now() + relativedelta(months=6, days=-1)).strftime("%Y-%m-%d %H:%M:%S.%f"),
    				'username': webauth.username,
            		'refresh_token': webauth.refresh_token,
				}
                with open(keypath, 'w') as f:
                    json.dump(credentials, f, indent=4)
        else:
            credentials = {
                'expires': (datetime.now() + relativedelta(months=6, days=-1)).strftime("%Y-%m-%d %H:%M:%S.%f"),
				'username': webauth.username,
                'refresh_token': webauth.refresh_token,
			}
            with open(keypath, 'w') as f:
                json.dump(credentials, f, intend=4)
            
        print("Logging in as", username, "using saved login key")
        client.login(webauth.username, access_token=webauth.refresh_token)
        
        # if the Refresh Token is about to expire
        # Renew it.
        # if dateNow > expirationDate:
        #     credentials = {
		# 		'expires': (datetime.now() + relativedelta(months=6, days=-1)).strftime("%Y-%m-%d %H:%M:%S.%f"),
    	# 		'username': webauth.username,
        #     	'refresh_token': webauth.refresh_token,
		# 	}
        #     with open(keypath, 'w') as f:
        #         json.dump(credentials, f, indent=4)
        
        return post_login(client)
    if username == "" and exists("./auth/credentials.json") and relogin:
        with open("./auth/credentials.json", "r") as f: credentials = json.load(f)
        client.login(credentials['username'], access_token=credentials['refresh_token'])
        return post_login(client)
    # if no username, fall back to either anonymous or CLI login based on fallback_anonymous
    if fallback_anonymous:
        client.anonymous_login()
        return
    else:
        webauth.cli_login(input("Steam User: "))
        client.login(webauth.username, access_token=webauth.refresh_token)
        
        return post_login(client)

def post_login(client, used_login_key=False):
    assert(type(client) == SteamClient)
    makedirs("./auth/", exist_ok=True)
    # if not used_login_key:
    #     if not client.login_key:
    #         print("Waiting for login key...")
    #         client.wait_event(SteamClient.EVENT_NEW_LOGIN_KEY)
    #     print("Writing login key...")
    #     with open("./auth/" + client.username + ".txt", "w") as f:
    #         f.write(client.login_key)
    with open("./auth/lastuser.txt", "w") as f:
        f.write(client.username)

if __name__ == "__main__":
    auto_login(SteamClient(), fallback_anonymous=False, relogin=False)

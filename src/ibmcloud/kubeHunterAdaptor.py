import time
import json
import sys
import requests
import logging
import argparse
import datetime
import string
import random
from kubeHunterResultsParser import fetchVulList
from kubeHunterL1Adaptor import postToSA


# Change the context according to your service

def obtain_iam_token(api_key, token_url):
    if not api_key:
        raise Exception("obtain_uaa_token: missing api key")

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }

    body = 'grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=' + api_key + '&response_type=cloud_iam'

    try:
        response = requests.post(token_url, data=body, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logger.exception("An unexpected error was encountered while obtaining IAM token" + str(err))
        return None
    if response.status_code == 200 and response.json()['access_token']:
        return response.json()['access_token']        

def adaptInsightsToOccurence(category,vulnerability,evidence,location,description, account_id , cluster_name):
	finding_type = ""
	provider_id = ""	
	if category.strip() == "Information Disclosure" :
		finding_type = "kubehunteribmcloud-information-disclosure"
		provider_id = "kubeHunterIBMCloudInformationDisclosure"
	elif category.strip() == "Remote Code Execution" :
		finding_type = "kubehunteribmcloud-remote-code-execution"
		provider_id = "kubeHunterIBMCloudRemoteCodeExecutor"		
	elif category.strip() == "Identity Theft" :
		finding_type = "kubehunteribmcloud-identity-and-access"
		provider_id = "kubeHunterIBMCloudIdentityAndAccess"	
				
	elif category.strip() == "Unauthenticated Access" :
		finding_type = "kubehunteribmcloud-identity-and-access"
		provider_id = "kubeHunterIBMCloudIdentityAndAccess"		
	elif category.strip() == "Access Risk" :
		finding_type = "kubehunteribmcloud-identity-and-access"
		provider_id = "kubeHunterIBMCloudIdentityAndAccess"				
	elif category.strip() == "Privilege Escalation" :
		finding_type = "kubehunteribmcloud-identity-and-access"
		provider_id = "kubeHunterRedhatIdentityAndAccess"	
	elif category.strip() == "Denial of Service" :
		finding_type = "kubehunteribmcloud-denial-of-service"
		provider_id = "kubeHunterIBMCloudDenialofService"

	pay_json = {			
        "note_name": str(account_id) + "/providers/" + str(provider_id) + "/notes/" + str(finding_type),
        "kind": "FINDING",
        "message": evidence,
        "description": cluster_name + " : " + vulnerability + " "+ location,
        "remediation": description,
        "provider_id": provider_id,
        "context" : {
            "resource_name": cluster_name,
            "resource_type": "cluster",
        },
        "id": id_generator(),
        "finding": {
            "severity": "LOW",
            "next_steps": [{
			"title": category +": Please check following : \n"+ description +"  "+location
			}]
        }
    } 
	return pay_json
    



def id_generator(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))


# This method needs to be defined for any partner application that needs to adapt
def fetchInsightsReportedByPartner(account_id, cluster_name):
    fileName = '/vul.txt'
    kubeHunterVulnerabilities = fetchVulList(fileName)
    vulnerabilityInsights = {"insights": []}
    
    for vulnerability in kubeHunterVulnerabilities:
        location = ""
        evidence = ""
        try :                
        	if  vulnerability['LOCATION'] :
        		location = vulnerability['LOCATION']
        except : 
        	location = ""   
        
        try :                
        	if  vulnerability['EVIDENCE'] :
        		evidence = vulnerability['EVIDENCE']
        except : 
        	evidence = ""                     
        vulnerabilityInstance = adaptInsightsToOccurence(vulnerability['CATEGORY'],vulnerability['VULNERABILITY'],evidence,location,vulnerability['DESCRIPTION'], account_id, cluster_name)
        vulnerabilityInsights["insights"].append(vulnerabilityInstance)

    return vulnerabilityInsights


def main(args):

    account_id = args[1]
    apikey = args[2]
    cluster_name = args[3]
    endpoint = args[4]
    vulnerabilityInsights = fetchInsightsReportedByPartner(account_id, cluster_name)
    postToSA({"vulnerabilityInsights": vulnerabilityInsights,
            "apikey": apikey,
            "account": account_id,
            "endpoint": endpoint})


if __name__ == "__main__":
    main(sys.argv)

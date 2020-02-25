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

def adaptInsightsToOccurence(category,vulnerability,evidence,location,description, account_id , cluster_name):
	finding_type = ""
	provider_id = ""
    category = "".join(category.split()).strip()	
	if category == "Information Disclosure" :
		finding_type = "kubehunterredhat-information-disclosure"
		provider_id = "kubeHunterRedhatInformationDisclosure"
	elif category == "Remote Code Execution" :
		finding_type = "kubehunterredhat-remote-code-execution"
		provider_id = "kubeHunterRedhatRemoteCodeExecutor"		
	elif category == "Identity Theft" :
		finding_type = "kubehunterredhat-identity-and-access"
		provider_id = "kubeHunterRedhatIdentityAndAccess"	
				
	elif category == "Unauthenticated Access" :
		finding_type = "kubehunterredhat-identity-and-access"
		provider_id = "kubeHunterRedhatIdentityAndAccess"		
	elif category == "Access Risk" :
		finding_type = "kubehunterredhat-identity-and-access"
		provider_id = "kubeHunterRedhatIdentityAndAccess"				
	elif category == "Privilege Escalation" :
		finding_type = "kubehunterredhat-identity-and-access"
		provider_id = "kubeHunterRedhatIdentityAndAccess"	
	elif category == "Denial of Service" :
		finding_type = "kubehunterredhat-denial-of-service"
		provider_id = "kubeHunterRedhatDenialofService"

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
        try :                
        	if  vulnerability['LOCATION'] :
        		location = vulnerability['LOCATION']
        except : 
        	location = ""          
        vulnerabilityInstance = adaptInsightsToOccurence(vulnerability['CATEGORY'],vulnerability['VULNERABILITY'],vulnerability['EVIDENCE'],location,vulnerability['DESCRIPTION'], account_id, cluster_name)
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

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
from ibm_cloud_sdk_core.authenticators import BearerTokenAuthenticator, IAMAuthenticator
from ibm_security_advisor_findings_api_sdk import FindingsApiV1

logger = logging.getLogger("adaptor")
logger.setLevel(logging.INFO)     

def adaptInsightsToOccurence(category,vulnerability,evidence,location,description, account_id , cluster_name):
    finding_type = ""
    provider_id = ""
    category = "".join(category.split()).strip()
    if category == "InformationDisclosure" :
        finding_type = "kubehunteribmcloud-information-disclosure"
        provider_id = "kubeHunterIBMCloudInformationDisclosure"
    elif category == "RemoteCodeExecution" :
        finding_type = "kubehunteribmcloud-remote-code-execution"
        provider_id = "kubeHunterIBMCloudRemoteCodeExecutor"		
    elif category == "IdentityTheft" :
        finding_type = "kubehunteribmcloud-identity-and-access"
        provider_id = "kubeHunterIBMCloudIdentityAndAccess"	
                
    elif category == "UnauthenticatedAccess" :
        finding_type = "kubehunteribmcloud-identity-and-access"
        provider_id = "kubeHunterIBMCloudIdentityAndAccess"		
    elif category == "AccessRisk" :
        finding_type = "kubehunteribmcloud-identity-and-access"
        provider_id = "kubeHunterIBMCloudIdentityAndAccess"				
    elif category == "PrivilegeEscalation" :
        finding_type = "kubehunteribmcloud-identity-and-access"
        provider_id = "kubeHunterRedhatIdentityAndAccess"	
    elif category == "DenialofService" :
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

import time
import json
import sys
import requests
import logging
import argparse
import datetime
import string
import random
import os

logging.basicConfig()
logger = logging.getLogger("kubehunter")

vulnerablity_notes_defenition = {
    "notes": [
        {
            "kind": "FINDING",
            "short_description": "Kube hunter redhatOS Information Disclosure",
            "long_description": "Kube hunter redhatOS Information Disclosure",
            "provider_id": "kubeHunterRedhatInformationDisclosure",
            "id": "kubehunterredhat-information-disclosure",
            "reported_by": {
                "id": "kubehunterredhat-information-disclosure",
                "title": "Kubehunter redhat openshift control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "Kube hunter redhatOS Information Disclosure"
                }]
            }
        },
        {
            "kind": "FINDING",
            "short_description": "Kube hunter redhatOS Remote Code Execution",
            "long_description": "Kube hunter redhatOS Remote Code Execution",
            "provider_id": "kubeHunterRedhatRemoteCodeExecutor",
            "id": "kubehunterredhat-remote-code-execution",
            "reported_by": {
                "id": "kubehunterredhat-remote-code-execution",
                "title": "Kubehunter redhat openshift control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "Kube hunter redhatOS Remote Code Execution"
                }]
            }
        },
        {
            "kind": "FINDING",
            "short_description": "Kube hunter redhatOS Identity And Access",
            "long_description": "Kube hunter redhatOS Identity And Access",
            "provider_id": "kubeHunterRedhatIdentityAndAccess",
            "id": "kubehunterredhat-identity-and-access",
            "reported_by": {
                "id": "kubehunterredhat-identity-and-access",
                "title": "Kubehunter redhat openshift control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "Kube hunter redhatOS Identity And Access"
                }]
            }
        },       
        {
            "kind": "FINDING",
            "short_description": "Kube hunter redhatOS Denial of Service",
            "long_description": "Kube hunter redhatOS Denial of Service",
            "provider_id": "kubeHunterRedhatDenialofService",
            "id": "kubehunterredhat-denial-of-service",
            "reported_by": {
                "id": "kubehunterredhat-denial-of-service",
                "title": "Kube hunter redhatOS Kubehunter control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "Kube hunter redhatOS Denial of Service"
                }]
            }
        },
        {
            "kind": "CARD",
            "provider_id": "kubeHunterRedhatOpenshift",
            "id": "kubehunterredhat-openshift-card",
            "short_description": "Kubehunter redhat openshift vulnerabilities",
            "long_description": "Kubehunter redhat openshift reported vulnerabilities",
            "reported_by": {
                "id": "kubehunterredhat-openshift-card",
                "title": "Kubehunter redhat openshift vulnerabilities"
            },
            "card": {
                "section": "Container Config Exposures",
                "title": "Kube-Hunter",
                "subtitle": "Redhat Openshift",
                "context" : {},
                "finding_note_names": [
                    "providers/kubeHunterRedhatInformationDisclosure/notes/kubehunterredhat-information-disclosure",
                    "providers/kubeHunterRedhatRemoteCodeExecutor/notes/kubehunterredhat-remote-code-execution",
                    "providers/kubeHunterRedhatIdentityAndAccess/notes/kubehunterredhat-identity-and-access",  
                    "providers/kubeHunterRedhatDenialofService/notes/kubehunterredhat-denial-of-service"              
                ],
                "elements": [{
                    "kind": "NUMERIC",
                    "text": "InformationDisclosure",
                    "default_time_range": "4d",
                    "value_type": {
                        "kind": "FINDING_COUNT",
                        "finding_note_names": [
                            "providers/kubeHunterRedhatInformationDisclosure/notes/kubehunterredhat-information-disclosure"
                        ]
                    }
                },
                    {
                        "kind": "NUMERIC",
                        "text": "RemoteCodeExecution",
                        "default_time_range": "4d",
                        "value_type": {
                            "kind": "FINDING_COUNT",
                            "finding_note_names": [
                                "providers/kubeHunterRedhatRemoteCodeExecutor/notes/kubehunterredhat-remote-code-execution"
                            ]
                        }
                    },
                 {
                        "kind": "NUMERIC",
                        "text": "IdentityAndAccess",
                        "default_time_range": "4d",
                        "value_type": {
                            "kind": "FINDING_COUNT",
                            "finding_note_names": [
                                "providers/kubeHunterRedhatIdentityAndAccess/notes/kubehunterredhat-identity-and-access"
                            ]
                        }
                    },
                    {
                        "kind": "NUMERIC",
                        "text": "DenialofService",
                        "default_time_range": "4d",
                        "value_type": {
                            "kind": "FINDING_COUNT",
                            "finding_note_names": [
                                "providers/kubeHunterRedhatDenialofService/notes/kubehunterredhat-denial-of-service"
                            ]
                        }
                    }
                    
                ]
            }
        }
    ]
}


def obtain_iam_token(api_key):
    if not api_key:
        raise Exception("obtain_uaa_token: missing api key")

    token_url = os.environ['TOKEN_URL']
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


def create_note(account_id, token, endpoint):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    for note in vulnerablity_notes_defenition["notes"]:
        if note['kind'] == "CARD":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatOpenshift/notes"
  
        elif note['provider_id'] == "kubeHunterRedhatInformationDisclosure":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatInformationDisclosure/notes"
        elif note['provider_id'] == "kubeHunterRedhatRemoteCodeExecutor":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatRemoteCodeExecutor/notes"
        elif note['provider_id'] == "kubeHunterRedhatIdentityAndAccess":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatIdentityAndAccess/notes"
        elif note['provider_id'] == "kubeHunterRedhatDenialofService":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatDenialofService/notes"
            
            
        try:
            response = requests.post(url, data=json.dumps(note), headers=headers)
            response.raise_for_status()                
        except requests.exceptions.HTTPError as err:
            logger.exception("An unexpected error was encountered while creating note" + str(err))
        if response.status_code == 200:
            logger.info("Note created : %s" % note['id'])


def get_all_kubehunternotes(account_id, token, endpoint):
    notes = []
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatOpenshift/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatInformationDisclosure/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatRemoteCodeExecutor/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatIdentityAndAccess/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatDenialofService/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    return notes


def get_notes(account_id, token, endpoint, url):
    occurrences = []
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logger.exception("An unexpected error was encountered while getting the note" + str(err))
        return False
    if response.status_code == 200:
        body = response.json()
        for note in body['notes']:
            occurrences.append(note['id'])
        return note
    else:
        return []


def delete_notes(account_id, token, endpoint, notes):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    for note in notes:
        if note['kind'] == "CARD":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatOpenshift/notes"
        elif note['provider_id'] == "kubeHunterRedhatInformationDisclosure":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatInformationDisclosure/notes"
        elif note['provider_id'] == "kubeHunterRedhatRemoteCodeExecutor":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatRemoteCodeExecutor/notes"

        elif note['provider_id'] == "kubeHunterRedhatIdentityAndAccess":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatIdentityAndAccess/notes"
        elif note['provider_id'] == "kubeHunterRedhatDenialofService":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatDenialofService/notes"
            
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
        except:
            logger.exception("An unexpected error was encountered while deleting the note" + str(err))
        time.sleep(1)


def get_all_kubehunteroccurrences(account_id, token, endpoint):
    occurrences = []
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatOpenshift/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatInformationDisclosure/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatRemoteCodeExecutor/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatIdentityAndAccess/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatDenialofService/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    return occurrences


def get_occurrences(account_id, token, endpoint, url):
    occurrences = []
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logger.exception("An unexpected error was encountered while getting the occurrences" + str(err))
        return False
    if response.status_code == 200:
        body = response.json()
        for occurrence in body['occurrences']:
            occurrences.append(occurrence)
        return occurrences


def delete_occurrences(account_id, token, endpoint, occurrences):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    for occurrence in occurrences:
        if occurrence['provider_id'] == "kubeHunterRedhatInformationDisclosure":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatInformationDisclosure/occurrences/" + occurrence['id']
        elif occurrence['provider_id'] == "kubeHunterRedhatRemoteCodeExecutor":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatRemoteCodeExecutor/occurrences/" + occurrence['id']

        elif occurrence['provider_id'] == "kubeHunterRedhatIdentityAndAccess":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatIdentityAndAccess/occurrences/" + occurrence['id']
        elif occurrence['provider_id'] == "kubeHunterRedhatDenialofService":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatDenialofService/occurrences/" + occurrence['id']

        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.exception("An unexpected error was encountered while deleting the occurrence" + str(err))
        time.sleep(1)


def id_generator(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))


# This method needs to be defined for any partner application that needs to adapt
def createOccurences(account_id, token, endpoint, occurrencesJson):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    for occurrence in occurrencesJson:
        print("occurrencesJson is",occurrencesJson)
        if occurrence['provider_id'] == "kubeHunterRedhatInformationDisclosure":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatInformationDisclosure/occurrences"
        elif occurrence['provider_id'] == "kubeHunterRedhatRemoteCodeExecutor":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatRemoteCodeExecutor/occurrences"
        elif occurrence['provider_id'] == "kubeHunterRedhatIdentityAndAccess":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatIdentityAndAccess/occurrences"
        elif occurrence['provider_id'] == "kubeHunterRedhatDenialofService":
            url = endpoint + "/" + account_id + "/providers/kubeHunterRedhatDenialofService/occurrences" 
        try:
            response = requests.post(url, data=json.dumps(occurrence), headers=headers)
            print("response is",response)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.exception("An unexpected error was encountered while creating occurrence" + str(err))
        if response.status_code == 200:
            logging.info("Created occurrence")
		    

def executePointInTimeVulnerabilityOccurenceAdapter(apikey, account_id, endpoint, vulnerabilitiesReportedByPartner):
    token = obtain_iam_token(apikey)
    try:
        create_note(account_id, token, endpoint)
    except:
        print("ignoring metadata duplicate errors")
    try:
        vulnerabilityOccurrences = get_all_kubehunteroccurrences(account_id, token, endpoint)
        delete_occurrences(account_id, token, endpoint, vulnerabilityOccurrences)
    except:
        print("ignoring metadata duplicate errors")


    createOccurences(account_id, token, endpoint, vulnerabilitiesReportedByPartner["insights"])
    occurrences = get_all_kubehunteroccurrences(account_id, token, endpoint)
    return occurrences


def postToSA(args):
    apikey = args["apikey"]
    account_id = args["account"]
    endpoint = args["endpoint"]
    vulnerabilityOccurrences = executePointInTimeVulnerabilityOccurenceAdapter(apikey, account_id, endpoint,
                                                                               args["vulnerabilityInsights"])
    return {'insights': vulnerabilityOccurrences}

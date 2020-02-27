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
from ibm_cloud_sdk_core.authenticators import BearerTokenAuthenticator, IAMAuthenticator
from ibm_security_advisor_findings_api_sdk import FindingsApiV1

logger = logging.getLogger("l1_adaptor")
logger.setLevel(logging.INFO)

vulnerablity_notes_definition = {
    "notes": [
        {
            "kind": "FINDING",
            "short_description": "kube-hunter IBM Cloud Information Disclosure",
            "long_description": "Kube-hunter IBM Cloud Information Disclosure",
            "provider_id": "kubeHunterIBMCloudInformationDisclosure",
            "id": "kubehunteribmcloud-information-disclosure",
            "reported_by": {
                "id": "kubehunteribmcloud-information-disclosure",
                "title": "kube-hunter IBM Cloud Control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "kube-hunter IBM Cloud Information Disclosure"
                }]
            }
        },
        {
            "kind": "FINDING",
            "short_description": "kube-hunter IBM Cloud Remote Code Execution",
            "long_description": "kube-hunter IBM Cloud Remote Code Execution",
            "provider_id": "kubeHunterIBMCloudRemoteCodeExecutor",
            "id": "kubehunteribmcloud-remote-code-execution",
            "reported_by": {
                "id": "kubehunteribmcloud-remote-code-execution",
                "title": "kube-hunter IBM Cloud Control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "kube-hunter IBM Cloud Remote Code Execution"
                }]
            }
        },
        {
            "kind": "FINDING",
            "short_description": "kube-hunter IBM Cloud Identity And Access",
            "long_description": "kube-hunter IBM Cloud Identity And Access",
            "provider_id": "kubeHunterIBMCloudIdentityAndAccess",
            "id": "kubehunteribmcloud-identity-and-access",
            "reported_by": {
                "id": "kubehunteribmcloud-identity-and-access",
                "title": "kube-hunter IBM Cloud control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "kube-hunter IBM Cloud Identity And Access"
                }]
            }
        },       
        {
            "kind": "FINDING",
            "short_description": "kube-hunter IBM Cloud Denial of Service",
            "long_description": "kube-hunter IBM Cloud Denial of Service",
            "provider_id": "kubeHunterIBMCloudDenialofService",
            "id": "kubehunteribmcloud-denial-of-service",
            "reported_by": {
                "id": "kubehunteribmcloud-denial-of-service",
                "title": "kube-hunter IBM Cloud control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "kube-hunter IBM Cloud Denial of Service"
                }]
            }
        },
        {
            "kind": "CARD",
            "provider_id": "kubeHunterIBMCloud",
            "id": "kubehunteribmcloud-card",
            "short_description": "kube-hunter IBM Cloud Vulnerabilities",
            "long_description": "kube-hunter IBM Cloud Vulnerabilities",
            "reported_by": {
                "id": "kubehunteribmcloud-card",
                "title": "kube-hunter IBM Cloud Vulnerabilities"
            },
            "card": {
                "section": "Container Config Exposures",
                "title": "Kube Hunter",
                "subtitle": "Kubernetes Security",
                "finding_note_names": [
                    "providers/kubeHunterIBMCloudInformationDisclosure/notes/kubehunteribmcloud-information-disclosure",
                    "providers/kubeHunterIBMCloudRemoteCodeExecutor/notes/kubehunteribmcloud-remote-code-execution",
                    "providers/kubeHunterIBMCloudIdentityAndAccess/notes/kubehunteribmcloud-identity-and-access",  
                    "providers/kubeHunterIBMCloudDenialofService/notes/kubehunteribmcloud-denial-of-service"              
                ],
                "elements": [{
                    "kind": "NUMERIC",
                    "text": "InformationDisclosure",
                    "default_time_range": "4d",
                    "value_type": {
                        "kind": "FINDING_COUNT",
                        "finding_note_names": [
                            "providers/kubeHunterIBMCloudInformationDisclosure/notes/kubehunteribmcloud-information-disclosure"
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
                                "providers/kubeHunterIBMCloudRemoteCodeExecutor/notes/kubehunteribmcloud-remote-code-execution"
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
                                "providers/kubeHunterIBMCloudIdentityAndAccess/notes/kubehunteribmcloud-identity-and-access"
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
                                "providers/kubeHunterIBMCloudDenialofService/notes/kubehunteribmcloud-denial-of-service"
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
        raise Exception("obtain_iam_token: missing api key")
    try:
        authenticator = IAMAuthenticator(api_key, url=os.environ['TOKEN_URL'])
        token = authenticator.token_manager.get_token()
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while obtaining IAM token: "+str(err))
        sys.exit(1)
    if token:
        return token


def create_note(account_id, token, endpoint):
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for note in vulnerablity_notes_definition["notes"]:
            response = findingsAPI.create_note(
                account_id=account_id,
                **note
            )
            if response.get_status_code() == 200:
                logger.info("created note: %s" % note['id'])
            elif response.get_status_code() == 409 and note['kind'] == "CARD":
                logger.info("card already present... attempting to update")
                change_card(account_id, token, endpoint, note)
            else:
                logger.error("unable to create note: %s" % note['id'])
    except:
        logger.exception("an unexpected error was encountered while creating note")


def change_card(account_id, token, endpoint, note):
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        response = findingsAPI.update_note(
            account_id=account_id,
            note_id=note['id']
            **note
        )
        if response.get_status_code() == 200:
            logger.info("card updated: %s" % note['id'])
        else:
            logger.error("card not updated: %s" % note['id'])
    except:
        logger.exception("an unexpected error was encountered while updating note")


def get_all_kubehunternotes(account_id, token, endpoint):
    providers = [
        "kubeHunterIBMCloud",
        "kubeHunterIBMCloudInformationDisclosure",
        "kubeHunterIBMCloudRemoteCodeExecutor",
        "kubeHunterIBMCloudIdentityAndAccess",
        "kubeHunterIBMCloudDenialofService"
    ]
    notes.extend(get_notes(account_id, token, endpoint, providers))
    return notes


def get_notes(account_id, token, endpoint, url):
    notes = []
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for provider in providers:
            response = findingsAPI.list_notes(
                account_id=account_id, 
                provider_id=provider
            )
            if response.get_status_code() == 200:
                logger.info("got notes by provider: %s" % provider)
                for note in response.get_result()['notes']:
                    notes.append(note)
            else:
                logger.error("unable to get notes by provider: %s" % provider)
        return notes
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while getting the note: "+str(err))
        return False


def delete_notes(account_id, token, endpoint, notes):
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for note in notes:
            response = findingsAPI.delete_note(
                account_id=account_id,  
                note_id=note['id'],
                **note
            )
            if response.get_status_code() == 200:
                logger.info("deleted note: %s" % note['id'])
            else:
                logger.error("unable to delete note: %s" % note['id'])
    except:
        logger.exception("an unexpected error was encountered while deleting the note: "+str(err))
    time.sleep(1)


def get_all_kubehunteroccurrences(account_id, token, endpoint):
    occurrences = []
    providers = [
        "kubeHunterIBMCloud", 
        "kubeHunterIBMCloudInformationDisclosure", 
        "kubeHunterRedhatRemoteCodeExecutor",
        "kubeHunterIBMCloudIdentityAndAccess",
        "kubeHunterIBMCloudDenialofService"
    ]
    occurrences.extend(get_occurrences(account_id, token, endpoint, providers))
    return occurrences


def get_occurrences(account_id, token, endpoint, providers):
    occurrences = []
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for provider_id in providers:
            response = findingsAPI.list_occurrences(
                account_id=account_id, 
                provider_id=provider_id
            )
            if response.get_status_code() == 200:
                logger.info("got occurrences by provider: %s" % provider_id)
                for occurrence in response.get_result()['occurrences']:
                    occurrences.append(occurrence)
            else:
                logger.error("unable to get occurrences by provider: %s" % provider_id)
        return occurrences
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while getting the occurrences: "+str(err))
        return False


def delete_occurrences(account_id, token, endpoint, occurrences):
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for occurrence in occurrences:
            response = findingsAPI.delete_occurrence(
                account_id=account_id, 
                occurrence_id=occurrence['id'],
                **occurrence
            )
            if response.get_status_code() == 200:
                logger.info("deleted occurrence: %s" % occurrence['id'])
            else:
                logger.error("unable to delete occurrence: %s" % occurrence['id'])
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while deleting the occurrence: "+str(err))
    time.sleep(1)


def id_generator(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))


# This method needs to be defined for any partner application that needs to adapt
def createOccurences(account_id, token, endpoint, occurrencesJson):
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for occurrence in occurrencesJson:
            response = findingsAPI.create_occurrence(
                account_id=account_id,
                **occurrence
            )
            if response.get_status_code() == 200:
                logger.info("created occurrence: %s" % occurrence['id'])
            else:
                logger.error("unable to create occurrence: %s" % occurrence['id'])
    except requests.exceptions.HTTPError as err:
            logger.exception("an unexpected error was encountered while creating occurrence: "+str(err))
		    

def executePointInTimeVulnerabilityOccurenceAdapter(apikey, account_id, endpoint, vulnerabilitiesReportedByPartner):
    token = obtain_iam_token(apikey)
    try:
        create_note(account_id, token, endpoint)
    except:
        logger.exception("ignoring metadata duplicate errors")
    try:
        vulnerabilityOccurrences = get_all_kubehunteroccurrences(account_id, token, endpoint)
        delete_occurrences(account_id, token, endpoint, vulnerabilityOccurrences)
    except:
        logger.exception("ignoring metadata duplicate errors")
    createOccurences(account_id, token, endpoint, vulnerabilitiesReportedByPartner["insights"])
    occurrences = get_all_kubehunteroccurrences(account_id, token, endpoint)
    return occurrences


def postToSA(args):
    logging.info("Patch Management Monitoring started")
    apikey = args["apikey"]
    account_id = args["account"]
    endpoint = args["endpoint"]
    vulnerabilityOccurrences = executePointInTimeVulnerabilityOccurenceAdapter(apikey, account_id, endpoint, args["vulnerabilityInsights"])
    return {'insights': vulnerabilityOccurrences}

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

logger = logging.getLogger("cleanup")
logger.setLevel(logging.INFO)

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


def get_all_kubehunternotes(account_id, token, endpoint):
    notes = []
    providers = [
        "kubeHunterIBMCloud",
        "kubeHunterIBMCloudInformationDisclosure",
        "kubeHunterIBMCloudRemoteCodeExecutor",
        "kubeHunterIBMCloudIdentityAndAccess",
        "kubeHunterIBMCloudDenialofService"
    ]
    notes.extend(get_notes(account_id, token, endpoint, providers))
    return notes


def get_notes(account_id, token, endpoint, providers):
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


def delete_all_kubenotes(account_id, token, endpoint):
	notes = get_all_kubehunternotes(account_id, token, endpoint)
	delete_notes(account_id, token, endpoint, notes)
	
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
    occurrences = []
    providers = [
        "kubeHunterIBMCloud", 
        "kubeHunterIBMCloudInformationDisclosure", 
        "kubeHunterIBMCloudRemoteCodeExecutor",
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

def cleanup(apikey, account_id, endpoint):
    token = obtain_iam_token(apikey)
    try:
        delete_all_kubenotes(account_id, token, endpoint)
        vulnerabilityOccurrences = get_all_kubehunteroccurrences(account_id, token, endpoint)
        delete_occurrences(account_id, token, endpoint, vulnerabilityOccurrences)
    except:
        logger.exception("An unexpected error was encountered while cleanup")

def main(args):
    account_id = args[1]
    apikey = args[2]
    endpoint =  args[3]
    cleanup(apikey, account_id, endpoint)


if __name__ == "__main__":
    main(sys.argv)

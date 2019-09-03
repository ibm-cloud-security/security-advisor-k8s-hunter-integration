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
logger = logging.getLogger("cleanup")


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



def get_all_kubehunternotes(account_id, token, endpoint):
    notes = []
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloud/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudInformationDisclosure/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudRemoteCodeExecutor/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudIdentityAndAccess/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudDenialofService/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    return notes


def get_notes(account_id, token, endpoint, url):
    notes = []
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
            notes.append(note)
        return notes
    else:
        return []


def delete_all_kubenotes(account_id, token, endpoint):
	notes = get_all_kubehunternotes(account_id, token, endpoint)
	delete_notes(account_id, token, endpoint, notes)
	
def delete_notes(account_id, token, endpoint, notes):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    for note in notes:
        if note['kind'] == "CARD":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloud/notes/"+ note['id']
        elif note['provider_id'] == "kubeHunterIBMCloudInformationDisclosure":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudInformationDisclosure/notes/"+ note['id']
        elif note['provider_id'] == "kubeHunterIBMCloudRemoteCodeExecutor":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudRemoteCodeExecutor/notes/"+ note['id']

        elif note['provider_id'] == "kubeHunterIBMCloudIdentityAndAccess":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudIdentityAndAccess/notes/"+ note['id']
        elif note['provider_id'] == "kubeHunterIBMCloudDenialofService":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudDenialofService/notes/"+ note['id']
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
        except:
            logger.exception("An unexpected error was encountered while deleting the note" + str(err))
        time.sleep(1)


def get_all_kubehunteroccurrences(account_id, token, endpoint):
    occurrences = []
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloud/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudInformationDisclosure/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudRemoteCodeExecutor/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudIdentityAndAccess/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudDenialofService/occurrences"
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
        if occurrence['provider_id'] == "kubeHunterIBMCloudInformationDisclosure":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudInformationDisclosure/occurrences/" + occurrence['id']
        elif occurrence['provider_id'] == "kubeHunterIBMCloudRemoteCodeExecutor":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudRemoteCodeExecutor/occurrences/" + occurrence['id']

        elif occurrence['provider_id'] == "kubeHunterIBMCloudIdentityAndAccess":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudIdentityAndAccess/occurrences/" + occurrence['id']
        elif occurrence['provider_id'] == "kubeHunterIBMCloudDenialofService":
            url = endpoint + "/" + account_id + "/providers/kubeHunterIBMCloudDenialofService/occurrences/" + occurrence['id']

        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.exception("An unexpected error was encountered while deleting the occurrence" + str(err))
        time.sleep(1)

def cleanup(apikey, account_id, endpoint):
    token = obtain_iam_token(apikey)
    try:
    	delete_all_kubenotes(account_id, token, endpoint)
        vulnerabilityOccurrences = get_all_kubehunteroccurrences(account_id, token, endpoint)
        delete_occurrences(account_id, token, endpoint, vulnerabilityOccurrences)
    except:
        logger.exception("An unexpected error was encountered while cleanup");

def main(args):
    account_id = args[1]
    apikey = args[2]
    endpoint =  args[3]
    cleanup(apikey, account_id, endpoint)


if __name__ == "__main__":
    main(sys.argv)

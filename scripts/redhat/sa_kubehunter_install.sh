#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2017 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

set -x

if [ "$#" -ne 5 ] && [ "$#" -ne 4 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <account id> <api key> <cluster name> <oc login api-key>"
    echo -e '\t \t' "-----------OR-----------"
    echo "Usage : ./$(basename "$0") <account id> <api key> <cluster name> <oc login api-key> <source_server>"
    exit 1
fi

account_id=$1
api_key=$2
cluster_name=$3
oc_login_apikey=$4
source_server=$5

if [ "$source_server" == "redhat" ]; then
    ibmcloud login -a test.cloud.ibm.com -r us-south --apikey $oc_login_apikey
    ibmcloud oc cluster-get --cluster $cluster_name

    chmod +x generate_kubehunter_secrets.sh
    ./generate_kubehunter_secrets.sh $account_id $api_key $cluster_name $oc_login_apikey default
    masterURL=$(ibmcloud oc cluster-get --cluster $cluster_name|grep "Master URL" |awk '{ print $3 }')
    echo "masterURL is $masterURL"
    oc login -u apikey -p $oc_login_apikey --server=$masterURL

else
    chmod +x generate_kubehunter_secrets.sh
    ./generate_kubehunter_secrets.sh $account_id $api_key $cluster_name $oc_login_apikey default
fi

cd ../../config/helm/kubehunter-adapter-redhat
helm install --name kubehunter-sa-adapter-redhat .

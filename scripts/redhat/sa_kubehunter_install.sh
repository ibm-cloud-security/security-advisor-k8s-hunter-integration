#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2020 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

# To check if helm is installed on system or not.
command -v helm >/dev/null 2>&1 || { echo >&2 "helm is required. Aborting."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo >&2 "kubectl is required. Aborting."; exit 1; }

# To check what version of helm is installed on system.
helmVer=`helm version --template {{.Version}}`
helmVerMajor="$(cut -d'.' -f 1 <<< ${helmVer:1})"

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

    chmod +x ./scripts/redhat/generate_kubehunter_secrets.sh
    ./scripts/redhat/generate_kubehunter_secrets.sh $account_id $api_key $cluster_name $oc_login_apikey default
    masterURL=$(ibmcloud oc cluster-get --cluster $cluster_name|grep "Master URL" |awk '{ print $3 }')
    echo "masterURL is $masterURL"
    oc login -u apikey -p $oc_login_apikey --server=$masterURL

else
    chmod +x ./scripts/redhat/generate_kubehunter_secrets.sh
    ./scripts/redhat/generate_kubehunter_secrets.sh $account_id $api_key $cluster_name $oc_login_apikey default
fi

# Install helm chart in kubernetes
cd config/helm/kubehunter-adapter-redhat
if [ $helmVerMajor -gt 2 ]; then
    helm install kubehunter-sa-adapter-redhat .
else
    helm install --name kubehunter-sa-adapter-redhat .
fi

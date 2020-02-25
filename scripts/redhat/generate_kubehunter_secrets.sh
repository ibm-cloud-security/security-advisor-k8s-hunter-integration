#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2020 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

if [ "$#" -ne 5 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <account_id> <api_key> <cluster_name> <kube config name> <namespace>"
    exit 1
fi

kubectl create secret generic kubehunter-redhat-credentials --from-literal=account_id=$1 --from-literal=api_key=$2 --from-literal=cluster_name=$3 --from-literal=oc_login_apikey=$4 -n$5

#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2017 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

if [ "$#" -ne 5 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <account_id> <api_key> <cluster_name> <kube config name> <namespace>"
    exit 1
fi

kubectl create secret generic kubehunter-public-credentials --from-literal=account_id=$1 --from-literal=api_key=$2 --from-literal=cluster_name=$3 --from-literal=kube_config_name=$4 -n$5

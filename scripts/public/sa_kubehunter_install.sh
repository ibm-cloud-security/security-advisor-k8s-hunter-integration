#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2017 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

set +x
if [ "$#" -ne 4 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <account id> <api key> <cluster name> <full path to directory of kube configs>"
    exit 1
fi

account_id=$1
api_key=$2
cluster_name=$3
kube_config_dir=$4
kubeconfig_name=$(ls $kube_config_dir |grep yml)

chmod +x generate_kubeconfig_secrets.sh
chmod +x generate_kubehunter_secrets.sh

./generate_kubeconfig_secrets.sh $kube_config_dir kubehunter-public-secret default
./generate_kubehunter_secrets.sh $account_id $api_key $cluster_name $kubeconfig_name default

cd ../../config/helm/kubehunter-adapter-public
helm install --name kubehunter-sa-adapter-public .

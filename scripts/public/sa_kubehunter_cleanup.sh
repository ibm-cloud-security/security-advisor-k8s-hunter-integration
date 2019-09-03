
set +x
if [ "$#" -ne 5 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <account id> <api key> <full path to directory of kube configs> <cloud-env> <sa-endpoint>"
    exit 1
fi

account_id=$1
api_key=$2
kube_config_dir=$3
cloud_env=$4
sa_endpoint=$5
kubeconfig_name=$(ls $kube_config_dir |grep yml)

python ../../src/$cloud_env/kubeHunterCleanup.py $account_id $api_key $sa_endpoint

kubectl delete secret kubehunter-public-secret
kubectl delete secret kubehunter-public-credentials
helm del --purge kubehunter-sa-adapter-public
podname=$(kubectl get job |grep kubehunter-sa-adapter-public|awk '{ print $1 }')
kubectl delete job $podname

# Delete kube-hunter Job running on target cluster: 
export KUBECONFIG=$kube_config_dir/$kubeconfig_name
kubectl delete job kube-hunter-public

set +x
if [ "$#" -ne 5 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <account_id> <api_key> <cluster_name> <kube config name> <namespace>"
    exit 1
fi

kubectl create secret generic kubehunter-redhat-credentials --from-literal=account_id=$1 --from-literal=api_key=$2 --from-literal=cluster_name=$3 --from-literal=oc_login_apikey=$4 -n$5

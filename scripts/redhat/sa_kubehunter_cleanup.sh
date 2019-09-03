
set +x
if [ "$#" -ne 6 ] && [ "$#" -ne 5 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <account id> <api key> <cluster name> <oc login api-key> <sa-endpoint>"
    echo -e '\t \t' "-----------OR-----------"
    echo "Usage : ./$(basename "$0") <account id> <api key> <cluster name> <oc login api-key> <sa-endpoint> <source_server>"
    exit 1
fi

account_id=$1
api_key=$2
cluster_name=$3
oc_login_apikey=$4
sa_endpoint=$5
source_server=$6

python ../../src/redhat-openshift/kubeHunterCleanup.py $account_id $api_key $sa_endpoint

if [ "$source_server" == "redhat" ]; then
    ibmcloud login -a test.cloud.ibm.com -r us-south --apikey $oc_login_apikey
    ibmcloud oc cluster-get --cluster $cluster_name

    masterURL=$(ibmcloud oc cluster-get --cluster $cluster_name|grep "Master URL" |awk '{ print $3 }')
    oc login -u apikey -p $oc_login_apikey --server=$masterURL

    kubectl delete secret kubehunter-redhat-credentials
    helm del --purge kubehunter-sa-adapter-redhat
    podname=$(kubectl get job |grep kubehunter-sa-adapter-redhat|awk '{ print $1 }')
    kubectl delete job $podname
    kubectl delete job kube-hunter-redhat
    
else
    kubectl delete secret kubehunter-redhat-credentials
    helm del --purge kubehunter-sa-adapter-redhat
    podname=$(kubectl get job |grep kubehunter-sa-adapter-redhat|awk '{ print $1 }')
    kubectl delete job $podname

    ibmcloud login -a test.cloud.ibm.com -r us-south --apikey $oc_login_apikey
    ibmcloud oc cluster-get --cluster $cluster_name

    masterURL=$(ibmcloud oc cluster-get --cluster $cluster_name|grep "Master URL" |awk '{ print $3 }')
    oc login -u apikey -p $oc_login_apikey --server=$masterURL
    kubectl delete job kube-hunter-redhat
    
fi

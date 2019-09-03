
set -x
accountid=$1
apikey=$2
clustername=$3
oc_login_apikey=$4
echo "CLOUD_ENV is $CLOUD_ENV"

git clone https://github.com/aquasecurity/kube-hunter.git
cd kube-hunter/
rm job.yaml
cd ..
cd kubehunter-sa-adapter/$CLOUD_ENV
cp job.yaml ../../kube-hunter/
cd ../../kube-hunter


ibmcloud login -a $LOGIN_ENDPOINT -r $REGION --apikey $oc_login_apikey
ibmcloud oc cluster-get --cluster $clustername

masterURL=$(ibmcloud oc cluster-get --cluster $clustername|grep "Master URL" |awk '{ print $3 }')
echo "masterURL is $masterURL"
oc login -u apikey -p $oc_login_apikey --server=$masterURL
oc apply -f job.yaml

sleep 20
echo "starting to prepare kubehunter analysis report"
kubectl logs -f "$(kubectl get pods |grep kube-hunter-redhat | awk '{ print $1 }')" | sed -ne '/^Vulnerabilities$/{:a' -e 'n;p;ba' -e '}' >> ../vul.txt
echo "analysis report prepared"
echo "Uploading report to SA"

cd ../kubehunter-sa-adapter/$CLOUD_ENV
python kubeHunterAdaptor.py $accountid $apikey $clustername $SA_ENDPOINT
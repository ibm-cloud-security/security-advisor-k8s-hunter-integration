#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2020 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

accountid=$1
apikey=$2
clustername=$3
kubeconfigname=$4

git clone https://github.com/aquasecurity/kube-hunter.git
cd kube-hunter/
rm job.yaml
cd ..
cd kubehunter-sa-adapter/$CLOUD_ENV
cp job.yaml ../../kube-hunter/
cd ../../kube-hunter

export KUBECONFIG=/etc/kubeconfig/$kubeconfigname
kubectl apply -f job.yaml
sleep 20
echo "starting to prepare kubehunter analysis report"
kubectl logs -f "$(kubectl get pods |grep kube-hunter-public | awk '{ print $1 }')" | sed -ne '/^Vulnerabilities$/{:a' -e 'n;p;ba' -e '}' >> ../vul.txt
echo "analysis report prepared"
echo "uploading report to SA..."

cd ../kubehunter-sa-adapter/$CLOUD_ENV
python3 kubeHunterAdaptor.py $accountid $apikey $clustername $SA_ENDPOINT
echo "uploaded kube-hunter report to SA"
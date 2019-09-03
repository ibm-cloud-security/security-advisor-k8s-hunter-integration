# security-advisor-k8s-hunter-integration

## Defination of terms:
![Defination of Terms](https://github.ibm.com/security-services/security-advisor-project-management/blob/master/kube-definations.png) 

# Prerequisites 
- Install python (Only if you want to do the cleanup of cards, notes and occurances)
- Install [Kubernetes Helm (package manager)](https://docs.helm.sh/using_helm/#from-script) v2.9.0 or higher

## public-k8s cloud 
### Install steps for public-k8s cloud:
- Clone this repo
- `cd security-advisor-k8s-hunter-integration/scripts/public`
- Inorder to point to security advisor london endpoint do following changes:
  uncomment line#16 and comment line#15 in /config/helm/kubehunter-adapter-public/values.yaml 
- `./sa_kubehunter_install.sh <account-id> <apikey> <target-clustername> "<complete path of kubeconfig of target cluster>"`
- for example: 
```
./sa_kubehunter_install.sh account_id apikey mycluster "/Users/sunilsingh/.bluemix/plugins/container-ser-ice/clusters/mycluster"

<account-id>: Account id on which the card needs to be generated
<apikey>: api-key of the above account-id.
<target-clustername>: The target public k8s cluster on which kube-hunter needs to be configured 
<complete path of kubeconfig of target cluster>: Run `ibmcloud cs cluster-config <clustername>` to get kube-config
```

### Cleanup setup for public-k8s cloud:
- Clone this repo
- `cd security-advisor-k8s-hunter-integration/scripts/public`
- Run below automated script to cleanup all in once.
`./sa_kubehunter_cleanup.sh <account id> <api key> "full path to directory of kube configs>" <cloud-env>`
- For example: 
 ```
 ./sa_kubehunter_cleanup.sh  accountid apikey myrhelcluster oc-login-apikey 

 ./sa_kubehunter_cleanup.sh  accountid apikey "/Users/sunilsingh/.bluemix/plugins/container-service/clusters/mycluster" "https://us-south.secadvisor.cloud.ibm.com/findings/v1" ibmcloud

<account id>: Account id on which the card needs to be generated
<apikey>: api-key of the above account-id.
<target-clustername>: The target public k8s cluster on which kube-hunter needs to be configured 
<complete path of kubeconfig of target cluster>: Run `ibmcloud cs cluster-config <clustername>` to get kube-config
<cloud-env>: Value is `ibmcloud`
```

## Redhat Openshift
### Install steps for source is public-k8s cloud and target is redhat-openshift cloud:
- Clone this repo
- `cd security-advisor-k8s-hunter-integration/scripts/redhat`
- Inorder to point to security advisor london endpoint do following changes:
  uncomment line#6 and comment line#15 in /config/helm/kubehunter-adapter/values.yaml 
- `./sa_kubehunter_install.sh <account-id> <api key> <target-clustername> <oc login api-key>`
- for example: 
```
./sa_kubehunter_install.sh account_id apikey mycluster-rhel "oc-login-api-key"

<account-id>: Account id on which the card needs to be generated
<apikey>: api-key of the above account-id.
<target-clustername>: The target rhel-openshift cluster on which kube-hunter needs to be configured 
<oc-login-api-key>: The api-key to login to cluster
```

### Cleanup of setup for source is public-k8s cloud and target is redhat-openshift cloud:
- Clone this repo
- `cd security-advisor-k8s-hunter-integration/scripts/redhat`
- Run below automated script to cleanup all in once.
- `./sa_kubehunter_cleanup.sh <account id> <apikey> <target-clustername> <oc-login-api-key> <sa-endpoint>`
-  For example: 
```
./sa_hunter_cleanup.sh  accountid apikey myrhelcluster oc-login-apikey "https://us-south.secadvisor.cloud.ibm.com/findings/v1"

<account id>: Account id on which the card needs to be generated
<apikey>: api-key of the above account-id.
<target-clustername>: The target rhel-openshift cluster on which kube-hunter needs to be configured 
<oc-login-api-key>: The api-key to login to cluster
<sa-endpoint>: The value is `https://us-south.secadvisor.cloud.ibm.com/findings/v1`
<source-server>: The value is `redhat`
```

### Install steps for source and target as redhat-openshift cloud:
- Clone this repo
- `cd security-advisor-k8s-hunter-integration/scripts/redhat`
- Inorder to point to security advisor london endpoint do following changes:
  uncomment line#16 and comment line#15 in /config/helm/kubehunter-adapter/values.yaml 
- `./sa_kubehunter_install.sh <account id> <api key> <cluster name> <oc login api-key> redhat`
- for example: 
```
./sa_kubehunter_install.sh account_id apikey mycluster-rhel "oc login api-key" redhat

<account id>: Account id on which the card needs to be generated
<apikey>: api-key of the above account-id.
<target-clustername>: The target rhel-openshift k8s cluster on which kube-hunter needs to be configured 
<oc-login-api-key>: The api-key to login to cluster
```

### Cleanup of setup for source and target as redhat-openshift:

- Clone this repo
- `cd security-advisor-k8s-hunter-integration/scripts/redhat`
- Run below automated script to cleanup all in once.
- `./sa_kubehunter_cleanup.sh <account id> <api key> <target-clustername> <oc-login-api-key> <sa-endpoint> <source-server>`
-  For example: 
```
./sa_kubehunter_cleanup.sh  accountid apikey mycluster-rhel oc-login-apikey "https://us-south.secadvisor.cloud.ibm.com/findings/v1 redhat"

<account id>: Account id on which the card needs to be generated
<apikey>: api-key of the above account-id.
<target-clustername>: The target rhel-openshift cluster on which kube-hunter needs to be configured 
<oc-login-api-key>: The api-key to login to cluster
<sa-endpoint>: The value is `https://us-south.secadvisor.cloud.ibm.com/findings/v1`
<source-server>: The value is `redhat`
```

## Configure cronjob:
- The cronjobs are scheduled to run every 15 mins, which is configurable. Change the schedule to run the cronjobs at: 
```
https://github.ibm.com/sec-advisor-code-samples/security-advisor-k8s-hunter-integration/blob/master/config/helm/kubehunter-adapter-public/templates/kube-cronjob.yaml#L8
```

## Troubleshooting

1. If you get an error something like `Error: incompatible versions client and server`, run `helm init --upgrade`
2. If you get an error like : `namespaces security-advisor-insights is forbidden: User system:serviceaccount:kube-system:default cannot get resource namespaces in API group in thenamespace security-advisor-insights`, fix the helm using [helm setup](https://cloud.ibm.com/docs/containers?topic=containers-integrations#helm) or follow below steps:
   ```kubectl delete deployment tiller-deploy -n kube-system
   kubectl apply -f https://raw.githubusercontent.com/IBM-Cloud/kube-samples/master/rbac/serviceaccount-tiller.yaml
   helm init --service-account tiller
   kubectl get pods -n kube-system -l app=helm
   helm list
   ```

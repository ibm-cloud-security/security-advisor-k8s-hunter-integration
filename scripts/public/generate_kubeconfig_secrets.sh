#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2020 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

if [ "$#" -ne 3 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <full path to directory of kube configs> <secret name> <namespace>"
    exit 1
fi

for entry in "$1"/*
do
  param+=" --from-file=$(basename "$entry")=$entry"
done

kubectl create secret generic $2 $param -n$3

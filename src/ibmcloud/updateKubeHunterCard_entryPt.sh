#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2017 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

echo "CLOUD_ENV is $CLOUD_ENV"
while true; do
  /kubebench-sa-adapter/$CLOUD_ENV/update_kubebenchcard.sh $1 $2 $3 $4 &
  sleep 3600
done
FROM ubuntu:16.04

RUN apt-get update && \
      apt-get -y install sudo
RUN apt-get install curl -y
RUN apt-get update
RUN apt-get install python3-pip -y
RUN pip3 install requests ibm-cloud-security-advisor-findingsapi-sdk==2.0.5

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
RUN chmod +x ./kubectl
RUN sudo mv ./kubectl /usr/local/bin/kubectl

RUN curl -sL https://ibm.biz/idt-installer | bash
RUN curl -LO https://github.com/openshift/origin/releases/download/v3.11.0/openshift-origin-client-tools-v3.11.0-0cbc58b-linux-64bit.tar.gz
RUN tar -xf openshift-origin-client-tools-v3.11.0-0cbc58b-linux-64bit.tar.gz
RUN mv /openshift-origin-client-tools-v3.11.0-0cbc58b-linux-64bit/oc /usr/local/bin/oc

RUN mkdir -p /etc/kubeconfig

ADD /config /kubehunter-sa-adapter/config
ADD /src /kubehunter-sa-adapter
ADD /scripts /kubehunter-sa-adapter
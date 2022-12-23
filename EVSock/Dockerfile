# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM enclave_sdk_base:latest
#FROM python:3.7.9-alpine3.12
COPY EVSockListner.py /app/
COPY extract_attestation.py /app/
COPY SymmetricEncryption.py /app/
COPY RSAEncryption.py /app/
COPY server.py /app/

COPY requirements-docker.txt .

####WORKDIR /tmp
#we want to make sure that each of our dependencies are going to be installed in our container
#RUN python3 -m pip install -r requirements-docker.txt --user
#RUN python3 -m pip install sklearn --user
RUN python3 -m pip install cbor2 --user
RUN python3 -m pip install pandas --user
RUN python3 -m pip install numpy --user
RUN python3 -m pip install chinesecalendar==1.7.2
RUN python3 -m pip install pycryptodome==3.15.0 --user



CMD ["python3", "/app/server.py", "5005"]

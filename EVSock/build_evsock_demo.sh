sudo docker build -f Dockerfile -t evsockdemo .
echo "begin to generate eif"
nitro-cli build-enclave --docker-uri evsockdemo:latest --output-file evsockdemo.eif
echo "begin to run enclave"
nitro-cli terminate-enclave --all
nitro-cli run-enclave --cpu-count 2 --memory 4096 --enclave-cid 32 --eif-path evsockdemo.eif --debug-mode

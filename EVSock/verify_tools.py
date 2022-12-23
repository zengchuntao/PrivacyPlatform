import extract_attestation
import cbor2 as cbor
import base64
import cose 
import traceback
import OpenSSL
from cryptography.x509 import load_pem_x509_certificate
from cose import EC2, CoseAlgorithms, CoseEllipticCurves
from OpenSSL.crypto import X509Store, X509StoreContext,verify
from cryptography.hazmat.backends import default_backend
from Crypto.Util.number import long_to_bytes
from OpenSSL import crypto

def verify_signature(attdata,cert):
    cbor_all = cbor.loads(attdata)
    attdoc = cbor.loads(cbor_all[2])
    signature = cbor_all[3]
    certificate = attdoc["certificate"]
    phdr = cbor.loads(cbor_all[0])
    x509_cer = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, certificate)
    
    # Get the key parameters from the cert public key
    cert_public_numbers = x509_cer.get_pubkey().to_cryptography_key().public_numbers()
    x = long_to_bytes(cert_public_numbers.x)
    y = long_to_bytes(cert_public_numbers.y)
    
    # Create the EC2 key from public key parameters
    key = EC2(
        alg = CoseAlgorithms.ES384,
        x   = x,
        y   = y,
        crv = CoseEllipticCurves.P_384
    )
    try:
        sig_struct = ["Signature1", cbor_all[0], b'', cbor_all[2]]
        sig_struct2 = cbor.dumps(sig_struct)
        #ret = OpenSSL.crypto.verify(x509_cer, signature, sig_struct2, "SHA384")
        msg = cose.Sign1Message(phdr=phdr, uhdr=cbor_all[1], payload=cbor_all[2])
        msg.signature = signature
        ret = msg.verify_signature(key)

        if ret:
            print("signature verify successfully")
            return True
        else:
            print("signature Failed")
            return False
    except:
        traceback.print_exc()
        return False


def verify_cert_chain(attdoc,untrust_cert,root_cert_path):
    cert_file = open(root_cert_path, 'r')
    cert_data = cert_file.read()
    root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    
    cabundle = attdoc["cabundle"]
    chain_len = len(attdoc["cabundle"])
    
    try:
        store = crypto.X509Store()
        store.add_cert(root_cert) # add the root cert
        # Assuming the certificates are in PEM format in a trusted_certs list
        for _cert in cabundle:
            cert_data = "-----BEGIN CERTIFICATE-----\n"
            cert_data+= _cert +"\n"
            cert_data+="-----END CERTIFICATE-----"
            client_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            store.add_cert(client_certificate)
            
        # Create a certificate context using the store and the downloaded certificate
        store_ctx = crypto.X509StoreContext(store, untrust_cert)
        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()
        return True
    except Exception as e:
        print(e)
        return False

        
def verify_attestation_doc(bytes_data,root_cert_path,nouce,user_data):
    sigalg, attdoc, docsig = extract_attestation.get_all_items(bytes_data)
    
    """
        step1: verify nouce and user_data
        step2: verify signature
        step3: verify certificate chain
    """

    nouce_to_verify = base64.b64decode(attdoc["nonce"]).decode()
    user_data_to_verify = base64.b64decode(attdoc["user_data"]).decode()
    print("nonce to veiry:  "+nouce_to_verify)
    print("user_data to veiry:  "+user_data_to_verify)
    if nouce != nouce_to_verify  or  user_data_to_verify!=user_data:
        print("nouce or user data inccorect!")
        return False
    # verifying
    
    # step2 parse the cert and verify sig
    certificate = "-----BEGIN CERTIFICATE-----\n"
    certificate+=attdoc['certificate']+"\n"
    certificate+="-----END CERTIFICATE-----"
    untrust_cert = load_pem_x509_certificate(certificate.encode(), default_backend())
    if not verify_signature(bytes_data,untrust_cert) or \
        not verify_cert_chain(attdoc,untrust_cert,root_cert_path):
        return False
    
    print(attdoc)
    return True
    
if __name__ == '__main__':
    doc = ""
    verify_attestation_doc(res,"root.pem","hi","nonce")
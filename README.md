# MTLS Cipher Issue Example
Example of re-creating issue where ECDSA related Ciphers don't work with OpenSSL as an SSL Provider.

## Steps to Reproduce
* Start the Application
* Execute `openssl s_client -connect localhost:8080 -msg -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -tls1_2`
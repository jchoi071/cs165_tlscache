all: root.pem chain.pem server.key client.key proxy.key

clean:
	/bin/rm -rf root intermediate root.pem chain.pem *.key *.crt *.der

chain.pem: intermediate/certs/intermediate.cert.pem root/certs/ca.cert.pem
	cat intermediate/certs/intermediate.cert.pem root/certs/ca.cert.pem > chain.pem

root.pem: root/certs/ca.cert.pem
	cp root/certs/ca.cert.pem root.pem

root/certs/ca.cert.pem:
	mkdir -p root/private
	mkdir -p root/certs
	mkdir -p root/newcerts
	cp openssl-root.cnf root/openssl.cnf
	(cd root && openssl genrsa -out private/ca.key.pem 4096)
	touch root/index.txt
	echo 1000 > root/serial
	(cd root && openssl req -batch -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -subj "/C=CA/ST=Edmonton/O=Bob Beck/OU=LibTLS Tutorial/CN=Root CA Cert" -out certs/ca.cert.pem)

intermediate/certs/intermediate.cert.pem: root/certs/ca.cert.pem
	mkdir -p intermediate/certs
	mkdir -p intermediate/crl
	mkdir -p intermediate/csr
	mkdir -p intermediate/newcerts
	mkdir -p intermediate/private
	cp openssl-intermediate.cnf intermediate/openssl.cnf
	touch intermediate/index.txt
	echo 1000 > intermediate/serial
	echo 1000 > intermediate/crlnumber
	(cd intermediate && openssl genrsa -out private/intermediate.key.pem 4096)
	(cd intermediate && openssl req -batch -config openssl.cnf -key private/intermediate.key.pem -new -sha256 -subj "/C=CA/ST=Edmonton/O=Bob Beck/OU=LibTLS Tutorial/CN=Intermediate CA Cert" -out csr/intermediate.csr.pem)
	openssl ca -batch -config root/openssl.cnf -extensions v3_intermediate_ca -days 3600 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem

server.key: intermediate/certs/intermediate.cert.pem chain.pem
	(cd intermediate && openssl genrsa -out private/server.key 2048)
	(cd intermediate && openssl req -batch -config openssl.cnf -new -key private/server.key -subj "/C=CA/ST=Edmonton/O=Bob Beck/OU=LibTLS Tutorial Server Certs/CN=localhost" -out csr/server.pem)
	openssl ca -batch -config intermediate/openssl.cnf -extensions server_cert -days 375 -notext -md sha256 -in intermediate/csr/server.pem -out intermediate/certs/server.crt
	cp intermediate/private/server.key server.key
	cp intermediate/certs/server.crt server.crt
	cat chain.pem >> server.crt

client.key: intermediate/certs/intermediate.cert.pem chain.pem
	(cd intermediate && openssl genrsa -out private/client.key 2048)
	(cd intermediate && openssl req -batch -config openssl.cnf -new -key private/client.key -subj "/emailAddress=beck@openbsd.org/C=CA/ST=Edmonton/O=Bob Beck/OU=LibTLS Tutorial Client Certs/CN=localhost" -out csr/client.pem)
	openssl ca -batch -config intermediate/openssl.cnf -extensions usr_cert -days 375 -notext -md sha256 -in intermediate/csr/client.pem -out intermediate/certs/client.crt
	cp intermediate/private/client.key client.key
	cp intermediate/certs/client.crt client.crt
	cat chain.pem >> client.crt
	
proxy.key: intermediate/certs/intermediate.cert.pem chain.pem
	(cd intermediate && openssl genrsa -out private/proxy.key 2048)
	(cd intermediate && openssl req -batch -config openssl.cnf -new -key private/proxy.key -subj "/emailAddress=beck@openbsd.org/C=CA/ST=Edmonton/O=Bob Beck/OU=LibTLS Tutorial Proxy Certs/CN=localhost" -out csr/proxy.pem)
	openssl ca -batch -config intermediate/openssl.cnf -extensions server_cert -days 375 -notext -md sha256 -in intermediate/csr/proxy.pem -out intermediate/certs/proxy.crt
	cp intermediate/private/proxy.key proxy.key
	cp intermediate/certs/proxy.crt proxy.crt
	cat chain.pem >> proxy.crt
	
	

# Deletes all the certs and re-creates them.
# Use this script if you want to mess around with generating different certs.

# delete everything and start over.
rm ca.crt ca.key ca.srl
rm ca-unknown.crt ca-unknown.key ca-unknown.srl
rm server.crt server.csr server.key server.pfx
rm client.crt client.csr client.key client.pfx
rm unknown.crt unknown.csr unknown.key unknown.pfx

# create certificate authority key and cert
openssl genrsa -out ca.key 4096
openssl req -new  -key ca.key -out ca.crt -config ca.cnf -x509 -days 99999

# create unknown certificate authority key and cert
openssl genrsa -out ca-unknown.key 4096
openssl req -new  -key ca-unknown.key -out ca-unknown.crt -config ca.cnf -x509 -days 99999

# create server key and cert signed with certificate authority
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
 -out server.crt -days 99999 -extfile server.cnf
openssl pkcs12 -export -in server.crt -inkey server.key -certfile ca.crt \
-out server.pfx -name fred -password pass:''

# create client key and cert signed with certificate authority
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -config client.cnf
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
 -out client.crt -days 99999 -extfile client.cnf
openssl pkcs12 -export -in client.crt -inkey client.key -certfile ca.crt \
-out client.pfx -name fred -password pass:''

# create unknown key and cert signed with certificate authority
openssl genrsa -out unknown.key 4096
openssl req -new -key unknown.key -out unknown.csr -config client.cnf
openssl x509 -req -in unknown.csr -CA ca-unknown.crt -CAkey ca-unknown.key -CAcreateserial \
 -out unknown.crt -days 99999 -extfile client.cnf
openssl pkcs12 -export -in unknown.crt -inkey unknown.key -certfile ca-unknown.crt \
-out unknown.pfx -name fred -password pass:''


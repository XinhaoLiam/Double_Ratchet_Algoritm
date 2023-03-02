# Double Ratchet Encryption

This repository is written to have an easy simulation of 2 encryption method: e2ee and double ratchet encryption. There are 2 packages in the __src__ file. 

## I.Package e2ee

This package simulates the conversation based on the simplest E2EE concept. 

The files should be executed in the following order:

1. Run ServerAB.java
2. Run ClientAlice.java. Input "Alice" and then press Enter.
3. Run another ClientAlice.java. Input "Bob" and then press Enter.
4. Input "send" then press Enter in the ClientAlice.java with the name "Alice". This command will send the DH private key of Alice to Bob.
5. Input "send" then press Enter in the ClientAlice.java with the name "Bob". This command will send the DH private key of Bob to Alice.
6. Now you can start chat. Be sure to avoid the command "send".

## II. Package whatsApp

This package simulates the simplest conversation based on protocol used by WhatsApp (a Double Ratchet Algorithm). 

The difference lies in:
1. We are using basic DH algorithm instead of ECDH on Curve25519.
2. We reduce the size of MessageKey (80 bytes in the Whitepaper，but Hmac-SHA256 generates a value of 32bytes……）
3. We assume that all the authentication before and during the chat is satisfied.(The X3DH protocol is omitted and there is only encryption process in the code)

The files should be executed in the following order:
1. Run Server.java
2. Run Client.java. Input "Alice" and then press Enter.
3. Run another Client.java. Input "Bob" and then press Enter.
4. Now you can start chat.

** "Alice" and "Bob" can be replaced by any name you want.
** The whatsApp code is based on the whitepaper of WhatsApp, https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf 

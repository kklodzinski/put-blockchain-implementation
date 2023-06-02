# put-blockchain-implementation
put-blockchain-implementation

## Notes

Public centralised blockchain
Blockchain difficulty set to 3 or 6 leading zeros.

Private key: `openssl genrsa -out private.pem 2048`
Public key: `openssl rsa -in ./private.pem -outform PEM -pubout -out ./public.pem`

### Server

 - Blockchain
 - Clients adresses
 - No mining
 - If a transaction is added, it is broadcasted to all connected clients

### Client

 - Copy of the blockchain
 - Private wallet key
 - Ability to add transactions to the ledger
 - Receive broadcasted transaction and adds them to current ledger
 - Once block available make it available to mine

 `g++ -o client -I./block_chain ./src/client.cpp ./block_chain/block_chain.cpp -lcrypto -g`
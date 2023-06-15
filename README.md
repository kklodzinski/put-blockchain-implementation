# put-blockchain-implementation
put-blockchain-implementation

## Notes

Public centralised blockchain
Blockchain difficulty set to 1 leading zeros.

Private key: `openssl genrsa -out private.pem 2048`
Public key: `openssl rsa -in ./private.pem -outform PEM -pubout -out ./public.pem`

### Server

 - syncs clients
 - syncs miners
 - sends new transactions to miners
 - sends new blocks to clients
 - adds rewards for mined blocks

### Client

 - receives blocks
 - sends transactions

### Miner

 - receives transactions
 - mines blocks

 `g++ -o client -I./block_chain ./src/client.cpp ./block_chain/block_chain.cpp -lcrypto -g`
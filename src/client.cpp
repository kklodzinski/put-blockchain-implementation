// Client side C/C++ program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <unordered_map>
#include <fstream>

#include "../block_chain/block_chain.hpp"

#define PORT 8888
  
// Send public key to server
// Receive new blocks if needed
// Add transaction or mine block
int main(int argc, char const* argv[])
{

    // Read public key for sending to server
    FILE * public_key_file = fopen("./keys/public.pem", "r");
    if (public_key_file == nullptr) {
        perror("No such file");
    }
    char key_buffer[10000];
    fgets(key_buffer, sizeof(key_buffer), public_key_file);
    RSA * public_key = nullptr;
    public_key = PEM_read_RSAPublicKey(public_key_file, nullptr, nullptr, nullptr);
    fclose(public_key_file);

    put::blockchain::block_chain::block_chain blockchain("./keys/private.pem", 0);
    
    // Init client
    int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    char* hello = "Hello from client";
    char buffer[1024] = { 0 };
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
  
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }
  
    if ((status
         = connect(client_fd, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    //send(client_fd, hello, strlen(hello), 0);
    //printf("Hello message sent\n");
    // Read hello message
    valread = read(client_fd, buffer, 1024);
    printf("%s\n", buffer);

    // Send public key, last block hash
    std::cout << public_key << " " << sizeof(&public_key) << std::endl;
    send(client_fd, key_buffer, sizeof(key_buffer), 0);

    // Test sending new transaction
    put::blockchain::block_chain::transaction_t current_transaction;
    current_transaction = blockchain.add_transaction(1, 2, 20);
    send(client_fd, &current_transaction, sizeof(current_transaction), 0);

    // TODO Get last transaction id to init blockchain
    // Send last block you have
    unsigned char hash[SHA256_DIGEST_LENGTH + 1] = {0};
    unsigned char * hash_ptr;
    hash_ptr = blockchain.get_transaction_block_hash();
    if (hash_ptr != NULL)
        std::memcpy(&hash, blockchain.get_transaction_block_hash(), sizeof(hash));
    hash[SHA256_DIGEST_LENGTH] = '\x0a';
    std::cout << hash << std::endl;
    int len = send(client_fd, hash, SHA256_DIGEST_LENGTH + 1, 0);

    // Sync to last block
    // Send last transaction you have
    // Sync to last transaction
  
    // closing the connected socket
    close(client_fd);
    return 0;
}
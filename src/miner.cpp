// Client side C/C++ program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <ctime>

#include "../block_chain/block_chain.hpp"

#define PORT 8888
  
// Send public key to server
// Receive new blocks if needed
// Add transaction or mine block
int main(int argc, char const* argv[])
{

    // Read public key for sending to server
    BIO * bio = BIO_new(BIO_s_mem());
    FILE * public_key_file = fopen("./keys/public.pem", "r");
    RSA * public_key;// = nullptr;
    public_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
    std::cout << "is pubkey null? " << (public_key == NULL) << std::endl;
    fclose(public_key_file);

    std::ifstream public_key_stream("./keys/public.pem");
    std::stringstream key_buffer;
    key_buffer << public_key_stream.rdbuf();
    std::string key_string(key_buffer.str());
    public_key_stream.close();

    unsigned int user_id;
    
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

    // Read hello message
    valread = read(client_fd, buffer, 1024);
    printf("%s\n", buffer);

    // Identify as miner
    std::string identity = "minerr";
    send(client_fd, identity.c_str(), 7, 0);

    // Send public key
    std::cout << public_key << " " << sizeof(&public_key) << std::endl;
    send(client_fd, key_string.c_str(), key_string.size(), 0);

    // Receive last transaction id
    unsigned int receiver_id; // To be reused for transactions
    recv(client_fd, &receiver_id, sizeof(unsigned int), 0);
    std::cout << "Last transaction id: " << receiver_id << std::endl;

    put::blockchain::block_chain::block_chain blockchain(receiver_id);

    // Receive last block hash
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    recv(client_fd, hash, sizeof(hash), 0);

    // Receive transaction on ledger
    put::blockchain::block_chain::transaction_t current_transaction;
    unsigned int ledger_transaction_count;
    recv(client_fd, &receiver_id, sizeof(unsigned int), 0);
    for (int i = 0; i < receiver_id; i++) {
        recv(client_fd, &current_transaction, sizeof(put::blockchain::block_chain::transaction_t), 0);
        blockchain.add_transaction(current_transaction);
        ledger_transaction_count++;
    }

    unsigned int choice = 1;
    unsigned int amount;
    unsigned char transaction_or_block[sizeof(put::blockchain::block_chain::transaction_block_t)];
    put::blockchain::block_chain::transaction_block_t current_block;
    std::time_t timestamp;
    std::cout << "Starting mining process..." << std::endl;
    while (choice != 0) {

        // If enough transactions, generate block
        if (ledger_transaction_count >= 10) {
            std::cout << "Calculating new block" << std::endl;
            current_block = blockchain.create_transaction_block(hash);
            timestamp = std::time(nullptr);
            send(client_fd, &current_block, sizeof(put::blockchain::block_chain::transaction_block_t), 0);
            send(client_fd, &timestamp, sizeof(std::time_t), 0);
            ledger_transaction_count -= 10;
        }

        // Wait for next transction
        std::cout << "Waiting for transaction..." << std::endl;
        recv(client_fd, &current_transaction, sizeof(put::blockchain::block_chain::transaction_t), 0);
        blockchain.add_transaction(current_transaction);
        ledger_transaction_count++;
    }

    // closing the connected socket
    close(client_fd);
    return 0;
}
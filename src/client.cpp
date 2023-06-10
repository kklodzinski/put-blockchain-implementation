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
    // Read stored blockchain - TODO
    std::vector<put::blockchain::block_chain::transaction_block_t> blocks;
    
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

    // Identify as client
    std::string identity = "client";
    send(client_fd, identity.c_str(), 7, 0);

    // Send public key
    std::cout << public_key << " " << sizeof(&public_key) << std::endl;
    send(client_fd, key_string.c_str(), key_string.size(), 0);

    // Receive user id
    recv(client_fd, &user_id, sizeof(unsigned int), 0);
    std::cout << "User id: " << user_id << std::endl;

    // Receive last transaction id
    unsigned int receiver_id; // To be reused for transactions
    recv(client_fd, &receiver_id, sizeof(unsigned int), 0);
    std::cout << "Last transaction id: " << receiver_id << std::endl;

    put::blockchain::block_chain::block_chain blockchain("./keys/private.pem", receiver_id);

    // Send last block hash
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    blockchain.get_transaction_block_hash(hash);
    std::cout << "Current hash" << hash << std::endl;
    send(client_fd, hash, sizeof(hash), 0);

    // Receive blocks if any
    put::blockchain::block_chain::transaction_block_t current_block;
    recv(client_fd, &receiver_id, sizeof(unsigned int), 0);
    for (int i = 0; i < receiver_id; i++) {
        recv(client_fd, &current_block, sizeof(put::blockchain::block_chain::transaction_block_t), 0);
        blocks.push_back(current_block);
    }

    // Receive transaction on ledger
    put::blockchain::block_chain::transaction_t current_transaction;
    unsigned int ledger_transaction_count;
    recv(client_fd, &receiver_id, sizeof(unsigned int), 0);
    for (int i = 0; i < receiver_id; i++) {
        recv(client_fd, &current_transaction, sizeof(put::blockchain::block_chain::transaction_t), 0);
        blockchain.add_transaction(current_transaction);
        ledger_transaction_count++;
    }

    // Calculate how much coins do you have
    unsigned int coins = 0, tmp_coins = 0;
    for (int i = 0; i < blocks.size(); i++) {
        current_block = blocks.at(i);
        for (int j = 0; j < 10; j++) {
            if (current_block.transactions[j].sender_id == user_id) {
                coins -= current_block.transactions[j].transaction_amount;
            }
            if (current_block.transactions[j].recipient_id == user_id) {
                coins += current_block.transactions[j].transaction_amount;
            }
        }
    }
    std::cout << "You have " << coins << " PUT coins" << std::endl;
    tmp_coins = coins;

    unsigned int choice = 1;
    char new_block[4];
    unsigned int amount;
    unsigned char transaction_or_block[sizeof(put::blockchain::block_chain::transaction_block_t)];
    while (choice != 0) {

        std::cout << "What do you want to do:\n\t0: exit\n\t1: add transaction" << std::endl;
        std::cin >> choice;
        std::cout << choice << std::endl;

        switch (choice) {
            // Sending new transaction
            case 1:
                std::cout << "To who? ";
                std::cin >> receiver_id;
                std::cout << "Amount: ";
                std::cin >> amount;
                if (amount > tmp_coins) {
                    std::cout << "Not enough money" << std::endl;
                    break;
                }
                current_transaction = blockchain.create_transaction(1, 2, 20);
                send(client_fd, &current_transaction, sizeof(current_transaction), 0);
                tmp_coins -= amount;

                // Check if new block is available
            recv(client_fd, new_block, 4, 0);
            std::cout << new_block << " - " << std::strcmp(new_block, "yes") << std::endl;
            if (std::strcmp(new_block, "yes") == 0) {
                recv(client_fd, &current_block, sizeof(put::blockchain::block_chain::transaction_block_t), 0);
                blocks.push_back(current_block);

                // Sync coins
                for (int i = 0; i < 10; i++) {
                    current_transaction = current_block.transactions[i];
                    if (current_transaction.sender_id == user_id)
                        coins -= current_transaction.transaction_amount;
                    if (current_transaction.recipient_id == user_id)
                        coins += current_transaction.transaction_amount;
                }
                std::cout << "You have " << coins << "PUT coins" << std::endl;
                tmp_coins = coins;
            }

                break;
            case 0:
                std::cout << "Goodbye" << std::endl;
                break;
            default:
                std::cout << "No such option" << std::endl;
                break;
        } 
    }

    // closing the connected socket
    close(client_fd);
    return 0;
}
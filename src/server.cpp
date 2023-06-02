#include <cstddef>
#include <cstring>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdio.h> 
#include <string.h>   //strlen 
#include <stdlib.h> 
#include <errno.h> 
#include <string>
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <vector>
#include <unordered_map>

#include "../block_chain/block_chain.hpp"
     
#define TRUE   1 
#define FALSE  0 
#define PORT 8888 

int verify_transaction(put::blockchain::block_chain::transaction_t &transaction, RSA * public_key) {

    unsigned char data[sizeof(put::blockchain::block_chain::transaction_t)];
    memcpy(data, &transaction, sizeof(put::blockchain::block_chain::transaction_t));

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char signature[SHA256_DIGEST_LENGTH];

    EVP_MD_CTX * md_ctx;
    const EVP_MD * md;
    md = EVP_get_digestbyname("sha256");
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, data, sizeof(put::blockchain::block_chain::transaction_t));
    EVP_DigestFinal_ex(md_ctx, hash, NULL);
    EVP_MD_CTX_free(md_ctx);

    unsigned int sig_len;
    int ret = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, public_key);
    return ret;
}

// Recevie client connections
// Receive client transactions from clients with timestmps to order them
// Broadcast latest transactions
// Receive new blocks and broadcast the latest one to add to the chain
     
int main(int argc , char *argv[])  
{  

    // Init RSA key reading
    RSA * public_key = nullptr;
    BIO * bio = BIO_new(BIO_s_mem());

    // Init blockchain
    put::blockchain::block_chain::block_chain blockchain("./keys/private_server.pem", 0);
    blockchain.add_transaction(26, 19, 0);
    blockchain.add_transaction(3, 25, 5);
    blockchain.add_transaction(15, 18, 4);
    blockchain.add_transaction(12, 10, 1);
    blockchain.add_transaction(10, 3, 4);
    blockchain.add_transaction(14, 0, 3);
    blockchain.add_transaction(0, 18, 2);
    blockchain.add_transaction(18, 14, 5);
    blockchain.add_transaction(0, 15, 4);
    blockchain.add_transaction(1, 10, 1);
    char hash[SHA256_DIGEST_LENGTH] = {0};

    put::blockchain::block_chain::transaction_block_t block;
    block = blockchain.create_transaction_block(hash);
    std::unordered_map<char *, put::blockchain::block_chain::transaction_block_t> map; 
    map.emplace(block.previous_block_hash, block);

    put::blockchain::block_chain::transaction_t current_transaction;

    // Init Server
    int opt = TRUE;  
    int master_socket , addrlen , new_socket , client_socket[30] , 
          max_clients = 30 , activity, i , valread , sd;  
    int max_sd;  
    struct sockaddr_in address;  
         
    char buffer[1025] = { 0 };  //data buffer of 1K 
    char key_buffer[10000] = {0};
         
    //set of socket descriptors 
    fd_set readfds;  
         
    //a message 
    char *message = "ECHO Daemon v1.0 \r\n";  
     
    //initialise all client_socket[] to 0 so not checked 
    for (i = 0; i < max_clients; i++)  
    {  
        client_socket[i] = 0;  
    }  
         
    //create a master socket 
    if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)  
    {  
        perror("socket failed");  
        exit(EXIT_FAILURE);  
    }  
     
    //set master socket to allow multiple connections , 
    //this is just a good habit, it will work without this 
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, 
          sizeof(opt)) < 0 )  
    {  
        perror("setsockopt");  
        exit(EXIT_FAILURE);  
    }  
     
    //type of socket created 
    address.sin_family = AF_INET;  
    address.sin_addr.s_addr = INADDR_ANY;  
    address.sin_port = htons( PORT );  
         
    //bind the socket to localhost port 8888 
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)  
    {  
        perror("bind failed");  
        exit(EXIT_FAILURE);  
    }  
    printf("Listener on port %d \n", PORT);  
         
    //try to specify maximum of 3 pending connections for the master socket 
    if (listen(master_socket, 3) < 0)  
    {  
        perror("listen");  
        exit(EXIT_FAILURE);  
    }  
         
    //accept the incoming connection 
    addrlen = sizeof(address);  
    puts("Waiting for connections ...");  
         
    while(TRUE)  
    {  
        //clear the socket set 
        FD_ZERO(&readfds);  
     
        //add master socket to set 
        FD_SET(master_socket, &readfds);  
        max_sd = master_socket;  
             
        //add child sockets to set 
        for ( i = 0 ; i < max_clients ; i++)  
        {  
            //socket descriptor 
            sd = client_socket[i];  
                 
            //if valid socket descriptor then add to read list 
            if(sd > 0)  
                FD_SET( sd , &readfds);  
                 
            //highest file descriptor number, need it for the select function 
            if(sd > max_sd)  
                max_sd = sd;  
        }  
     
        //wait for an activity on one of the sockets , timeout is NULL , 
        //so wait indefinitely 
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);  
       
        if ((activity < 0) && (errno!=EINTR))  
        {  
            printf("select error");  
        }  
             
        //If something happened on the master socket , 
        //then its an incoming connection 
        // TODO - send blockchain if not synced
        if (FD_ISSET(master_socket, &readfds))  
        {  
            if ((new_socket = accept(master_socket, 
                    (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)  
            {  
                perror("accept");  
                exit(EXIT_FAILURE);  
            }  
             
            //inform user of socket number - used in send and receive commands 
            printf("New connection , socket fd is %d , ip is : %s , port : %d \n" ,
                  new_socket , inet_ntoa(address.sin_addr) , ntohs
                  (address.sin_port));  
           
            //send new connection greeting message 
            if( send(new_socket, message, strlen(message), 0) != strlen(message) )  
            {  
                perror("send");  
            }  
                 
            puts("Welcome message sent successfully");

            // Receive public key, add to list of users and send user id
            //valread = recv(sd, buffer, 1024, 0);


            // Receive last block hash
            valread = recv(new_socket, key_buffer, sizeof(key_buffer), 0);
            BIO_puts(bio, buffer);

            if (valread == -1)
            {
                fprintf(stderr, "recv: %s (%d)\n", strerror(errno), errno);
            }
            std::cout << "Buffer read" << std::endl;
            std::cout << key_buffer << "\n" << valread << " " << strlen(buffer) << std::endl;
            public_key = PEM_read_bio_RSAPublicKey(bio, &public_key, nullptr, nullptr);
            std::cout << public_key << std::endl;

            // Send remaining blocks if any


            //add new socket to array of sockets 
            for (i = 0; i < max_clients; i++)  
            {  
                //if position is empty 
                if( client_socket[i] == 0 )  
                {  
                    client_socket[i] = new_socket;  
                    printf("Adding to list of sockets as %d\n" , i);  
                         
                    break;  
                }  
            }  
        }  
             
        //else its some IO operation on some other socket
        // Check if transaction or block
        for (i = 0; i < max_clients; i++)  
        {  
            sd = client_socket[i];  
                 
            if (FD_ISSET( sd , &readfds))  
            {  
                //Check if it was for closing , and also read the 
                //incoming message 
                valread = read(sd, &current_transaction, sizeof(put::blockchain::block_chain::transaction_t));
                std::cout << buffer << std::endl;

                //if ((valread = read( sd , buffer, 1024)) == 0)  
                if (valread == 0)
                {  
                    //Somebody disconnected , get his details and print 
                    getpeername(sd , (struct sockaddr*)&address , \
                        (socklen_t*)&addrlen);  
                    printf("Host disconnected , ip %s , port %d \n" , 
                          inet_ntoa(address.sin_addr) , ntohs(address.sin_port));  
                         
                    //Close the socket and mark as 0 in list for reuse 
                    close( sd );  
                    client_socket[i] = 0;  
                }  
                     
                //Echo back the message that came in 
                else 
                {  
                    //set the string terminating NULL byte on the end 
                    //of the data read 
                    //buffer[valread] = '\0';  
                    //send(sd , buffer , strlen(buffer) , 0 );  
                    std::memmove(&current_transaction, buffer, sizeof(current_transaction));
                    valread = verify_transaction(current_transaction, public_key);
                    std::cout << "transaction verified: " << valread << std::endl;
                }  
            }  
        }  
    }  
         
    return 0;  
}  
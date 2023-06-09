#include <cstdint>
#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string>
#include <vector>

#define BLOCK_SIZE 10

namespace put::blockchain::block_chain
{
struct transaction_t
{
    uint16_t transaction_id;
    uint64_t sender_id;
    uint64_t recipient_id;
    uint64_t transaction_amount;
    char signature[256] = {0};
};
struct transaction_block_t
{
    unsigned char previous_block_hash[SHA256_DIGEST_LENGTH];
    transaction_t transactions[BLOCK_SIZE];
    uint64_t proof_of_work = NULL;
};

class block_chain
{
  private:
    RSA *private_key = nullptr;
    uint64_t last_transaction_id;
    std::vector<transaction_t> transactions;
    transaction_block_t newest_transaction_block;

  public:
    block_chain(uint64_t last_transaction_id);
    block_chain(std::string private_key_file_name, uint64_t last_transaction_id);
    void set_private_key(std::string private_key_file_name);
    transaction_t add_transaction(uint64_t sender_id, uint64_t recipient_id, uint64_t transaction_amount);
    transaction_t create_transaction(uint64_t sender_id, uint64_t recipient_id, uint64_t transaction_amount);
    void add_transaction(transaction_t transaction);
    transaction_block_t create_transaction_block(unsigned char previous_block_hash[SHA256_DIGEST_LENGTH]);
    unsigned char *get_transaction_block_hash();
    void get_transaction_block_hash(unsigned char * transaction_hash);
};

} // namespace put::blockchain::block_chain
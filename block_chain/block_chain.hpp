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
void calculate_hash(const unsigned char *data, size_t len, unsigned char *hash)
{
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, data, len);
    SHA256_Final(hash, &sha_ctx);
}

void generate_signature(const transaction_t &transaction, RSA *private_key, unsigned char *signature)
{
    unsigned char data[sizeof(transaction_t)];
    memcpy(data, &transaction, sizeof(transaction_t));

    unsigned char hash[SHA256_DIGEST_LENGTH];
    calculate_hash(data, sizeof(transaction_t), hash);

    unsigned int sig_len;
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, private_key);
}
struct transaction_t
{
    uint16_t transaction_id;
    uint64_t sender_id;
    uint64_t recipient_id;
    uint64_t transaction_amount;
    char signature[SHA256_DIGEST_LENGTH] = {0};
};
struct transaction_block_t
{
    char previous_block_hash[SHA256_DIGEST_LENGTH];
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
    block_chain(std::string private_key_file_name, uint64_t last_transaction_id);
    void set_private_key(std::string private_key_file_name);
    void add_transaction(uint64_t sender_id, uint64_t recipient_id, uint64_t transaction_amount);
    transaction_block_t create_transaction_block(char previous_block_hash[SHA256_DIGEST_LENGTH]);
    unsigned char *get_transaction_block_hash();
};

} // namespace put::blockchain::block_chain
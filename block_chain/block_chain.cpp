#include "block_chain.hpp"

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

block_chain::block_chain(std::string private_key_file_name, uint64_t last_transaction_id)
    : last_transaction_id(last_transaction_id)
{
    set_private_key(private_key_file_name);
}
void block_chain::set_private_key(std::string private_key_file_name)
{
    FILE *private_key_file = fopen(private_key_file_name.c_str(), "r");
    if (private_key_file != nullptr)
    {
        private_key = PEM_read_RSAPrivateKey(private_key_file, nullptr, nullptr, nullptr);
        fclose(private_key_file);
    }

    if (private_key == nullptr)
    {
        std::cerr << "Failed to load private key" << std::endl;
    }
}
void block_chain::add_transaction(uint64_t sender_id, uint64_t recipient_id, uint64_t transaction_amount)
{
    if (transactions.size() >= 10)
    {
        std::cerr << "Too many transactions for one block, create block first" << std::endl;
    }
    transaction_t new_transaction;
    new_transaction.recipient_id = recipient_id;
    new_transaction.sender_id = sender_id;
    new_transaction.transaction_amount = transaction_amount;
    new_transaction.transaction_id = ++last_transaction_id;

    unsigned char signature[RSA_size(private_key)];
    generate_signature(new_transaction, private_key, signature);

    std::memcpy(new_transaction.signature, signature, sizeof(signature));

    delete signature;
    transactions.push_back(new_transaction);
}

transaction_block_t block_chain::create_transaction_block(char previous_block_hash[SHA256_DIGEST_LENGTH])
{
    if (transactions.size() != 10)
    {
        std::cerr << "Not enough transactions to create a block, add more transactions" << std::endl;
    }
    transaction_block_t new_block;
    std::memcpy(new_block.previous_block_hash, previous_block_hash, SHA256_DIGEST_LENGTH);
    std::memcpy(new_block.transactions, transactions.data(), sizeof(transaction_t) * BLOCK_SIZE);
    new_block.proof_of_work = 0;
    unsigned char transaction_hash[SHA256_DIGEST_LENGTH];
    calculate_hash(reinterpret_cast<unsigned char *>(&new_block), sizeof(transaction_block_t), transaction_hash);
    while (transaction_hash[0] != '\0')
    {
        ++new_block.proof_of_work;
        calculate_hash(reinterpret_cast<unsigned char *>(&new_block), sizeof(transaction_block_t), transaction_hash);
    }

    transactions.clear();
    newest_transaction_block = new_block;
    return new_block;
}

unsigned char *block_chain::get_transaction_block_hash()
{
    if (newest_transaction_block.proof_of_work == NULL) // IS TRANSACTION BLOCK VALID)
    {
        std::cerr << "Can't calcualte a hash of a nonexistent block" << std::endl;
    }
    unsigned char transaction_hash[SHA256_DIGEST_LENGTH];
    calculate_hash(reinterpret_cast<unsigned char *>(&newest_transaction_block), sizeof(transaction_block_t),
                   transaction_hash);
    return transaction_hash;
}

} // namespace put::blockchain::block_chain
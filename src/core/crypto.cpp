/**
 * OSL: Open Source Ledger - Cryptographic Module Logic
 * Implementation of SHA-256 chaining.
 */

#include "crypto.hpp"
#include <openssl/sha.h> // Standard OpenSSL header for hashing
#include <iomanip>
#include <sstream>

// Standard SHA-256 generation
std::string OSLCrypto::generate_sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    // Initialise the context, update it with data, and finalise the hash
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    // Convert the raw binary hash into a readable Hexadecimal string
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// The "Chain Link" logic
std::string OSLCrypto::calculate_entry_hash(const std::string& prev_hash, const LedgerLine& line) {
    std::stringstream data;
    
    /**
     * We concatenate the previous hash with the current line attributes.
     * If even one character in the description or one micro in the amount 
     * changes, the resulting hash will be completely different.
     */
    data << prev_hash 
         << line.account_code 
         << line.debit 
         << line.credit 
         << line.description;
             
    return generate_sha256(data.str());
}

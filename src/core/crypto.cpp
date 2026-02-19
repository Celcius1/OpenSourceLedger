#include "crypto.hpp"
#include <openssl/evp.h> // Modern OpenSSL API
#include <iomanip>
#include <sstream>

namespace osl {

std::string OSLCrypto::generate_sha256(const std::string str) {
    unsigned char hash[32]; // SHA256 is 32 bytes
    unsigned int length = 0;
    
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    EVP_DigestUpdate(context, str.c_str(), str.size());
    EVP_DigestFinal_ex(context, hash, &length);
    EVP_MD_CTX_free(context);

    std::stringstream ss;
    for(unsigned int i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string OSLCrypto::calculate_entry_hash(const std::string& prev_hash, const LedgerLine& line) {
    std::stringstream data;
    data << prev_hash 
         << line.account_code 
         << line.debit 
         << line.credit 
         << line.description;
             
    return generate_sha256(data.str());
}

} // namespace osl

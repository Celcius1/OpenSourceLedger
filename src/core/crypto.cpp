#include "crypto.hpp"
#include <openssl/evp.h> // Modern OpenSSL API
#include <iomanip>
#include <sstream>
#include <random>

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

std::string osl::OSLCrypto::generate_random_string(int length) {
    const std::string charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> dist(0, charset.size() - 1);
    
    std::string str;
    for (int i = 0; i < length; ++i) str += charset[dist(generator)];
    return str;
}

std::string osl::OSLCrypto::hash_password(const std::string& password) {
    // Salting with your business name to prevent rainbow table attacks
    return generate_sha256(password + "CEL-TECH-SERV-SALT"); 
}

} // namespace osl

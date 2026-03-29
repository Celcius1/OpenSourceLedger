/**
 * OSL: Open Source Ledger - Cryptographic Module Header
 * Purpose: Defines the SHA-256 hashing interface for the Sovereign chain.
 */

#ifndef OSL_CRYPTO_HPP
#define OSL_CRYPTO_HPP

#include <string>
#include "osl_plugin.hpp"

namespace osl {

class OSLCrypto {
public:
    // Ledger Hashing (Existing)
    static std::string generate_sha256(const std::string str);
    static std::string calculate_entry_hash(const std::string& prev_hash, const LedgerLine& line);

    // Identity & Security (NEW - Required for User Management)
    /**
     * generate_random_string
     * Creates a secure alphanumeric string for one-time bootstrap passwords.
     */
    static std::string generate_random_string(int length);

    /**
     * hash_password
     * Salts and hashes user passwords before they reach the Vault.
     */
    static std::string hash_password(const std::string& password);
};

} // namespace osl

#endif

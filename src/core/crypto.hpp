/**
 * OSL: Open Source Ledger - Cryptographic Module Header
 * Purpose: Defines the SHA-256 hashing interface for the Sovereign chain.
 */

#ifndef OSL_CRYPTO_HPP
#define OSL_CRYPTO_HPP

#include <string>
#include "osl_plugin.hpp" // Now part of the OSL namespace

namespace osl { // Aligning with the Sovereign SDK namespace

class OSLCrypto {
public:
    /**
     * generate_sha256
     * Uses OpenSSL EVP API for compatibility with OpenSSL 3.0+
     */
    static std::string generate_sha256(const std::string str);

    /**
     * calculate_entry_hash
     * Bonds the previous hash to the current LedgerLine.
     */
    static std::string calculate_entry_hash(const std::string& prev_hash, const LedgerLine& line);
};

} // namespace osl

#endif

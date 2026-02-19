/**
 * OSL: Open Source Ledger - Cryptographic Module Header
 * Purpose: Defines the SHA-256 hashing interface for the Sovereign chain.
 */

#ifndef OSL_CRYPTO_HPP
#define OSL_CRYPTO_HPP

#include <string>
#include "../plugins/interface/osl_plugin.hpp"

class OSLCrypto {
public:
    /**
     * generate_sha256
     * @param str: The raw string data to be hashed.
     * @return: A 64-character hex string representing the SHA-256 hash.
     */
    static std::string generate_sha256(const std::string str);

    /**
     * calculate_entry_hash
     * @param prev_hash: The hash of the previous record in the vault.
     * @param line: The current ledger entry data to be bonded.
     * @return: The unique hash that links this entry to the previous one.
     */
    static std::string calculate_entry_hash(const std::string& prev_hash, const LedgerLine& line);
};

#endif

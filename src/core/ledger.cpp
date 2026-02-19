/**
 * OSL: Open Source Ledger - Core Ledger Logic
 * Focus: Double-entry validation and cryptographic chain enforcement.
 */

#include "../plugins/interface/osl_plugin.hpp"
#include "crypto.hpp" // Now using the header instead of including the .cpp
#include <vector>
#include <stdexcept>
#include <iostream>

class OSLCoreLedger {
public:
    /**
     * validate_transaction
     * Ensures that the sum of debits equals the sum of credits.
     * This is the fundamental rule of the "Old Fashioned" ledger.
     */
    bool validate_transaction(const std::vector<LedgerLine>& lines) {
        money_micro total_balance = 0;

        // An empty transaction is logically invalid
        if (lines.empty()) {
            throw std::runtime_error("Transaction must have at least one line.");
        }

        // Aggregate all debits and credits
        for (const auto& line : lines) {
            total_balance += line.debit;
            total_balance -= line.credit;
        }

        // If the total isn't exactly zero, the entry is rejected.
        if (total_balance != 0) {
            std::cerr << "[ERROR] Transaction unbalanced! Deviation: " << total_balance << " micros." << std::endl;
            return false;
        }

        return true;
    }

    /**
     * apply_security_chain
     * Iterates through a transaction and "bonds" each line to the previous one.
     * @param last_vault_hash: The current 'head' hash from the PostgreSQL database.
     * @return: The new 'head' hash representing the updated state of truth.
     */
    std::string apply_security_chain(std::string last_vault_hash, std::vector<LedgerLine>& transaction) {
        std::string current_link = last_vault_hash;

        for (auto& line : transaction) {
            // Cryptographically bond this line to the history of the ledger
            current_link = OSLCrypto::calculate_entry_hash(current_link, line);
        }
        
        return current_link; 
    }
};

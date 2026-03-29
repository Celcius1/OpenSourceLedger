#include "osl_plugin.hpp"
#include "crypto.hpp" 
#include <vector>
#include <stdexcept>
#include <iostream>
#include <string>

// Fixed: Signature perfectly matches main.cpp
extern void osl_log(std::string level, std::string message);

using namespace osl; // Allows access to LedgerLine and money_micro

class OSLCoreLedger {
public:
    bool validate_transaction(const std::vector<LedgerLine>& lines) {
        // --- INJECTED LEDGER TRIPWIRE ---
        osl_log("DEBUG", "Validating Transaction. Line count: " + std::to_string(lines.size()));
        // --------------------------------

        money_micro total_balance = 0;

        if (lines.empty()) {
            throw std::runtime_error("Transaction must have at least one line.");
        }

        for (const auto& line : lines) {
            total_balance += line.debit;
            total_balance -= line.credit;
        }

        if (total_balance != 0) {
            osl_log("ERROR", "Transaction unbalanced! Deviation: " + std::to_string(total_balance) + " micros.");
            std::cerr << "[ERROR] Transaction unbalanced! Deviation: " << total_balance << " micros." << std::endl;
            return false;
        }
        
        osl_log("DEBUG", "Transaction Validation Passed. Zero-sum confirmed.");
        return true;
    }

    std::string apply_security_chain(std::string last_vault_hash, std::vector<LedgerLine>& transaction) {
        // --- INJECTED LEDGER TRIPWIRE ---
        osl_log("DEBUG", "Initiating Security Chain. Lines to seal: " + std::to_string(transaction.size()));
        osl_log("DEBUG", "Starting Vault Hash: " + last_vault_hash);
        // --------------------------------

        std::string current_link = last_vault_hash;

        for (auto& line : transaction) {
            // Now correctly calls the namespaced OSLCrypto
            current_link = OSLCrypto::calculate_entry_hash(current_link, line);
        }

        // --- INJECTED LEDGER TRIPWIRE ---
        osl_log("DEBUG", "Security Chain Complete. Final Hash: " + current_link);
        // --------------------------------

        return current_link; 
    }
};
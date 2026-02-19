#include "osl_plugin.hpp"
#include "crypto.hpp" 
#include <vector>
#include <stdexcept>
#include <iostream>

using namespace osl; // Allows access to LedgerLine and money_micro

class OSLCoreLedger {
public:
    bool validate_transaction(const std::vector<LedgerLine>& lines) {
        money_micro total_balance = 0;

        if (lines.empty()) {
            throw std::runtime_error("Transaction must have at least one line.");
        }

        for (const auto& line : lines) {
            total_balance += line.debit;
            total_balance -= line.credit;
        }

        if (total_balance != 0) {
            std::cerr << "[ERROR] Transaction unbalanced! Deviation: " << total_balance << " micros." << std::endl;
            return false;
        }
        return true;
    }

    std::string apply_security_chain(std::string last_vault_hash, std::vector<LedgerLine>& transaction) {
        std::string current_link = last_vault_hash;

        for (auto& line : transaction) {
            // Now correctly calls the namespaced OSLCrypto
            current_link = OSLCrypto::calculate_entry_hash(current_link, line);
        }
        return current_link; 
    }
};

#include "../plugins/interface/osl_plugin.hpp"
#include <vector>
#include <stdexcept>
#include <iostream>

class OSLCoreLedger {
public:
    // This is the "Gatekeeper" function. 
    // It verifies the math before the database even sees the data.
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

    // This is where the "Sovereign" part happens.
    // In the future, this will use OpenSSL to generate the SHA-256 hash.
    std::string calculate_integrity_hash(std::string prev_hash, const std::vector<LedgerLine>& lines) {
        // Placeholder for SHA-256 logic
        std::string data_to_hash = prev_hash;
        for (const auto& line : lines) {
            data_to_hash += line.account_code + std::to_string(line.debit);
        }
        return "sha256_placeholder_hash"; 
    }
};

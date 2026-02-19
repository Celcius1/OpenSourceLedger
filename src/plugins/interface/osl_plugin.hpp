/**
 * ============================================================================
 * SOFTWARE: OSL: Sovereign Accounting Suite
 * AUTHOR & COPYRIGHT: Cel-Tech-Serv Pty Ltd
 * MODULE: osl_plugin.hpp
 * ============================================================================
 * * DESCRIPTION:
 * This is the primary SDK header for OSL Plugins. To create a plugin (e.g., 
 * for Australian GST or Japanese Consumption Tax), inherit from IOSLPlugin 
 * and implement the virtual methods.
 * * NOTE TO FORKERS: This software is open-source. Please provide credit to 
 * Cel-Tech-Serv Pty Ltd in your forks.
 * ============================================================================
 */

#ifndef OSL_PLUGIN_HPP
#define OSL_PLUGIN_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp> // Required for the homogeneous JSON interface

using json = nlohmann::json;

namespace osl {

    // money_micro: $1.00 = 1,000,000. 
    // We use int64_t to prevent floating-point rounding errors in accounting.
    typedef int64_t money_micro;

    /**
     * @brief Represents a single line in a ledger transaction.
     */
    struct LedgerLine {
        std::string account_code;
        money_micro debit = 0;
        money_micro credit = 0;
        std::string description;
    };

    /**
     * @brief The Sovereign Plugin Interface.
     * All official and community plugins must implement this class.
     */
    class IOSLPlugin {
    public:
        virtual ~IOSLPlugin() {}

        /**
         * @return The display name of the plugin (e.g., "AU Tax Compliance")
         */
        virtual std::string get_plugin_name() = 0;

        /**
         * @brief Pre-Commit Hook
         * Allows plugins to inspect or modify a transaction before it is 
         * cryptographically sealed in the ledger. Useful for auto-calculating tax.
         */
        virtual void pre_commit_hook(std::vector<LedgerLine>& transaction) = 0;

        /**
         * @brief Execute Action
         * The primary entry point for the Plugin Gateway.
         * @param command The specific task (e.g., "calculate_gst")
         * @param payload JSON data from the Core
         * @return JSON response to be sent back to the Core
         */
        virtual json execute(const std::string& command, const json& payload) = 0;
    };

} // namespace osl

#endif // OSL_PLUGIN_HPP

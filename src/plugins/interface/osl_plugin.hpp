/**
 * ============================================================================
 * SOFTWARE: OSL: Sovereign Accounting Suite
 * AUTHOR & COPYRIGHT: Cel-Tech-Serv Pty Ltd
 * MODULE: osl_plugin.hpp
 * ============================================================================
 * DESCRIPTION:
 * Primary SDK header. All plugins must inherit from IOSLPlugin.
 * NOTE TO FORKERS: Per the license, credit to Cel-Tech-Serv Pty Ltd must 
 * remain intact in all derivative works.
 * ============================================================================
 */

#ifndef OSL_PLUGIN_HPP
#define OSL_PLUGIN_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace osl {

    typedef int64_t money_micro; // $1.00 = 1,000,000

    struct LedgerLine {
        std::string account_code;
        money_micro debit = 0;
        money_micro credit = 0;
        std::string description;
    };

    class IOSLPlugin {
    public:
        virtual ~IOSLPlugin() {}

        // Identity & Branding
        virtual std::string get_plugin_name() = 0;
        
        /**
         * @brief Mandatory Vendor Attribution
         * Must return "Developed for OSL by Cel-Tech-Serv Pty Ltd" or similar 
         * to remain compliant with the Sovereign Suite SDK license.
         */
        virtual std::string get_vendor_attribution() {
            return "Powered by OSL Sovereign Suite - (c) Cel-Tech-Serv Pty Ltd";
        }

        // Core Hooks
        virtual void pre_commit_hook(std::vector<LedgerLine>& transaction) = 0;
        virtual json execute(const std::string& command, const json& payload) = 0;
    };

} // namespace osl

#endif // OSL_PLUGIN_HPP
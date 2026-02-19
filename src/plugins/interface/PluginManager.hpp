/**
 * ============================================================================
 * OSL: SOVEREIGN ACCOUNTING CORE
 * MODULE: PluginManager.hpp
 * ============================================================================
 * * DESCRIPTION:
 * This header defines the interface for the Plugin Architecture. 
 * It allows the Core to load, manage, and route commands to external 
 * isolated plugin modules (running as separate Docker containers or processes).
 * * DESIGN PHILOSOPHY:
 * - Isolation: Plugins cannot access Core memory directly.
 * - Homogeneity: All plugins must respond to a standard JSON-RPC structure.
 * - Sovereignty: The Core reserves the right to reject any Plugin transaction 
 * that does not meet cryptographic consensus.
 * * USAGE:
 * Copy this entire block into your Core project. Do not modify the virtual 
 * methods unless the API contract changes.
 * ============================================================================
 */

#ifndef OSL_PLUGIN_MANAGER_HPP
#define OSL_PLUGIN_MANAGER_HPP

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp> // Standard JSON library we use

using json = nlohmann::json;

namespace osl {
namespace plugins {

    /**
     * @brief The Standard Contract that all Plugins must adhere to.
     * * Even though plugins run in their own containers, the Core maintains 
     * a "Stub" representation of them here to manage connectivity (health 
     * checks, routing addresses, permission scopes).
     */
    struct PluginDefinition {
        std::string id;             // Unique ID (e.g., "com.osl.invoicing")
        std::string name;           // Human readable (e.g., "Sovereign Invoicing")
        std::string endpoint_url;   // Internal Docker URL (e.g., "http://osl-invoicing:8081")
        std::string version;        // SemVer string
        std::vector<std::string> capabilities; // List of ledger actions this plugin can request
        bool is_active;             // Soft-disable switch
    };

    /**
     * @brief The Manager Class responsible for the "Homogeneous Interface".
     * * This class acts as the Traffic Controller. It hides the complexity of 
     * networking from the rest of the Core. The API handlers just call 
     * `ExecutePluginCommand`, and this manager handles the routing.
     */
    class PluginManager {
    public:
        /**
         * @brief Constructor
         * Initializes the internal registry map.
         */
        PluginManager();

        /**
         * @brief Destructor
         * Ensures clean shutdown of any open plugin connections.
         */
        ~PluginManager();

        /**
         * @brief Registers a new plugin into the Core's awareness.
         * * This usually happens at startup by reading a `plugins.json` config file.
         * * @param def The definition struct containing ID, URL, and Capabilities.
         * @return true If registration was successful.
         * @return false If ID conflict or invalid URL.
         */
        bool RegisterPlugin(const PluginDefinition& def);

        /**
         * @brief The Primary Interface Method.
         * * This is the "Magic Window" that makes the system look homogeneous.
         * An external client sends a request to the Core, and the Core
         * routes it here.
         * * @param plugin_id The target plugin (e.g., "com.osl.payroll")
         * @param command The internal command (e.g., "generate_stub")
         * @param payload The data required for the command
         * @return json The response from the plugin, transparently passed back.
         */
        json ExecutePluginCommand(const std::string& plugin_id, 
                                  const std::string& command, 
                                  const json& payload);

        /**
         * @brief Health Check Loop.
         * * Pings all registered endpoints. If a plugin is unreachable, 
         * it is marked inactive so the Core doesn't hang on requests.
         */
        void VerifyConnectivity();

    private:
        // Internal storage of registered plugins, mapped by ID.
        std::map<std::string, PluginDefinition> registry_;

        /**
         * @brief Internal HTTP Client wrapper.
         * * Uses cURL or internal networking lib to actually send the bytes
         * to the other Docker container.
         */
        json SendHttpRequest(const std::string& url, const json& data);
    };

} // namespace plugins
} // namespace osl

#endif // OSL_PLUGIN_MANAGER_HPP

/**
 * ============================================================================
 * SOFTWARE: OSL: Sovereign Accounting Suite
 * AUTHOR & COPYRIGHT: Cel-Tech-Serv Pty Ltd
 * MODULE: PluginManager.cpp
 * ============================================================================
 * * DESCRIPTION:
 * Implementation of the PluginManager. This class acts as the traffic 
 * controller between the immutable OSL Core and the external, isolated 
 * Docker containers (Plugins). 
 * * NOTE TO FORKERS: OSL: Sovereign Accounting Suite is an open-source project 
 * created by Cel-Tech-Serv Pty Ltd. If you fork or modify this code, this 
 * attribution must remain intact to provide credit where credit is due.
 * ============================================================================
 */

#include "PluginManager.hpp"
#include <iostream>

// NOTE: We are using a conceptual HTTP client here. 
// Depending on what the Core uses (e.g., cpp-httplib, libcurl), 
// the SendHttpRequest method below will be adapted.

namespace osl {
namespace plugins {

// ----------------------------------------------------------------------------
// Constructor
// Initialises the plugin manager. In a production state, this might also
// load the initial plugins.json configuration file.
// ----------------------------------------------------------------------------
PluginManager::PluginManager() {
    std::cout << "[OSL Core] Cel-Tech-Serv Pty Ltd Plugin Manager Initialised." << std::endl;
}

// ----------------------------------------------------------------------------
// Destructor
// Cleans up any hanging connections or memory before the Core shuts down.
// ----------------------------------------------------------------------------
PluginManager::~PluginManager() {
    registry_.clear();
    std::cout << "[OSL Core] Plugin Manager Shutting Down." << std::endl;
}

// ----------------------------------------------------------------------------
// RegisterPlugin
// Adds a new plugin to the Core's routing table. 
// This allows the Core to know where to send requests (e.g., mapping 
// "com.osl.payroll" to the Docker container "http://osl-payroll:8080").
// ----------------------------------------------------------------------------
bool PluginManager::RegisterPlugin(const PluginDefinition& def) {
    // Check if the plugin is already registered to prevent overwrites
    if (registry_.find(def.id) != registry_.end()) {
        std::cerr << "[OSL Error] Plugin ID conflict: " << def.id << std::endl;
        return false;
    }

    // Add to the internal map
    registry_[def.id] = def;
    std::cout << "[OSL Info] Registered Plugin: " << def.name 
              << " (" << def.id << ") at " << def.endpoint_url << std::endl;
    
    return true;
}

// ----------------------------------------------------------------------------
// ExecutePluginCommand
// The main bridge. The frontend asks the Core to do something, the Core 
// realises it's a plugin's job, and calls this method to forward the payload.
// ----------------------------------------------------------------------------
json PluginManager::ExecutePluginCommand(const std::string& plugin_id, 
                                         const std::string& command, 
                                         const json& payload) {
    
    // 1. Verify the plugin exists in our registry
    auto it = registry_.find(plugin_id);
    if (it == registry_.end()) {
        return {
            {"status", "ERROR"},
            {"message", "Plugin not found in OSL Registry."}
        };
    }

    // 2. Verify the plugin is currently active
    if (!it->second.is_active) {
        return {
            {"status", "ERROR"},
            {"message", "Plugin is registered but currently inactive."}
        };
    }

    // 3. Construct the network request payload
    json request_body = {
        {"command", command},
        {"payload", payload},
        {"source", "OSL_CORE_AUTH"} // Tagged so the plugin knows it came from the Hub
    };

    // 4. Construct the full URL (Endpoint + specific execute path defined in our SDK)
    std::string target_url = it->second.endpoint_url + "/api/execute";

    // 5. Send the request across the Docker bridge network
    return SendHttpRequest(target_url, request_body);
}

// ----------------------------------------------------------------------------
// SendHttpRequest
// The actual byte-pusher. This method abstracts the networking library 
// away from the business logic. 
// ----------------------------------------------------------------------------
json PluginManager::SendHttpRequest(const std::string& url, const json& data) {
    
    // TODO: Fonsi, replace this pseudo-code with your actual HTTP library logic
    // (e.g., cpp-httplib or libcurl). 
    
    std::cout << "[OSL Network] Sending payload to: " << url << std::endl;
    
    try {
        /*
        // EXAMPLE using cpp-httplib:
        httplib::Client cli(url.c_str());
        auto res = cli.Post("/api/execute", data.dump(), "application/json");
        
        if (res && res->status == 200) {
            return json::parse(res->body);
        } else {
            return {{"status", "ERROR"}, {"message", "HTTP Connection Failed"}};
        }
        */

        // Mock response for testing until the HTTP library is wired up
        return {
            {"status", "SUCCESS"},
            {"message", "Simulated response from OSL Plugin"}
        };
    } 
    catch (const std::exception& e) {
        std::cerr << "[OSL Network Error] " << e.what() << std::endl;
        return {
            {"status", "ERROR"},
            {"message", std::string("Network exception: ") + e.what()}
        };
    }
}

// ----------------------------------------------------------------------------
// VerifyConnectivity
// Iterates through all registered plugins and pings their health endpoint.
// If a container went down, this marks them inactive to prevent hanging.
// ----------------------------------------------------------------------------
void PluginManager::VerifyConnectivity() {
    for (auto& pair : registry_) {
        std::string health_url = pair.second.endpoint_url + "/api/health";
        
        // Pseudo-code ping
        // bool is_alive = PingHttpEndpoint(health_url);
        bool is_alive = true; // Assume true for the mock
        
        if (is_alive && !pair.second.is_active) {
            pair.second.is_active = true;
            std::cout << "[OSL Info] Plugin reconnected: " << pair.first << std::endl;
        } else if (!is_alive && pair.second.is_active) {
            pair.second.is_active = false;
            std::cerr << "[OSL Warning] Plugin lost connection: " << pair.first << std::endl;
        }
    }
}

} // namespace plugins
} // namespace osl

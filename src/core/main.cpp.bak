/**
 * ============================================================================
 * SOFTWARE: OSL: Sovereign Accounting Suite - Core Engine
 * AUTHOR & COPYRIGHT: Cel-Tech-Serv Pty Ltd
 * MODULE: main.cpp
 * ============================================================================
 */

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib> 
#include <pqxx/pqxx>
#include <httplib.h>
#include <nlohmann/json.hpp> 
#include "crypto.hpp"
#include "ledger.cpp"
#include "ViewEngine.hpp"
#include <map>
#include "../plugins/interface/PluginManager.hpp" 

using json = nlohmann::json;

// Helper: Format Money (Australian English Formatting)
std::string format_money(long long micros) {
    long long dollars = micros / 1000000;
    long long cents = (micros % 1000000) / 10000;
    return "$" + std::to_string(dollars) + "." + (cents < 10 ? "0" : "") + std::to_string(cents);
}

// FIX: Updated to check the LLDAP 'admins' group passed by Authelia
// Protects Cel-Tech-Serv Pty Ltd admin routes
bool is_admin(const httplib::Request &req) {
    if (req.has_header("Remote-Groups")) {
        std::string groups = req.get_header_value("Remote-Groups");
        // Authelia passes groups as a comma-separated list (e.g., "users,admins,tenant_celtech")
        return groups.find("admins") != std::string::npos;
    }
    return false;
}

int main() {
    // FIX: Moved OSL_DB_CONN extraction to the very top so 'conn_str' is defined 
    // BEFORE we attempt to establish the pqxx::connection.
    const char* env_db = std::getenv("OSL_DB_CONN");
    if (!env_db) {
        std::cerr << "[FATAL] OSL_DB_CONN environment variable missing. Vault access denied. Core halted." << std::endl;
        return 1;
    }
    std::string conn_str = env_db;

    // 1. Establish Connection
    pqxx::connection C(conn_str); 

    // FIX: Safely extract the base domain for logout redirects
    const char* env_domain = std::getenv("OSL_BASE_DOMAIN");
    std::string base_domain = env_domain ? env_domain : "osl.net.au";

    // 3. Initialise the Plugin Manager (Cel-Tech-Serv Pty Ltd Hub)
    osl::plugins::PluginManager plugin_manager;

    osl::plugins::PluginDefinition invoicing_plugin = {
        "au.net.osl.invoicing",
        "Sovereign Invoicing",
        "http://osl-invoicing:8081", 
        "1.0.0",
        {"READ_LEDGER", "WRITE_LEDGER"},
        true
    };
    plugin_manager.RegisterPlugin(invoicing_plugin);

    // This boots the web server engine for the microkernel
    httplib::Server svr;
    std::cout << "[OSL] Cel-Tech-Serv Hub: Hybrid Auth & Plugin System Active." << std::endl;

    // --- SOVEREIGN LOGGER MIDDLEWARE ---
    svr.set_logger([](const httplib::Request &req, const httplib::Response &res) {
        std::cout << "[HUB] " << req.method << " " << req.path 
                  << " -> Status: " << res.status << " (User: " 
                  << (req.has_header("Remote-User") ? req.get_header_value("Remote-User") : "Local/Backup") 
                  << ")" << std::endl;
    });

    // --- GATEKEEPER MIDDLEWARE ---
    // We now ONLY trust the Reverse Proxy's cryptographically verified header.
    auto is_authenticated = [&](const httplib::Request &req) -> bool {
        return req.has_header("Remote-User") && !req.get_header_value("Remote-User").empty();
    };

    // --- ROUTES ---

    // 1. DASHBOARD (Root Path)
    svr.Get("/", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) {
            // No more redirecting to a local login page. Drop the connection.
            res.status = 401;
            res.set_content("401 Unauthorized - Access via Authelia Gateway Required", "text/plain");
            return;
        }
        
        // --- BEGIN COPY: Sovereign UI Assembly ---
        // 1. Initialise the context map for Cel-Tech-Serv Pty Ltd injection
        std::map<std::string, std::string> ui_context;

        // 2. Set Core Identity & Branding parameters
        ui_context["BUSINESS_NAME"] = "Cel-Tech-Serv Pty Ltd";
        
        // Dynamically extract the verified LLDAP username passed by Authelia
        // Fallback to 'celcius1' to prevent crashes during local testing
        std::string user = req.has_header("Remote-User") ? req.get_header_value("Remote-User") : "celcius1";
        ui_context["USERNAME"] = user; 

        // 3. Set Agnostic UI Hooks (Empty defaults for this test compile)
        ui_context["SIDEBAR_HOOKS"] = "";
        ui_context["HEADER_HOOKS"] = "";
        ui_context["DYNAMIC_HEADERS"] = "<th class='py-3'>Date</th><th class='py-3'>Description</th><th class='py-3 text-right'>Balance</th>";
        ui_context["DYNAMIC_ROW_DATA"] = "<td class='py-4'>Vault Synchronisation Pending...</td>";

        // 4. Instruct ViewEngine to assemble the final HTML using the internal Docker path
        std::string final_html = ViewEngine::render_template("/app/core/templates/base.html", ui_context);

        // 5. Handle potential engine failure gracefully
        if (final_html.find("500 Internal Server Error") != std::string::npos) {
            res.status = 500;
            res.set_content("OSL Core Error: ViewEngine failed to assemble the Sovereign UI. Check template paths.", "text/plain");
            return;
        }

        // 6. Serve the assembled dashboard successfully
        res.status = 200;
        res.set_content(final_html, "text/html");
        // --- END COPY: Sovereign UI Assembly ---
    });

    // 1b. FULL-CHAIN SOVEREIGN AUDIT API (GET)
    svr.Get("/api/ledger/data", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            pqxx::connection C(conn_str);
            pqxx::work W(C);
            pqxx::result R = W.exec("SELECT id, to_char(transaction_date, 'DD/MM/YYYY'), description, debit_micros, credit_micros, balance_micros, category, sub_category, status, row_hash FROM ledger ORDER BY id ASC");

            json ledger_json = json::array();
            std::string expected_prev_hash = "GENESIS"; 

            for (auto row : R) {
                std::string desc = row[2].as<std::string>();
                long long debit = row[3].as<long long>();
                long long credit = row[4].as<long long>();
                long long balance = row[5].as<long long>();
                std::string cat = row[6].is_null() ? "" : row[6].as<std::string>();
                std::string sub = row[7].is_null() ? "" : row[7].as<std::string>();
                std::string stored_hash = row[9].as<std::string>();

                std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(balance) + cat + sub + expected_prev_hash;
                std::string recalc_hash = osl::OSLCrypto::generate_sha256(raw_data);

                ledger_json.push_back({
                    {"id", row[0].as<int>()},
                    {"date", row[1].as<std::string>()},
                    {"description", desc},
                    {"debit", format_money(debit)},
                    {"credit", format_money(credit)},
                    {"balance", format_money(balance)},
                    {"category", cat},
                    {"subcategory", sub},
                    {"status", row[8].as<std::string>()},
                    {"audit_passed", (recalc_hash == stored_hash)}
                });
                expected_prev_hash = stored_hash;
            }
            std::reverse(ledger_json.begin(), ledger_json.end());
            res.set_content(ledger_json.dump(), "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
        }
    });

    // 1c. BANK-ALIGNED MANUAL ENTRY (POST)
    svr.Post("/api/ledger/add", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            auto j = json::parse(req.body);
            std::string desc = j.at("description").get<std::string>();
            long long debit = j.at("debit").get<long long>();
            long long credit = j.at("credit").get<long long>();
            std::string cat = j.at("category").get<std::string>();
            std::string sub = j.at("subcategory").get<std::string>();

            pqxx::connection C(conn_str);
            pqxx::work W(C);

            pqxx::result last_row = W.exec("SELECT balance_micros, row_hash FROM ledger ORDER BY id DESC LIMIT 1");
            long long prev_balance = last_row.empty() ? 0 : last_row[0][0].as<long long>();
            std::string prev_hash = last_row.empty() ? "GENESIS" : last_row[0][1].as<std::string>();

            long long new_balance = prev_balance - debit + credit;
            std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(new_balance) + cat + sub + prev_hash;
            std::string current_hash = osl::OSLCrypto::generate_sha256(raw_data);

            W.exec("INSERT INTO ledger (description, debit_micros, credit_micros, balance_micros, category, sub_category, row_hash) VALUES (" +
                   W.quote(desc) + ", " + std::to_string(debit) + ", " + std::to_string(credit) + ", " + 
                   std::to_string(new_balance) + ", " + W.quote(cat) + ", " + W.quote(sub) + ", " + W.quote(current_hash) + ")");
            
            W.commit();
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
        }
    });

    // 2. PLUGIN GATEWAY (POST)
    svr.Post(R"(/api/plugin/([^/]+)/([^/]+))", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) {
            res.status = 401;
            return;
        }
        std::string plugin_id = req.matches[1];
        std::string command = req.matches[2];
        json payload = req.body.empty() ? json::object() : json::parse(req.body);
        json result = plugin_manager.ExecutePluginCommand(plugin_id, command, payload);
        res.set_content(result.dump(), "application/json");
    });

    // 3. PLUGIN MANIFEST API (GET)
    svr.Get("/api/plugins/active", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        json plugins = json::array();
        plugins.push_back({
            {"id", "au.net.osl.invoicing"},
            {"name", "Sovereign Invoicing"},
            {"version", "1.0.0"}
        });
        res.set_content(plugins.dump(), "application/json");
    });

    // ------------------------------------------------------------------------
    // OSL: Sovereign Accounting Suite
    // 4. IDENTITY GATEWAY (POST) - Provisioning Users via Cel-Tech-Serv Pty Ltd
    // ------------------------------------------------------------------------
    svr.Post("/api/users/update", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_admin(req)) {
            res.status = 403;
            res.set_content("{\"error\":\"Forbidden: Sovereign Admin Privileges Required.\"}", "application/json");
            return;
        }

        try {
            auto j = json::parse(req.body);
            std::string target_user = j.at("username").get<std::string>();
            std::string new_email = j.at("email").get<std::string>();
            std::string new_display = j.at("displayName").get<std::string>();
            std::string new_first = j.at("firstName").get<std::string>();
            std::string new_last = j.at("lastName").get<std::string>();
            
            // Check if a new password was typed
            std::string new_pass = "";
            if (j.contains("password") && !j.at("password").get<std::string>().empty()) {
                new_pass = j.at("password").get<std::string>();
            }

            std::string admin_user = std::getenv("LLDAP_ADMIN_USER") ? std::getenv("LLDAP_ADMIN_USER") : "admin";
            std::string admin_pass = std::getenv("LLDAP_ADMIN_PASS") ? std::getenv("LLDAP_ADMIN_PASS") : "";
            httplib::Client lldap("http://osl-identity:17170");

            // Authenticate Core
            json auth_payload = {{"username", admin_user}, {"password", admin_pass}};
            auto auth_res = lldap.Post("/auth/simple/login", auth_payload.dump(), "application/json");
            if (!auth_res || auth_res->status != 200) {
                res.status = 500;
                res.set_content("{\"error\":\"Core failed to auth with Vault.\"}", "application/json");
                return;
            }

            std::string token = json::parse(auth_res->body)["token"];
            httplib::Headers headers = {{"Authorization", "Bearer " + token}};

	    // 1. Send Update Mutation for Text Fields (Corrected Schema Return Type for Cel-Tech-Serv Pty Ltd)
            json update_payload = {
                {"query", "mutation UpdateUser($user: UpdateUserInput!) { updateUser(user: $user) { ok } }"},
                {"variables", {
                    {"user", {
                        {"id", target_user},
                        {"email", new_email},
                        {"displayName", new_display},
                        {"firstName", new_first},
                        {"lastName", new_last}
                    }}
                }}
            };
            
            auto update_res = lldap.Post("/api/graphql", headers, update_payload.dump(), "application/json");
            
            // SENIOR TECH DIAGNOSTIC: Catch sneaky GraphQL errors
            if (update_res) {
                auto reply = json::parse(update_res->body);
                if (reply.contains("errors")) {
                    std::string err_msg = reply["errors"][0]["message"].get<std::string>();
                    res.status = 400;
                    res.set_content("{\"error\":\"Vault Error: " + err_msg + "\"}", "application/json");
                    return;
                }
            }

	    // ---------------------------------------------------------
            // SOVEREIGN ROLE ASSIGNMENT LOGIC (Cel-Tech-Serv Pty Ltd)
            // ---------------------------------------------------------
            // 1. Extract the requested role ID from the frontend JSON payload
            int role_id = 6; // Fail-safe default: Standard User (Group 6)
            if (j.contains("roleId") && !j.at("roleId").get<std::string>().empty()) {
                role_id = std::stoi(j.at("roleId").get<std::string>());
            }

            // 2. Construct the LLDAP GraphQL mutation to assign the group
            // Note: LLDAP strictly requires groupId to be an Int, not a String!
            json group_payload = {
                {"query", "mutation AddUserToGroup($userId: String!, $groupId: Int!) { addUserToGroup(userId: $userId, groupId: $groupId) { ok } }"},
                {"variables", {
                    {"userId", target_user},
                    {"groupId", role_id}
                }}
            };
            
            // 3. Transmit the role assignment to the Identity Vault
            auto group_res = lldap.Post("/api/graphql", headers, group_payload.dump(), "application/json");
            
            // 4. Senior Tech Diagnostic: Catch any schema or assignment errors
            if (group_res) {
                auto group_reply = json::parse(group_res->body);
                if (group_reply.contains("errors")) {
                    std::string err_msg = group_reply["errors"][0]["message"].get<std::string>();
                    res.status = 400;
                    res.set_content("{\"error\":\"Role Assignment Failed: " + err_msg + "\"}", "application/json");
                    return; // Halt and report the failure before sending the 200 OK
                }
            }
            // ---------------------------------------------------------

            // 2. Conditional Password Update
            if (!new_pass.empty()) {
                json pass_payload = {
                    {"query", "mutation { updatePassword(userId: \"" + target_user + "\", password: \"" + new_pass + "\") { ok } }"}
                };
                auto pass_res = lldap.Post("/api/graphql", headers, pass_payload.dump(), "application/json");
                if (pass_res) {
                    auto reply = json::parse(pass_res->body);
                    if (reply.contains("errors")) {
                        std::string err_msg = reply["errors"][0]["message"].get<std::string>();
                        res.status = 400;
                        res.set_content("{\"error\":\"Password Update Failed: " + err_msg + "\"}", "application/json");
                        return;
                    }
                }
            }

            res.status = 200;
            res.set_content("{\"status\":\"SUCCESS\", \"message\":\"Identity Updated Successfully\"}", "application/json");

        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content("{\"error\":\"Payload parsing error in Core.\"}", "application/json");
        }
    });

    // ------------------------------------------------------------------------
    // 5. IDENTITY GATEWAY (GET) - List Active Sovereign Identities
    // ------------------------------------------------------------------------
    svr.Get("/api/auth/me", [&](const httplib::Request &req, httplib::Response &res) {
        // Extract the secure headers injected by the Authelia/Caddy proxy
        std::string current_user = req.get_header_value("Remote-User");
        std::string current_groups = req.get_header_value("Remote-Groups");
        
        // If testing directly without Authelia, provide safe fallbacks
        if (current_user.empty()) current_user = "unknown";
        if (current_groups.empty()) current_groups = "none";

        json response = {
            {"user", current_user},
            {"groups", current_groups}
        };
        
        res.status = 200;
        res.set_content(response.dump(), "application/json");
    });

    svr.Get("/api/users/list", [&](const httplib::Request &req, httplib::Response &res) {
        // Enforce strict access: Only Admins can view the identity list
        if (!is_admin(req)) {
            res.status = 403;
            res.set_content("{\"error\":\"Forbidden: Sovereign Admin Privileges Required.\"}", "application/json");
            return;
        }

        try {
            // Retrieve secure credentials from the Docker environment
            std::string admin_user = std::getenv("LLDAP_ADMIN_USER") ? std::getenv("LLDAP_ADMIN_USER") : "admin";
            std::string admin_pass = std::getenv("LLDAP_ADMIN_PASS") ? std::getenv("LLDAP_ADMIN_PASS") : "";

            // Internal HTTP client talking directly to the LLDAP container
            httplib::Client lldap("http://osl-identity:17170");

            // Authenticate the Core
            json auth_payload = {{"username", admin_user}, {"password", admin_pass}};
            auto auth_res = lldap.Post("/auth/simple/login", auth_payload.dump(), "application/json");

            if (!auth_res || auth_res->status != 200) {
                res.status = 500;
                res.set_content("{\"error\":\"Core failed to authenticate with the Identity Vault.\"}", "application/json");
                return;
            }

            // Extract token and set headers
            std::string token = json::parse(auth_res->body)["token"];
            httplib::Headers headers = {{"Authorization", "Bearer " + token}};

	    // Updated GraphQL Query to include group membership for 'User Type'
            json query_payload = {
                {"query", "query { users { id email displayName firstName lastName groups { id displayName } } }"}
            };
            
            auto query_res = lldap.Post("/api/graphql", headers, query_payload.dump(), "application/json");

            // Pass the LLDAP JSON response directly back to the Javascript UI
            res.status = 200;
            res.set_content(query_res->body, "application/json");

        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content("{\"error\":\"Failed to fetch identities from the Vault.\"}", "application/json");
        }
    });

    // 6. SOVEREIGN LOGOUT ACTION
    svr.Get("/logout", [&](const httplib::Request &req, httplib::Response &res) {
        // Uses the base_domain variable defined at the top of main()
        std::string target_url = "https://" + base_domain;
        std::string encoded_target = "https%3A%2F%2F" + base_domain;
        
        // Redirect straight to Authelia's secure session destruction endpoint
        std::string auth_logout_url = "https://auth." + base_domain + "/logout?rd=" + encoded_target;
        res.set_redirect(auth_logout_url);
    });

    // --- STATIC ASSET MOUNTS ---
    // Expose the agnostic CSS and JS files to the browser
    svr.set_mount_point("/js", "/app/www/js");
    svr.set_mount_point("/css", "/app/www/css");

    int listen_port = std::getenv("OSL_PORT") ? std::stoi(std::getenv("OSL_PORT")) : 8080;
    svr.listen("0.0.0.0", listen_port);
    
    return 0;
}

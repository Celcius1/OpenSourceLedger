/**
 * ============================================================================
 * SOFTWARE: OSL: Sovereign Accounting Suite - Core Engine
 * AUTHOR & COPYRIGHT: Cel-Tech-Serv Pty Ltd
 * MODULE: main.cpp
 * ============================================================================
 * DESCRIPTION:
 * The primary entry point for the OSL Core. Handles Hybrid Auth (SSO/Local) 
 * and acts as the Microkernel Hub via the Plugin Manager.
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
// --- OSL PLUGIN SYSTEM INJECTION ---
#include "../plugins/interface/PluginManager.hpp" 

using json = nlohmann::json;

// --- CONFIGURATION ---
const std::string BACKUP_USER = std::getenv("OSL_BACKUP_USER") ? std::getenv("OSL_BACKUP_USER") : "admin";
const std::string BACKUP_PASS = std::getenv("OSL_BACKUP_PASS") ? std::getenv("OSL_BACKUP_PASS") : "password";
// Dynamically load the session secret for secure cookie generation
const std::string SESSION_SECRET = std::getenv("OSL_SESSION_SECRET") ? std::getenv("OSL_SESSION_SECRET") : "change_this_default_secret_immediately";

// Helper: Format Money (Australian English Formatting)
std::string format_money(long long micros) {
    long long dollars = micros / 1000000;
    long long cents = (micros % 1000000) / 10000;
    return "$" + std::to_string(dollars) + "." + (cents < 10 ? "0" : "") + std::to_string(cents);
}

// Helper: Load decoupled login page and inject error messages
std::string serve_login_page(std::string error_msg = "") {
    std::ifstream file("/web/login.html");
    if (!file.is_open()) return "OSL Core Error: /web/login.html missing. Check volume mounts.";
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string html = buffer.str();
    
    // Inject the error message if one exists
    size_t pos = html.find("{{ERROR_MSG}}");
    if (pos != std::string::npos) {
        html.replace(pos, 13, error_msg);
    }
    return html;
}

int main() {
    const char* env_domain = std::getenv("OSL_BASE_DOMAIN");
    if (!env_domain) {
        std::cerr << "[FATAL] OSL_BASE_DOMAIN environment variable missing. Cel-Tech-Serv core halted." << std::endl;
        return 1; // Refuse to boot without proper configuration
    }
    const std::string BASE_DOMAIN = env_domain;

    // 1. Initialise the Plugin Manager (Cel-Tech-Serv Pty Ltd Hub)
    osl::plugins::PluginManager plugin_manager;

    // 2. Register Sovereign Invoicing Plugin
    osl::plugins::PluginDefinition invoicing_plugin = {
        "au.net.osl.invoicing",
        "Sovereign Invoicing",
        "http://osl-invoicing:8081", 
        "1.0.0",
        {"READ_LEDGER", "WRITE_LEDGER"},
        true
    };
    plugin_manager.RegisterPlugin(invoicing_plugin);

    // DB Connection - Dynamically loaded for Cel-Tech-Serv Pty Ltd environments
    const char* env_db = std::getenv("OSL_DB_CONN");
    if (!env_db) {
        std::cerr << "[FATAL] OSL_DB_CONN environment variable missing. Vault access denied. Core halted." << std::endl;
        return 1;
    }
    std::string conn_str = env_db;

    // This boots the web server engine for the microkernel
    httplib::Server svr;
    std::cout << "[OSL] Cel-Tech-Serv Hub: Hybrid Auth & Plugin System Active." << std::endl;

   // --- SOVEREIGN LOGGER MIDDLEWARE ---
    // Log every request to the console for Cel-Tech-Serv auditing
    svr.set_logger([](const httplib::Request &req, const httplib::Response &res) {
        std::cout << "[HUB] " << req.method << " " << req.path 
                  << " -> Status: " << res.status << " (User: " 
                  << (req.has_header("Remote-User") ? req.get_header_value("Remote-User") : "Local/Backup") 
                  << ")" << std::endl;
    });

    // --- GATEKEEPER MIDDLEWARE ---
    auto is_authenticated = [&](const httplib::Request &req) -> bool {
        // Primary: Authelia Headers (Forwarded by Caddy)
        if (req.has_header("Remote-User")) return true;

        // Fallback: Local Cookie
        if (req.has_header("Cookie")) {
            std::string cookies = req.get_header_value("Cookie");
            if (cookies.find("OSL_SESSION=" + SESSION_SECRET) != std::string::npos) return true;
        }
        return false;
    };

    // --- ROUTES ---

    // 1. DASHBOARD (Root Path) - Decoupled Frontend
    svr.Get("/", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) {
            std::cout << "[AUTH] Unauthorized Access Attempt. Redirecting to Login." << std::endl;
            res.set_redirect("/login");
            return;
        }

        // Attempt to load the external UI file
        std::ifstream file("/web/index.html");
        if (!file.is_open()) {
            res.status = 500;
            res.set_content("OSL Core Error: UI template missing. Cel-Tech-Serv Pty Ltd system halted.", "text/plain");
            return;
        }

        // Read the file into a string
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string html = buffer.str();

        // Dynamically inject the user's name into the HTML before sending it
        std::string user = req.has_header("Remote-User") ? req.get_header_value("Remote-User") : "Backup Admin";
        size_t pos = html.find("{{USERNAME}}");
        if (pos != std::string::npos) {
            html.replace(pos, 12, user);
        }

        res.set_content(html, "text/html");
    });

    // 1b. FULL-CHAIN SOVEREIGN AUDIT API (GET)
    svr.Get("/api/ledger/data", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;

        try {
            pqxx::connection C(conn_str);
            pqxx::work W(C);
            // We sort by ID ASC to verify the chain from the beginning
            pqxx::result R = W.exec("SELECT id, to_char(transaction_date, 'DD/MM/YYYY'), description, debit_micros, credit_micros, balance_micros, category, sub_category, status, row_hash FROM ledger ORDER BY id ASC");

            json ledger_json = json::array();
            std::string expected_prev_hash = "GENESIS"; // The start of the Cel-Tech-Serv chain

            for (auto row : R) {
                std::string desc = row[2].as<std::string>();
                long long debit = row[3].as<long long>();
                long long credit = row[4].as<long long>();
                long long balance = row[5].as<long long>();
                std::string cat = row[6].is_null() ? "" : row[6].as<std::string>();
                std::string sub = row[7].is_null() ? "" : row[7].as<std::string>();
                std::string stored_hash = row[9].as<std::string>();

                // RECALCULATE: Now includes the hash of the PREVIOUS row
                std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(balance) + cat + sub + expected_prev_hash;
                std::string recalc_hash = osl::OSLCrypto::generate_sha256(raw_data);

                bool integrity_ok = (recalc_hash == stored_hash);
                
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
                    {"audit_passed", integrity_ok}
                });

                // Set the expectation for the NEXT row in the chain
                expected_prev_hash = stored_hash;
            }
            
            // Reverse the list before sending to UI so newest is on top
            std::reverse(ledger_json.begin(), ledger_json.end());
            res.set_content(ledger_json.dump(), "application/json");
        } catch (const std::exception &e) {
            std::cerr << "[AUDIT FATAL] " << e.what() << std::endl;
            res.status = 500;
        }
    });

    // 1c. BANK-ALIGNED MANUAL ENTRY (POST) - Syntax Correction
    svr.Post("/api/ledger/add", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;

        try {
            // FIX: Use double colon for the static parse method
            auto j = json::parse(req.body);
            
            // Extract values using explicit casting to avoid template ambiguity
            std::string desc = j.at("description").get<std::string>();
            long long debit = j.at("debit").get<long long>();
            long long credit = j.at("credit").get<long long>();
            std::string cat = j.at("category").get<std::string>();
            std::string sub = j.at("subcategory").get<std::string>();

            pqxx::connection C(conn_str);
            pqxx::work W(C);

            // Fetch last balance and last hash to maintain the Sovereign Audit Chain
            pqxx::result last_row = W.exec("SELECT balance_micros, row_hash FROM ledger ORDER BY id DESC LIMIT 1");
            long long prev_balance = last_row.empty() ? 0 : last_row[0][0].as<long long>();
            std::string prev_hash = last_row.empty() ? "GENESIS" : last_row[0][1].as<std::string>();

            long long new_balance = prev_balance - debit + credit;

            // Generate the cryptographic link for the audit trail
            std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(new_balance) + cat + sub + prev_hash;
            std::string current_hash = osl::OSLCrypto::generate_sha256(raw_data);

            // Use modern exec to avoid deprecation warnings
            W.exec("INSERT INTO ledger (description, debit_micros, credit_micros, balance_micros, category, sub_category, row_hash) VALUES (" +
                   W.quote(desc) + ", " + std::to_string(debit) + ", " + std::to_string(credit) + ", " + 
                   std::to_string(new_balance) + ", " + W.quote(cat) + ", " + W.quote(sub) + ", " + W.quote(current_hash) + ")");
            
            W.commit();
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) {
            std::cerr << "[AUDIT ERROR] " << e.what() << std::endl;
            res.status = 500;
        }
    });

    // 2. PLUGIN GATEWAY (POST)
    // Used by frontend to route commands to microservices
    svr.Post(R"(/api/plugin/([^/]+)/([^/]+))", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) {
            res.status = 401;
            res.set_content("{\"status\":\"ERROR\",\"message\":\"Unauthorized\"}", "application/json");
            return;
        }

        std::string plugin_id = req.matches[1];
        std::string command = req.matches[2];
        json payload = req.body.empty() ? json::object() : json::parse(req.body);

        json result = plugin_manager.ExecutePluginCommand(plugin_id, command, payload);
        res.set_content(result.dump(), "application/json");
    });

    // 3. PLUGIN MANIFEST API (GET)
    // Allows the decoupled frontend to dynamically load active modules
    svr.Get("/api/plugins/active", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) {
            res.status = 401;
            res.set_content("{\"status\":\"ERROR\",\"message\":\"Unauthorized\"}", "application/json");
            return;
        }

        // Build a JSON array of active plugins for the Sovereign Hub
        // (In the future, this will dynamically pull from plugin_manager)
        json plugins = json::array();
        plugins.push_back({
            {"id", "au.net.osl.invoicing"},
            {"name", "Sovereign Invoicing"},
            {"version", "1.0.0"}
        });
        
        res.set_content(plugins.dump(), "application/json");
    });

    // 4. LOGIN PAGE (GET)
    svr.Get("/login", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(serve_login_page(), "text/html");
    });

    // 5. LOGIN ACTION (POST)
    svr.Post("/login", [&](const httplib::Request &req, httplib::Response &res) {
        if (req.has_param("user") && req.has_param("pass")) {
            if (req.get_param_value("user") == BACKUP_USER && req.get_param_value("pass") == BACKUP_PASS) {
                res.set_header("Set-Cookie", "OSL_SESSION=" + SESSION_SECRET + "; HttpOnly; Path=/; Max-Age=3600");
                res.set_redirect("/");
            } else {
                res.set_content(serve_login_page("Invalid Credentials"), "text/html");
            }
        } else {
            res.set_content(serve_login_page("Missing Fields"), "text/html");
        }
    });

    // 6. LOGOUT ACTION (Clears Local & Redirects SSO)
    // Part of the OSL: Sovereign Accounting Suite security stack
    // Authored by Cel-Tech-Serv Pty Ltd
    svr.Get("/logout", [&](const httplib::Request &req, httplib::Response &res) {
        // Clear the local OSL_SESSION cookie for Cel-Tech-Serv local access
        res.set_header("Set-Cookie", "OSL_SESSION=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0");

        // Construct dynamic domains based on the environment variable
        // This ensures the core remains completely domain-agnostic
        std::string target_url = "https://" + BASE_DOMAIN;
        std::string encoded_target = "https%3A%2F%2F" + BASE_DOMAIN;
        std::string auth_logout_url = "https://auth." + BASE_DOMAIN + "/logout?rd=" + encoded_target;

        // If we detect an Authelia session, redirect to the SSO logout page
        if (req.has_header("Remote-User")) {
            // URL-Encoded target routes the user out of Authelia and onto the base domain
            res.set_redirect(auth_logout_url);
        } else {
            // Standard redirection for backup/local mode directly to the base domain
            res.set_redirect(target_url);
        }
        std::cout << "[AUTH] User logged out of OSL Core. Bouncing to " << BASE_DOMAIN << "." << std::endl;
    });

    // Start Server on internal port dynamically provided by Docker
    int listen_port = std::getenv("OSL_PORT") ? std::stoi(std::getenv("OSL_PORT")) : 8080;
    std::cout << "[OSL] Cel-Tech-Serv Hub engaging on port " << listen_port << "..." << std::endl;
    svr.listen("0.0.0.0", listen_port);
    
    return 0;
}

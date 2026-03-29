/**
 * ============================================================================
 * SOFTWARE: OSL: Accounting Suite - Core Engine
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
#include <dlfcn.h> 
#include "../plugins/interface/osl_plugin.hpp" 
#include "crypto.hpp"
#include "ledger.cpp"
#include "ViewEngine.hpp"
#include <map>
#include "../plugins/interface/PluginManager.hpp" 
#include <deque>
#include <mutex>
#include <chrono>
#include <iomanip>

std::deque<std::string> system_logs;
std::mutex log_mutex;

bool global_debug_mode = false; 

void osl_log(std::string level, std::string message) {
    if (level == "DEBUG" && !global_debug_mode) {
        return; 
    }
    std::lock_guard<std::mutex> lock(log_mutex);
    if (system_logs.size() >= 200) system_logs.pop_front();
    
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now), "%H:%M:%S");
    
    std::string log_entry = "[" + ss.str() + "] [" + level + "] " + message;
    system_logs.push_back(log_entry);
    std::cout << log_entry << std::endl;
}

using json = nlohmann::json;

std::string format_money(long long micros) {
    long long dollars = micros / 1000000;
    long long cents = (micros % 1000000) / 10000;
    return "$" + std::to_string(dollars) + "." + (cents < 10 ? "0" : "") + std::to_string(cents);
}

bool is_admin(const httplib::Request &req) {
    if (req.has_header("Remote-Groups")) {
        std::string groups = req.get_header_value("Remote-Groups");
        return groups.find("admins") != std::string::npos;
    }
    return false;
}

int main() {
    const char* env_db = std::getenv("OSL_DB_CONN");
    if (!env_db) {
        osl_log("FATAL", "Database connection variable missing. System halted.");
        return 1;
    }
    std::string conn_str = env_db;
    pqxx::connection C(conn_str); 

    const char* env_domain = std::getenv("OSL_BASE_DOMAIN");
    std::string base_domain = env_domain ? env_domain : "osl.net.au";

    // === [SECTION: PLUGIN INITIALIZATION & DYNAMIC BOOTLOADER] ===
    osl::plugins::PluginManager plugin_manager; 
    std::vector<osl::IOSLPlugin*> native_plugins;
        
    std::string global_business_name = "OSL Sovereign Suite (Unconfigured)";
    int seal_grace_period_minutes = 15; 
    const int MAX_GRACE_PERIOD_MINUTES = 120; 

    std::ifstream config_file("/app/core/config/osl_config.json");
    if (config_file.is_open()) {
        try {
            json config = json::parse(config_file);
            if (config.contains("core")) {
                if (config["core"].contains("entity_name")) global_business_name = config["core"]["entity_name"].get<std::string>();
                if (config["core"].contains("debug_mode")) {
                    global_debug_mode = config["core"]["debug_mode"].get<bool>();
                    if (global_debug_mode) osl_log("WARN", "OSL Engine starting in DEBUG mode. Expect high log verbosity.");
                }
                if (config["core"].contains("seal_grace_period_minutes")) {
                    int requested_grace = config["core"]["seal_grace_period_minutes"];
                    seal_grace_period_minutes = (requested_grace > MAX_GRACE_PERIOD_MINUTES) ? MAX_GRACE_PERIOD_MINUTES : (requested_grace < 0 ? 0 : requested_grace);
                }
            }

            if (config.contains("plugins")) {
                for (auto& [id, details] : config["plugins"].items()) {
                    if (details.value("status", "") == "active") {
                        std::string path = details.value("path", "");
                        if (!path.empty() && path.find(".so") != std::string::npos) {
                            void* handle = dlopen(path.c_str(), RTLD_NOW);
                            if (!handle) continue;
                            
                            typedef osl::IOSLPlugin* (*create_plugin_t)();
                            create_plugin_t create_plugin = (create_plugin_t) dlsym(handle, "create_plugin");
                            
                            if (dlerror()) { dlclose(handle); continue; }
                            
                            osl::IOSLPlugin* instance = create_plugin();
                            osl_log("INFO", "Successfully Loaded Native Module: " + instance->get_plugin_name());
                            
                            native_plugins.push_back(instance);
                            osl::plugins::PluginDefinition def;
                            def.id = id;
                            def.name = details.value("description", id);
                            def.is_active = true;
                            def.native_instance = instance; 
                            plugin_manager.RegisterPlugin(def);

                            // Trigger plugin DB setup FIRST so constraints work later
                            json init_res = instance->execute("init_sub_db", {});
                            if (init_res.value("status", "") == "success") {
                                osl_log("INFO", "Plugin DB: " + init_res.value("message", "Ready"));
                            }
                        }
                    }
                }
            }
        } catch (const std::exception &e) {
            osl_log("ERROR", "Bootloader failed to parse config JSON: " + std::string(e.what()));
        }
    }

    // === [CORE DATABASE BOOTSTRAP] ===
    // Secure the core ledger by binding it to the Landlord plugin's entities.
    try {
        pqxx::work W(C);
        W.exec(R"(
            CREATE TABLE IF NOT EXISTS ledger (
                id SERIAL PRIMARY KEY,
                transaction_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                description TEXT NOT NULL,
                debit_micros BIGINT DEFAULT 0,
                credit_micros BIGINT DEFAULT 0,
                balance_micros BIGINT DEFAULT 0,
                category TEXT,
                sub_category TEXT,
                division_id VARCHAR(50) REFERENCES landlord_entities(entity_id) ON DELETE RESTRICT,
                status TEXT DEFAULT 'CLEARED',
                row_hash TEXT NOT NULL
            );
        )");
        W.commit();
        osl_log("INFO", "Core Ledger Database Schema Verified.");
    } catch (const std::exception &e) {
        osl_log("ERROR", "Failed to verify Core Ledger Schema: " + std::string(e.what()));
    }

    osl_log("INFO", "Ledger sealing grace period locked at " + std::to_string(seal_grace_period_minutes) + " minutes.");

    httplib::Server svr;
    osl_log("INFO", "OSL Accounting Suite: Engine Active.");

    svr.set_logger([](const httplib::Request &req, const httplib::Response &res) {
        std::string log_msg = "API Request: " + req.method + " " + req.path + " -> Status " + std::to_string(res.status);
        osl_log("INFO", log_msg);
    });

    auto is_authenticated = [&](const httplib::Request &req) -> bool {
        return req.has_header("Remote-User") && !req.get_header_value("Remote-User").empty();
    };

    // === [UI RENDERER & AGNOSTIC INJECTION] ===
    svr.Get("/", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) {
            res.status = 401;
            res.set_content("401 Unauthorized - Secure Gateway Login Required", "text/plain");
            return;
        }
        
        std::map<std::string, std::string> ui_context;
        ui_context["BUSINESS_NAME"] = global_business_name; 
        ui_context["USERNAME"] = req.has_header("Remote-User") ? req.get_header_value("Remote-User") : "Local User"; 

        std::string plugin_ui_html = "";
        std::string plugin_ui_js = "<script>";
        std::string user_mgmt_ui = ""; 
        
        for (auto* plugin : native_plugins) {
            json ui_payload = plugin->execute("get_ui_extensions", {});
            if (ui_payload.contains("html")) plugin_ui_html += ui_payload["html"].get<std::string>();
            if (ui_payload.contains("js")) plugin_ui_js += ui_payload["js"].get<std::string>();

            json user_ui_payload = plugin->execute("get_user_management_ui", {});
            if (user_ui_payload.contains("html")) user_mgmt_ui += user_ui_payload["html"].get<std::string>();
        }
        plugin_ui_js += "</script>";

        ui_context["PLUGIN_HOOKS"] = plugin_ui_html + plugin_ui_js;
        ui_context["USER_MANAGEMENT_HOOK"] = user_mgmt_ui; 
        ui_context["SIDEBAR_HOOKS"] = "";
        ui_context["HEADER_HOOKS"] = "";
        ui_context["DYNAMIC_HEADERS"] = "<th class='py-3'>Date</th><th class='py-3'>Description</th><th class='py-3 text-right'>Balance</th>";
        ui_context["DYNAMIC_ROW_DATA"] = "<td class='py-4'>Loading data...</td>";

        std::string final_html = ViewEngine::render_template("/app/core/templates/base.html", ui_context);
        res.status = 200;
        res.set_content(final_html, "text/html");
    });

    // === [HISTORICAL ARCHIVES] ===
    svr.Get("/api/archives/list", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        try {
            pqxx::connection C(conn_str);
            pqxx::work W(C);
            pqxx::result R = W.exec("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'ledger_archive_%' ORDER BY table_name DESC");
            
            json archives = json::array();
            for (auto row : R) archives.push_back(row[0].as<std::string>());
            res.set_content(archives.dump(), "application/json");
        } catch (const std::exception &e) { res.status = 500; }
    });

    svr.Get(R"(/api/archives/data/([^/]+))", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        std::string table_name = req.matches[1];
        try {
            pqxx::connection C(conn_str);
            pqxx::work W(C);
            std::string query = "SELECT id, to_char(transaction_date, 'DD/MM/YYYY'), description, debit_micros, credit_micros, balance_micros, category, sub_category, status, row_hash, COALESCE(division_id, 'global') FROM " + table_name + " ORDER BY id ASC";
            pqxx::result R = W.exec(query);
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
                std::string div_id = row[10].as<std::string>(); 

                std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(balance) + cat + sub + div_id + expected_prev_hash;
                std::string recalc_hash = osl::OSLCrypto::generate_sha256(raw_data);

                ledger_json.push_back({
                    {"id", row[0].as<int>()}, {"date", row[1].as<std::string>()}, {"description", desc},
                    {"debit", format_money(debit)}, {"credit", format_money(credit)}, {"balance", format_money(balance)},
                    {"category", cat}, {"subcategory", sub}, {"division", div_id},
                    {"status", row[8].as<std::string>()}, {"audit_passed", (recalc_hash == stored_hash)}
                });
                expected_prev_hash = stored_hash;
            }
            std::reverse(ledger_json.begin(), ledger_json.end());
            res.set_content(ledger_json.dump(), "application/json");
        } catch (const std::exception &e) { res.status = 500; }
    });

    // === [FETCH LEDGER DATA] ===
    svr.Get("/api/ledger/data", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            pqxx::connection C(conn_str);
            pqxx::work W(C);
            pqxx::result R = W.exec("SELECT id, to_char(transaction_date, 'DD/MM/YYYY'), description, debit_micros, credit_micros, balance_micros, category, sub_category, status, row_hash, COALESCE(division_id, 'global'), EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - transaction_date)) FROM ledger ORDER BY id ASC");
            json ledger_json = json::array();
            std::string expected_prev_hash = "GENESIS"; 

            for (auto row : R) {
                std::string desc = row[2].as<std::string>();
                long long debit = row[3].as<long long>();
                long long credit = row[4].as<long long>();
                long long balance = row[5].as<long long>();
                std::string cat = row[6].is_null() ? "" : row[6].as<std::string>();
                std::string stored_hash = row[9].as<std::string>();
                std::string div_id = row[10].as<std::string>(); 
                double age_seconds = row[11].as<double>();

                std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(balance) + cat + div_id + expected_prev_hash;
                std::string recalc_hash = osl::OSLCrypto::generate_sha256(raw_data);

                ledger_json.push_back({
                    {"id", row[0].as<int>()}, {"date", row[1].as<std::string>()}, {"description", desc},
                    {"debit", format_money(debit)}, {"credit", format_money(credit)}, {"balance", format_money(balance)},
                    {"category", cat}, {"division", div_id},
                    {"audit_passed", (recalc_hash == stored_hash)}, {"is_editable", (age_seconds < (seal_grace_period_minutes * 60))} 
                });
                expected_prev_hash = stored_hash;
            }
            std::reverse(ledger_json.begin(), ledger_json.end());
            res.set_content(ledger_json.dump(), "application/json");
        } catch (const std::exception &e) {
            osl_log("ERROR", "Data Fetch Failed: " + std::string(e.what()));
            res.status = 500;
        }
    });

    // === [LEDGER RESYNC ENGINE] ===
    svr.Post("/api/ledger/resync", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            pqxx::connection C(conn_str); pqxx::work W(C);
            pqxx::result chain = W.exec("SELECT id, description, debit_micros, credit_micros, category, sub_category, division_id FROM ledger ORDER BY id ASC");
            long long running_bal = 0; std::string last_hash = "GENESIS";
            for (auto row : chain) {
                int c_id = row[0].as<int>();
                running_bal = running_bal - row[2].as<long long>() + row[3].as<long long>();
                std::string raw = row[1].as<std::string>() + row[2].as<std::string>() + row[3].as<std::string>() + std::to_string(running_bal) + (row[4].is_null() ? "" : row[4].as<std::string>()) + (row[5].is_null() ? "" : row[5].as<std::string>()) + (row[6].is_null() ? "global" : row[6].as<std::string>()) + last_hash;
                last_hash = osl::OSLCrypto::generate_sha256(raw);
                W.exec("UPDATE ledger SET balance_micros = " + std::to_string(running_bal) + ", row_hash = " + W.quote(last_hash) + " WHERE id = " + std::to_string(c_id));
            }
            W.commit();
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) { res.status = 500; }
    });

    // === [EDIT TRANSACTION & CASCADING HASH] ===
    svr.Post("/api/ledger/edit", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            auto j = json::parse(req.body);
            int tx_id = j.at("id").get<int>();
            std::string desc = j.at("description").get<std::string>();
            long long new_debit = j.at("debit").get<long long>();
            long long new_credit = j.at("credit").get<long long>();
            std::string cat = j.at("category").get<std::string>();
            std::string sub = j.at("subcategory").get<std::string>();
            std::string div_id = j.contains("division") ? j.at("division").get<std::string>() : "global";

            pqxx::connection C(conn_str); pqxx::work W(C);

            pqxx::result check = W.exec("SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - transaction_date)) FROM ledger WHERE id = " + std::to_string(tx_id));
            if (check.empty() || check[0][0].as<double>() > (seal_grace_period_minutes * 60)) {
                res.status = 403; res.set_content("{\"error\":\"Grace period expired. Record is locked.\"}", "application/json"); return;
            }

            W.exec("UPDATE ledger SET description = " + W.quote(desc) + ", debit_micros = " + std::to_string(new_debit) + ", credit_micros = " + std::to_string(new_credit) + ", category = " + W.quote(cat) + ", sub_category = " + W.quote(sub) + ", division_id = " + W.quote(div_id) + " WHERE id = " + std::to_string(tx_id));

            pqxx::result chain = W.exec("SELECT id, description, debit_micros, credit_micros, category, sub_category, division_id FROM ledger WHERE id >= " + std::to_string(tx_id) + " ORDER BY id ASC");
            pqxx::result prev_rec = W.exec("SELECT balance_micros, row_hash FROM ledger WHERE id < " + std::to_string(tx_id) + " ORDER BY id DESC LIMIT 1");
            long long running_bal = prev_rec.empty() ? 0 : prev_rec[0][0].as<long long>();
            std::string last_hash = prev_rec.empty() ? "GENESIS" : prev_rec[0][1].as<std::string>();

            for (auto row : chain) {
                int c_id = row[0].as<int>();
                running_bal = running_bal - row[2].as<long long>() + row[3].as<long long>();
                std::string raw = row[1].as<std::string>() + row[2].as<std::string>() + row[3].as<std::string>() + std::to_string(running_bal) + (row[4].is_null() ? "" : row[4].as<std::string>()) + (row[5].is_null() ? "" : row[5].as<std::string>()) + (row[6].is_null() ? "global" : row[6].as<std::string>()) + last_hash;
                last_hash = osl::OSLCrypto::generate_sha256(raw);
                W.exec("UPDATE ledger SET balance_micros = " + std::to_string(running_bal) + ", row_hash = " + W.quote(last_hash) + " WHERE id = " + std::to_string(c_id));
            }

            W.commit();
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) { res.status = 500; }
    });

    // === [ADD TRANSACTION TO LEDGER] ===
    svr.Post("/api/ledger/add", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            auto j = json::parse(req.body);
            osl::LedgerLine base_line;
            base_line.description = j.at("description").get<std::string>();
            base_line.debit = j.at("debit").get<long long>();
            base_line.credit = j.at("credit").get<long long>();
            base_line.account_code = j.at("category").get<std::string>(); 
            std::string sub = j.at("subcategory").get<std::string>();
            std::string div_id = j.contains("division") ? j.at("division").get<std::string>() : "global"; 

            std::vector<osl::LedgerLine> transaction;
            transaction.push_back(base_line);

            for (auto* plugin : native_plugins) plugin->pre_commit_hook(transaction);

            pqxx::connection C(conn_str); pqxx::work W(C);

            pqxx::result last_row = W.exec("SELECT balance_micros, row_hash FROM ledger ORDER BY id DESC LIMIT 1");
            long long running_balance = last_row.empty() ? 0 : last_row[0][0].as<long long>();
            std::string prev_hash = last_row.empty() ? "GENESIS" : last_row[0][1].as<std::string>();

            for (const auto& line : transaction) {
                running_balance = running_balance - line.debit + line.credit;
                std::string raw_data = line.description + std::to_string(line.debit) + std::to_string(line.credit) + std::to_string(running_balance) + line.account_code + sub + div_id + prev_hash;
                std::string current_hash = osl::OSLCrypto::generate_sha256(raw_data);

                W.exec("INSERT INTO ledger (description, debit_micros, credit_micros, balance_micros, category, sub_category, division_id, row_hash) VALUES (" +
                       W.quote(line.description) + ", " + std::to_string(line.debit) + ", " + std::to_string(line.credit) + ", " + 
                       std::to_string(running_balance) + ", " + W.quote(line.account_code) + ", " + W.quote(sub) + ", " + W.quote(div_id) + ", " + W.quote(current_hash) + ")");
                prev_hash = current_hash; 
            }
            
            W.commit();
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) { res.status = 500; }
    });
    
    // === [PLUGIN API ROUTES] ===
    svr.Post(R"(/api/plugin/([^/]+)/([^/]+))", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        std::string plugin_id = req.matches[1];
        std::string command = req.matches[2];
        
        json payload;
        try { payload = req.body.empty() ? json::object() : json::parse(req.body); } catch (...) { payload = json::object(); }
        
        payload["user_id"] = req.has_header("Remote-User") ? req.get_header_value("Remote-User") : "unknown";
        payload["user_groups"] = req.has_header("Remote-Groups") ? req.get_header_value("Remote-Groups") : "";
        
        json result = plugin_manager.ExecutePluginCommand(plugin_id, command, payload);
        res.set_content(result.dump(), "application/json");
    });

    svr.Get("/api/plugins/active", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        json active_plugins = json::array();
        std::ifstream ifs("/app/core/config/osl_config.json");
        if (ifs.is_open()) {
            try {
                json config = json::parse(ifs);
                if (config.contains("plugins")) {
                    for (auto& [id, details] : config["plugins"].items()) {
                        if (details.value("status", "") == "active") {
                            active_plugins.push_back({ {"id", id}, {"name", details.value("description", id)}, {"path", details.value("path", "unknown")} });
                        }
                    }
                }
            } catch (...) { }
        }
        res.set_content(active_plugins.dump(), "application/json");
    });

    // === [AUTH & SYSTEM ROUTES] ===
    svr.Get("/api/auth/me", [&](const httplib::Request &req, httplib::Response &res) {
        std::string current_user = req.get_header_value("Remote-User");
        std::string current_groups = req.get_header_value("Remote-Groups");
        if (current_user.empty()) current_user = "unknown";
        if (current_groups.empty()) current_groups = "none";
        json response = { {"user", current_user}, {"groups", current_groups} };
        res.status = 200; res.set_content(response.dump(), "application/json");
    });

    svr.Get("/logout", [&](const httplib::Request &req, httplib::Response &res) {
        std::string target_url = "https://" + base_domain;
        std::string encoded_target = "https%3A%2F%2F" + base_domain;
        std::string auth_logout_url = "https://auth." + base_domain + "/logout?rd=" + encoded_target;
        res.set_redirect(auth_logout_url);
    });

    // === [SETTINGS & CONFIG ROUTES] ===
    svr.Get("/api/settings/manifest", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        std::ifstream ifs("/app/core/config/osl_config.json");
        if (ifs.is_open()) {
            try { res.set_content(json::parse(ifs).dump(), "application/json"); } 
            catch (...) { res.status = 500; res.set_content("{\"error\":\"Config corrupt.\"}", "application/json"); }
        } else {
            json fallback; fallback["core"]["entity_name"] = "Cel-Tech-Serv Pty Ltd (Default)"; fallback["core"]["divisions"] = json::array();
            res.set_content(fallback.dump(), "application/json");
        }
    });

    svr.Get("/api/system/logs", [&](const httplib::Request &req, httplib::Response &res) {
        std::string groups = req.has_header("Remote-Groups") ? req.get_header_value("Remote-Groups") : "";
        if (groups.find("admins") == std::string::npos) { res.status = 403; return; }
        json response; { std::lock_guard<std::mutex> lock(log_mutex); response["logs"] = system_logs; }
        res.set_content(response.dump(), "application/json");
    });

    svr.Post("/api/ledger/purge", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_admin(req)) { res.status = 403; return; }
        try {
            auto j = json::parse(req.body);
            std::string confirm = j.at("confirmation").get<std::string>();
            if (confirm == "PURGE DATA") {
                osl_log("CRITICAL", "User " + req.get_header_value("Remote-User") + " executed ledger data purge.");
                res.status = 200; res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
            } else { res.status = 400; }
        } catch (...) { res.status = 400; }
    });

    svr.Post("/api/settings/save", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_admin(req)) { res.status = 403; return; }
        try {
            auto new_config = json::parse(req.body);
            std::ofstream ofs("/app/core/config/osl_config.json");
            if (ofs.is_open()) {
                ofs << new_config.dump(4); ofs.close();
                res.status = 200; res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
            } else { res.status = 500; }
        } catch (...) { res.status = 400; }
    });

    svr.Get("/api/user/prefs", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        std::string current_user = req.get_header_value("Remote-User");
        std::ifstream ifs("/app/core/config/user_prefs.json");
        json user_prefs;
        if (ifs.is_open()) {
            try { json all_prefs = json::parse(ifs); if (all_prefs.contains(current_user)) user_prefs = all_prefs[current_user]; } catch (...) { }
        }
        if (!user_prefs.contains("theme")) user_prefs["theme"] = "dark";
        res.set_content(user_prefs.dump(), "application/json");
    });

    svr.Post("/api/user/prefs", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        std::string current_user = req.get_header_value("Remote-User");
        std::string prefs_path = "/app/core/config/user_prefs.json";
        json all_prefs; std::ifstream ifs(prefs_path);
        if (ifs.is_open()) { try { all_prefs = json::parse(ifs); } catch (...) {} ifs.close(); }
        try {
            auto incoming_prefs = json::parse(req.body);
            all_prefs[current_user] = incoming_prefs;
            std::ofstream ofs(prefs_path); ofs << all_prefs.dump(4);
            res.status = 200; res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (...) { res.status = 400; }
    });

    svr.set_mount_point("/js", "/app/www/js");
    svr.set_mount_point("/css", "/app/www/css");

    int listen_port = std::getenv("OSL_PORT") ? std::stoi(std::getenv("OSL_PORT")) : 8080;
    osl_log("INFO", "OSL Server running on port " + std::to_string(listen_port));
    svr.listen("0.0.0.0", listen_port);
    
    return 0;
}
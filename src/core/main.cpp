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

void osl_log(std::string level, std::string message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (system_logs.size() >= 200) {
        system_logs.pop_front();
    }
    
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

// === [SEARCH: NATIVE LDAP PASSWORD INJECTOR] ===
// Bypasses GraphQL to securely inject passwords directly into the LLDAP directory.
// Output is captured via POSIX pipe to ensure LDAP errors are logged by the Sovereign Engine.
bool set_lldap_password(const std::string& admin_user, const std::string& admin_pass, const std::string& target_user, const std::string& new_pass) {
    auto escape = [](const std::string& str) {
        std::string res = "'";
        for (char c : str) {
            if (c == '\'') res += "'\\''";
            else res += c;
        }
        res += "'";
        return res;
    };

    std::string base_dn = "dc=osl,dc=net,dc=au";
    std::string admin_dn = "uid=" + admin_user + ",ou=people," + base_dn;
    std::string target_dn = "uid=" + target_user + ",ou=people," + base_dn;

    // Notice we removed > /dev/null and added 2>&1 to pipe STDERR into STDOUT
    std::string cmd = "ldappasswd -x -H ldap://osl-identity:3890 -D " + escape(admin_dn) + 
                      " -w " + escape(admin_pass) + " -s " + escape(new_pass) + 
                      " " + escape(target_dn) + " 2>&1";
                      
    std::array<char, 128> buffer;
    std::string result;
    
    // Open a read pipe to execute the command and capture the output
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        osl_log("ERROR", "ldappasswd pipe creation failed. Cannot execute command.");
        return false;
    }
    
    // Read the piped output stream
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    
    // Close the pipe and grab the exit status
    int ret = pclose(pipe);
    int exit_code = WEXITSTATUS(ret);
    
    // Clean up trailing newlines for clean log formatting
    if (!result.empty() && result.back() == '\n') result.pop_back();

    if (exit_code != 0) {
        osl_log("ERROR", "ldappasswd execution failed (Code " + std::to_string(exit_code) + "): " + result);
        return false;
    }
    
    return true;
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

    osl::plugins::PluginManager plugin_manager;

    osl::plugins::PluginDefinition invoicing_plugin = {
        "au.net.osl.invoicing",
        "OSL Invoicing",
        "http://osl-invoicing:8081", 
        "1.0.0",
        {"READ_LEDGER", "WRITE_LEDGER"},
        true
    };
    plugin_manager.RegisterPlugin(invoicing_plugin);

    httplib::Server svr;
    osl_log("INFO", "OSL Accounting Suite: Engine Active.");

    svr.set_logger([](const httplib::Request &req, const httplib::Response &res) {
        std::string log_msg = "API Request: " + req.method + " " + req.path + " -> Status " + std::to_string(res.status);
        osl_log("INFO", log_msg);
    });

    auto is_authenticated = [&](const httplib::Request &req) -> bool {
        return req.has_header("Remote-User") && !req.get_header_value("Remote-User").empty();
    };

    // === [SEARCH: UI RENDERER] ===
    svr.Get("/", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) {
            res.status = 401;
            res.set_content("401 Unauthorized - Secure Gateway Login Required", "text/plain");
            return;
        }
        
        std::map<std::string, std::string> ui_context;
        ui_context["BUSINESS_NAME"] = "Cel-Tech-Serv Pty Ltd";
        
        std::string user = req.has_header("Remote-User") ? req.get_header_value("Remote-User") : "Local User";
        ui_context["USERNAME"] = user; 

        ui_context["SIDEBAR_HOOKS"] = "";
        ui_context["HEADER_HOOKS"] = "";
        ui_context["DYNAMIC_HEADERS"] = "<th class='py-3'>Date</th><th class='py-3'>Description</th><th class='py-3 text-right'>Balance</th>";
        ui_context["DYNAMIC_ROW_DATA"] = "<td class='py-4'>Loading data...</td>";

        std::string final_html = ViewEngine::render_template("/app/core/templates/base.html", ui_context);

        if (final_html.find("500 Internal Server Error") != std::string::npos) {
            res.status = 500;
            res.set_content("System Error: Failed to render interface.", "text/plain");
            return;
        }

        res.status = 200;
        res.set_content(final_html, "text/html");
    });

    // === [SEARCH: HISTORICAL ARCHIVES] ===
    // 1. List all EOFY Archive Tables
    svr.Get("/api/archives/list", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        try {
            pqxx::connection C(conn_str);
            pqxx::work W(C);
            // Scan PostgreSQL for tables starting with our specific archive prefix
            pqxx::result R = W.exec("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'ledger_archive_%' ORDER BY table_name DESC");
            
            json archives = json::array();
            for (auto row : R) {
                archives.push_back(row[0].as<std::string>());
            }
            res.set_content(archives.dump(), "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
        }
    });

    // 2. Fetch specific EOFY Archive Data
    svr.Get(R"(/api/archives/data/([^/]+))", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        std::string table_name = req.matches[1];
        
        // STRICT SQL INJECTION PREVENTION: Ensure it is an archive table and contains no malicious characters
        if (table_name.find("ledger_archive_") != 0 || table_name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") != std::string::npos) {
            osl_log("WARN", "Malicious or invalid archive fetch attempted: " + table_name);
            res.status = 400;
            res.set_content("{\"error\":\"Invalid archive name.\"}", "application/json");
            return;
        }

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

                // Verify the cryptographic seal dynamically on read
                std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(balance) + cat + sub + div_id + expected_prev_hash;
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
                    {"division", div_id},
                    {"status", row[8].as<std::string>()},
                    {"audit_passed", (recalc_hash == stored_hash)}
                });
                expected_prev_hash = stored_hash;
            }
            std::reverse(ledger_json.begin(), ledger_json.end());
            res.set_content(ledger_json.dump(), "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content("{\"error\":\"Archive not found or database error.\"}", "application/json");
        }
    });

    // === [SEARCH: FETCH LEDGER DATA] ===
    svr.Get("/api/ledger/data", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            pqxx::connection C(conn_str);
            pqxx::work W(C);
            // Added 'splits' at the end of the query (Index 12)
            pqxx::result R = W.exec("SELECT id, to_char(transaction_date, 'DD/MM/YYYY'), description, debit_micros, credit_micros, balance_micros, category, sub_category, status, row_hash, COALESCE(division_id, 'global'), EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - transaction_date)), splits FROM ledger ORDER BY id ASC");

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
                std::string splits_str = row[12].is_null() ? "[]" : row[12].as<std::string>();

                // Cryptographic seal now protects the splits too
                std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(balance) + cat + div_id + splits_str + expected_prev_hash;
                std::string recalc_hash = osl::OSLCrypto::generate_sha256(raw_data);

                ledger_json.push_back({
                    {"id", row[0].as<int>()},
                    {"date", row[1].as<std::string>()},
                    {"description", desc},
                    {"debit", format_money(debit)},
                    {"credit", format_money(credit)},
                    {"balance", format_money(balance)},
                    {"category", cat},
                    {"division", div_id},
                    {"splits", json::parse(splits_str)}, 
                    {"audit_passed", (recalc_hash == stored_hash)},
                    {"is_editable", (age_seconds < 7200)} 
                });
                expected_prev_hash = stored_hash;
            }
            std::reverse(ledger_json.begin(), ledger_json.end());
            res.set_content(ledger_json.dump(), "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
        }
    });

    // === [SEARCH: LEDGER RESYNC ENGINE] ===
    svr.Post("/api/ledger/resync", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            pqxx::connection C(conn_str);
            pqxx::work W(C);

            // Pull every single row from Genesis to the present
            pqxx::result chain = W.exec("SELECT id, description, debit_micros, credit_micros, category, sub_category, division_id, splits FROM ledger ORDER BY id ASC");
            
            long long running_bal = 0;
            std::string last_hash = "GENESIS";

            for (auto row : chain) {
                int c_id = row[0].as<int>();
                running_bal = running_bal - row[2].as<long long>() + row[3].as<long long>();
                std::string c_splits = row[7].is_null() ? "[]" : row[7].as<std::string>();
                
                // Cryptographically seal with the newly upgraded formula
                std::string raw = row[1].as<std::string>() + row[2].as<std::string>() + row[3].as<std::string>() + std::to_string(running_bal) + (row[4].is_null() ? "" : row[4].as<std::string>()) + (row[5].is_null() ? "" : row[5].as<std::string>()) + (row[6].is_null() ? "global" : row[6].as<std::string>()) + c_splits + last_hash;
                last_hash = osl::OSLCrypto::generate_sha256(raw);
                
                // Rewrite the running balance and the repaired hash
                W.exec("UPDATE ledger SET balance_micros = " + std::to_string(running_bal) + ", row_hash = " + W.quote(last_hash) + " WHERE id = " + std::to_string(c_id));
            }

            W.commit();
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
        }
    });

    // === [SEARCH: EDIT TRANSACTION & CASCADING HASH] ===
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
            std::string splits_json = j.value("splits", json::array()).dump();

            pqxx::connection C(conn_str);
            pqxx::work W(C);

            // 1. Verify 2-Hour Grace Period securely
            pqxx::result check = W.exec("SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - transaction_date)) FROM ledger WHERE id = " + std::to_string(tx_id));
            if (check.empty() || check[0][0].as<double>() > 7200) {
                res.status = 403;
                res.set_content("{\"error\":\"Grace period expired. Record is permanently locked.\"}", "application/json");
                return;
            }

            // 2. Update the target record
            W.exec("UPDATE ledger SET description = " + W.quote(desc) + 
                   ", debit_micros = " + std::to_string(new_debit) + 
                   ", credit_micros = " + std::to_string(new_credit) + 
                   ", category = " + W.quote(cat) + 
                   ", sub_category = " + W.quote(sub) + 
                   ", division_id = " + W.quote(div_id) + 
                   ", splits = " + W.quote(splits_json) + 
                   " WHERE id = " + std::to_string(tx_id));

            // 3. Cascading Hash Recalculation (Rebuild the chain from this ID forward)
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
            osl_log("INFO", "Ledger record " + std::to_string(tx_id) + " updated. Chain recalculated.");
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
        }
    });

    // === [SEARCH: ADD TRANSACTION TO LEDGER] ===
    svr.Post("/api/ledger/add", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) return;
        try {
            auto j = json::parse(req.body);
            std::string desc = j.at("description").get<std::string>();
            long long debit = j.at("debit").get<long long>();
            long long credit = j.at("credit").get<long long>();
            std::string cat = j.at("category").get<std::string>();
            std::string sub = j.at("subcategory").get<std::string>();
            std::string div_id = j.contains("division") ? j.at("division").get<std::string>() : "global"; 

            pqxx::connection C(conn_str);
            pqxx::work W(C);

            pqxx::result last_row = W.exec("SELECT balance_micros, row_hash FROM ledger ORDER BY id DESC LIMIT 1");
            long long prev_balance = last_row.empty() ? 0 : last_row[0][0].as<long long>();
            std::string prev_hash = last_row.empty() ? "GENESIS" : last_row[0][1].as<std::string>();

            long long new_balance = prev_balance - debit + credit;
            
            std::string raw_data = desc + std::to_string(debit) + std::to_string(credit) + std::to_string(new_balance) + cat + sub + div_id + prev_hash;
            std::string current_hash = osl::OSLCrypto::generate_sha256(raw_data);

            W.exec("INSERT INTO ledger (description, debit_micros, credit_micros, balance_micros, category, sub_category, division_id, row_hash) VALUES (" +
                   W.quote(desc) + ", " + std::to_string(debit) + ", " + std::to_string(credit) + ", " + 
                   std::to_string(new_balance) + ", " + W.quote(cat) + ", " + W.quote(sub) + ", " + W.quote(div_id) + ", " + W.quote(current_hash) + ")");
            
            W.commit();
            osl_log("INFO", "Transaction saved under entity '" + div_id + "': " + desc);
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
        }
    });

    // === [SEARCH: EDIT TRANSACTION & CASCADING HASH] ===
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

            pqxx::connection C(conn_str);
            pqxx::work W(C);

            // 1. Verify the 2-Hour Grace Period securely on the backend
            pqxx::result check = W.exec("SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - transaction_date)) FROM ledger WHERE id = " + std::to_string(tx_id));
            if (check.empty() || check[0][0].as<double>() > 7200) {
                res.status = 403;
                res.set_content("{\"error\":\"Grace period expired. Record is permanently locked.\"}", "application/json");
                return;
            }

            // 2. Update the target record's base data
            W.exec("UPDATE ledger SET description = " + W.quote(desc) + ", debit_micros = " + std::to_string(new_debit) + 
                   ", credit_micros = " + std::to_string(new_credit) + ", category = " + W.quote(cat) + 
                   ", division_id = " + W.quote(div_id) + " WHERE id = " + std::to_string(tx_id));

            // 3. The Cascading Hash Recalculation (Rebuild the chain from this ID forward)
            pqxx::result chain = W.exec("SELECT id, description, debit_micros, credit_micros, category, sub_category, division_id FROM ledger WHERE id >= " + std::to_string(tx_id) + " ORDER BY id ASC");
            
            // Get the hash and balance of the record immediately preceding the edit
            pqxx::result prev_record = W.exec("SELECT balance_micros, row_hash FROM ledger WHERE id < " + std::to_string(tx_id) + " ORDER BY id DESC LIMIT 1");
            long long running_balance = prev_record.empty() ? 0 : prev_record[0][0].as<long long>();
            std::string prev_hash = prev_record.empty() ? "GENESIS" : prev_record[0][1].as<std::string>();

            // Cascade down the chain
            for (auto row : chain) {
                int curr_id = row[0].as<int>();
                std::string c_desc = row[1].as<std::string>();
                long long c_deb = row[2].as<long long>();
                long long c_cred = row[3].as<long long>();
                std::string c_cat = row[4].is_null() ? "" : row[4].as<std::string>();
                std::string c_sub = row[5].is_null() ? "" : row[5].as<std::string>();
                std::string c_div = row[6].is_null() ? "global" : row[6].as<std::string>();

                running_balance = running_balance - c_deb + c_cred;
                
                std::string raw_data = c_desc + std::to_string(c_deb) + std::to_string(c_cred) + std::to_string(running_balance) + c_cat + c_sub + c_div + prev_hash;
                std::string new_hash = osl::OSLCrypto::generate_sha256(raw_data);

                W.exec("UPDATE ledger SET balance_micros = " + std::to_string(running_balance) + ", row_hash = " + W.quote(new_hash) + " WHERE id = " + std::to_string(curr_id));
                prev_hash = new_hash;
            }

            W.commit();
            osl_log("INFO", "Ledger record " + std::to_string(tx_id) + " edited. Cascading hash update completed.");
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content("{\"error\":\"Database error during recalculation.\"}", "application/json");
        }
    });

    // === [SEARCH: PLUGIN API ROUTES] ===
    svr.Post(R"(/api/plugin/([^/]+)/([^/]+))", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        std::string plugin_id = req.matches[1];
        std::string command = req.matches[2];
        json payload = req.body.empty() ? json::object() : json::parse(req.body);
        json result = plugin_manager.ExecutePluginCommand(plugin_id, command, payload);
        res.set_content(result.dump(), "application/json");
    });

    svr.Get("/api/plugins/active", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        json plugins = json::array();
        plugins.push_back({
            {"id", "au.net.osl.invoicing"},
            {"name", "OSL Invoicing"},
            {"version", "1.0.0"}
        });
        res.set_content(plugins.dump(), "application/json");
    });

    // === [SEARCH: ADD NEW USER TO LLDAP VAULT] ===
    svr.Post("/api/users/add", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_admin(req)) {
            osl_log("WARN", "Unauthorized attempt to add user blocked.");
            res.status = 403;
            res.set_content("{\"error\":\"Action Requires Administrator Privileges.\"}", "application/json");
            return;
        }

        osl_log("INFO", "Initiating new user provisioning process...");

        try {
            auto j = json::parse(req.body);
            std::string target_user = j.at("username").get<std::string>();
            std::string new_email = j.at("email").get<std::string>();
            std::string new_display = j.at("displayName").get<std::string>();
            std::string new_first = j.at("firstName").get<std::string>();
            std::string new_last = j.at("lastName").get<std::string>();
            std::string new_pass = j.at("password").get<std::string>();
            
            osl_log("DEBUG", "Payload Received -> Target: " + target_user + " | Email: " + new_email);

            std::string admin_user = std::getenv("LLDAP_ADMIN_USER") ? std::getenv("LLDAP_ADMIN_USER") : "admin";
            std::string admin_pass = std::getenv("LLDAP_ADMIN_PASS") ? std::getenv("LLDAP_ADMIN_PASS") : "";
            
            httplib::Client lldap("http://osl-identity:17170");

            // STEP 1: Authenticate Admin for GraphQL Profile Creation
            osl_log("DEBUG", "Authenticating Engine with Identity Gateway...");
            json auth_payload = {{"username", admin_user}, {"password", admin_pass}};
            auto auth_res = lldap.Post("/auth/simple/login", auth_payload.dump(), "application/json");
            
            if (!auth_res || auth_res->status != 200) {
                osl_log("ERROR", "Identity gateway authentication failed. Status: " + std::to_string(auth_res ? auth_res->status : 0));
                res.status = 500;
                res.set_content("{\"error\":\"Internal identity service connection failed.\"}", "application/json");
                return;
            }

            std::string token = json::parse(auth_res->body)["token"];
            httplib::Headers headers = {{"Authorization", "Bearer " + token}};

            // STEP 2: Create the User Profile
            osl_log("DEBUG", "Sending GraphQL CreateUser mutation...");
            json create_payload = {
                {"query", "mutation CreateUser($user: CreateUserInput!) { createUser(user: $user) { id } }"},
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
            
            auto create_res = lldap.Post("/api/graphql", headers, create_payload.dump(), "application/json");
            if (create_res) {
                auto reply = json::parse(create_res->body);
                if (reply.contains("errors")) {
                    std::string err_msg = reply["errors"][0]["message"].get<std::string>();
                    osl_log("ERROR", "LLDAP CreateUser Failed: " + err_msg);
                    res.status = 400;
                    res.set_content("{\"error\":\"" + err_msg + "\"}", "application/json");
                    return;
                }
            } else {
                osl_log("ERROR", "LLDAP CreateUser network timeout or no response.");
                res.status = 500;
                res.set_content("{\"error\":\"Identity service timeout.\"}", "application/json");
                return;
            }

            // STEP 3: Set Initial Password via LDAP (Bypassing GraphQL)
            osl_log("DEBUG", "Setting cryptographic password via native LDAP protocol...");
            if (!set_lldap_password(admin_user, admin_pass, target_user, new_pass)) {
                res.status = 500;
                res.set_content("{\"error\":\"Failed to set password. LDAP dependency missing in container.\"}", "application/json");
                return;
            }

            // STEP 4: Assign Account Role / Group
            int role_id = 6; // Default to standard user
            if (j.contains("roleId") && !j.at("roleId").get<std::string>().empty()) {
                role_id = std::stoi(j.at("roleId").get<std::string>());
            }
            
            osl_log("DEBUG", "Assigning group ID " + std::to_string(role_id) + " to user...");
            json group_payload = {
                {"query", "mutation AddUserToGroup($userId: String!, $groupId: Int!) { addUserToGroup(userId: $userId, groupId: $groupId) { ok } }"},
                {"variables", { {"userId", target_user}, {"groupId", role_id} }}
            };
            
            auto group_res = lldap.Post("/api/graphql", headers, group_payload.dump(), "application/json");
            if (group_res) {
                auto group_reply = json::parse(group_res->body);
                if (group_reply.contains("errors")) {
                    std::string err_msg = group_reply["errors"][0]["message"].get<std::string>();
                    osl_log("ERROR", "LLDAP GroupAssignment Failed: " + err_msg);
                }
            }

            osl_log("INFO", "Successfully provisioned identity: " + target_user);
            res.status = 200;
            res.set_content("{\"status\":\"SUCCESS\", \"message\":\"User Added Successfully\"}", "application/json");

        } catch (const std::exception &e) {
            osl_log("ERROR", "Exception during user creation: " + std::string(e.what()));
            res.status = 500;
            res.set_content("{\"error\":\"Invalid request format.\"}", "application/json");
        }
    });

    // === [SEARCH: UPDATE USER IN LLDAP VAULT] ===
    svr.Post("/api/users/update", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_admin(req)) {
            res.status = 403;
            res.set_content("{\"error\":\"Action Requires Administrator Privileges.\"}", "application/json");
            return;
        }

        try {
            auto j = json::parse(req.body);
            std::string target_user = j.at("username").get<std::string>();
            std::string new_email = j.at("email").get<std::string>();
            std::string new_display = j.at("displayName").get<std::string>();
            std::string new_first = j.at("firstName").get<std::string>();
            std::string new_last = j.at("lastName").get<std::string>();
            
            std::string new_pass = j.contains("password") ? j.at("password").get<std::string>() : "";

            std::string admin_user = std::getenv("LLDAP_ADMIN_USER") ? std::getenv("LLDAP_ADMIN_USER") : "admin";
            std::string admin_pass = std::getenv("LLDAP_ADMIN_PASS") ? std::getenv("LLDAP_ADMIN_PASS") : "";
            
            httplib::Client lldap("http://osl-identity:17170");

            json auth_payload = {{"username", admin_user}, {"password", admin_pass}};
            auto auth_res = lldap.Post("/auth/simple/login", auth_payload.dump(), "application/json");
            if (!auth_res || auth_res->status != 200) {
                res.status = 500;
                res.set_content("{\"error\":\"Internal identity service connection failed.\"}", "application/json");
                return;
            }
            std::string token = json::parse(auth_res->body)["token"];
            httplib::Headers headers = {{"Authorization", "Bearer " + token}};

            json update_payload = {
                {"query", "mutation UpdateUser($user: UpdateUserInput!) { updateUser(user: $user) { ok } }"},
                {"variables", {
                    {"user", {
                        {"id", target_user}, {"email", new_email}, {"displayName", new_display},
                        {"firstName", new_first}, {"lastName", new_last}
                    }}
                }}
            };
            auto update_res = lldap.Post("/api/graphql", headers, update_payload.dump(), "application/json");
            if (update_res) {
                auto reply = json::parse(update_res->body);
                if (reply.contains("errors")) {
                    res.status = 400;
                    res.set_content("{\"error\":\"User Update Failed: " + reply["errors"][0]["message"].get<std::string>() + "\"}", "application/json");
                    return;
                }
            }

            int role_id = 6; 
            if (j.contains("roleId") && !j.at("roleId").get<std::string>().empty()) {
                role_id = std::stoi(j.at("roleId").get<std::string>());
            }
            json group_payload = {
                {"query", "mutation AddUserToGroup($userId: String!, $groupId: Int!) { addUserToGroup(userId: $userId, groupId: $groupId) { ok } }"},
                {"variables", { {"userId", target_user}, {"groupId", role_id} }}
            };
            lldap.Post("/api/graphql", headers, group_payload.dump(), "application/json");

            if (!new_pass.empty()) {
                osl_log("DEBUG", "Updating password via internal LDAP protocol...");
                if (!set_lldap_password(admin_user, admin_pass, target_user, new_pass)) {
                    res.status = 500;
                    res.set_content("{\"error\":\"Password Update Failed. LDAP dependency missing in container.\"}", "application/json");
                    return;
                }
            }

            osl_log("INFO", "Successfully updated identity: " + target_user);
            res.status = 200;
            res.set_content("{\"status\":\"SUCCESS\", \"message\":\"User Updated Successfully\"}", "application/json");

        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content("{\"error\":\"Invalid request format.\"}", "application/json");
        }
    });

    // === [SEARCH: AUTH & SYSTEM ROUTES] ===
    svr.Get("/api/auth/me", [&](const httplib::Request &req, httplib::Response &res) {
        std::string current_user = req.get_header_value("Remote-User");
        std::string current_groups = req.get_header_value("Remote-Groups");
        
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
        if (!is_admin(req)) {
            res.status = 403;
            res.set_content("{\"error\":\"Action Requires Administrator Privileges.\"}", "application/json");
            return;
        }

        try {
            std::string admin_user = std::getenv("LLDAP_ADMIN_USER") ? std::getenv("LLDAP_ADMIN_USER") : "admin";
            std::string admin_pass = std::getenv("LLDAP_ADMIN_PASS") ? std::getenv("LLDAP_ADMIN_PASS") : "";

            httplib::Client lldap("http://osl-identity:17170");

            json auth_payload = {{"username", admin_user}, {"password", admin_pass}};
            auto auth_res = lldap.Post("/auth/simple/login", auth_payload.dump(), "application/json");

            if (!auth_res || auth_res->status != 200) {
                res.status = 500;
                res.set_content("{\"error\":\"Internal identity service connection failed.\"}", "application/json");
                return;
            }

            std::string token = json::parse(auth_res->body)["token"];
            httplib::Headers headers = {{"Authorization", "Bearer " + token}};

            json query_payload = {
                {"query", "query { users { id email displayName firstName lastName groups { id displayName } } }"}
            };
            
            auto query_res = lldap.Post("/api/graphql", headers, query_payload.dump(), "application/json");

            res.status = 200;
            res.set_content(query_res->body, "application/json");

        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content("{\"error\":\"Failed to retrieve user list.\"}", "application/json");
        }
    });

    svr.Get("/logout", [&](const httplib::Request &req, httplib::Response &res) {
        std::string target_url = "https://" + base_domain;
        std::string encoded_target = "https%3A%2F%2F" + base_domain;
        
        std::string auth_logout_url = "https://auth." + base_domain + "/logout?rd=" + encoded_target;
        res.set_redirect(auth_logout_url);
    });

    // === [SEARCH: SETTINGS & CONFIG ROUTES] ===
    svr.Get("/api/settings/manifest", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        
        std::string config_path = "/app/core/config/osl_config.json";
        std::ifstream ifs(config_path);
        
        if (ifs.is_open()) {
            try {
                json manifest = json::parse(ifs);
                res.set_content(manifest.dump(), "application/json");
            } catch (const std::exception &e) {
                osl_log("ERROR", "Config Parse Error: " + std::string(e.what()));
                res.status = 500;
                res.set_content("{\"error\":\"Configuration file is corrupt.\"}", "application/json");
            }
        } else {
            osl_log("WARN", "Config file missing. Using system defaults.");
            json fallback;
            fallback["core"]["entity_name"] = "Cel-Tech-Serv Pty Ltd (Default)";
	    fallback["core"]["divisions"] = json::array();
            res.set_content(fallback.dump(), "application/json");
        }
    });

    svr.Get("/api/system/logs", [&](const httplib::Request &req, httplib::Response &res) {
        std::string groups = req.has_header("Remote-Groups") ? req.get_header_value("Remote-Groups") : "";
        if (groups.find("admins") == std::string::npos) {
            osl_log("WARN", "Unauthorized log access blocked.");
            res.status = 403;
            res.set_content("{\"error\":\"Action Requires Administrator Privileges.\"}", "application/json");
            return;
        }

        json response;
        {
            std::lock_guard<std::mutex> lock(log_mutex);
            response["logs"] = system_logs;
        }
        
        res.set_content(response.dump(), "application/json");
    });

    svr.Post("/api/ledger/purge", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_admin(req)) { res.status = 403; return; }

        try {
            auto j = json::parse(req.body);
            std::string confirm = j.at("confirmation").get<std::string>();

            if (confirm == "PURGE DATA") {
                osl_log("CRITICAL", "User " + req.get_header_value("Remote-User") + " executed ledger data purge.");
                
                // TODO: Execute SQL TRUNCATE commands here in the next phase
                
                res.status = 200;
                res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
            } else {
                res.status = 400;
                res.set_content("{\"error\":\"Invalid confirmation string provided.\"}", "application/json");
            }
        } catch (...) {
            res.status = 400;
        }
    });

    svr.Post("/api/settings/save", [&](const httplib::Request &req, httplib::Response &res) {
    	if (!is_admin(req)) { res.status = 403; return; }

        try {
            auto new_config = json::parse(req.body);
            std::string config_path = "/app/core/config/osl_config.json";
            
            std::ofstream ofs(config_path);
            if (ofs.is_open()) {
                ofs << new_config.dump(4);
                ofs.close();
                
                osl_log("INFO", "Configuration updated by user: " + req.get_header_value("Remote-User"));
                res.status = 200;
                res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
            } else {
                osl_log("ERROR", "Failed to save configuration file to storage.");
                res.status = 500;
            }
        } catch (const std::exception &e) {
            osl_log("ERROR", "Invalid configuration format: " + std::string(e.what()));
            res.status = 400;
        }
    });

    svr.Get("/api/user/prefs", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        
        std::string current_user = req.get_header_value("Remote-User");
        std::string prefs_path = "/app/core/config/user_prefs.json";
        std::ifstream ifs(prefs_path);
        
        json user_prefs;
        if (ifs.is_open()) {
            try {
                json all_prefs = json::parse(ifs);
                if (all_prefs.contains(current_user)) {
                    user_prefs = all_prefs[current_user];
                }
            } catch (...) { }
        }
        
        if (!user_prefs.contains("theme")) user_prefs["theme"] = "dark";
        
        res.set_content(user_prefs.dump(), "application/json");
    });

    svr.Post("/api/user/prefs", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req)) { res.status = 401; return; }
        
        std::string current_user = req.get_header_value("Remote-User");
        std::string prefs_path = "/app/core/config/user_prefs.json";
        
        json all_prefs;
        std::ifstream ifs(prefs_path);
        if (ifs.is_open()) {
            try { all_prefs = json::parse(ifs); } catch (...) {}
            ifs.close();
        }
        
        try {
            auto incoming_prefs = json::parse(req.body);
            all_prefs[current_user] = incoming_prefs;
            
            std::ofstream ofs(prefs_path);
            ofs << all_prefs.dump(4);
            
            res.status = 200;
            res.set_content("{\"status\":\"SUCCESS\"}", "application/json");
        } catch (const std::exception &e) {
            res.status = 400;
        }
    });

    // === [SEARCH: SERVER INITIALIZATION] ===
    svr.set_mount_point("/js", "/app/www/js");
    svr.set_mount_point("/css", "/app/www/css");

    int listen_port = std::getenv("OSL_PORT") ? std::stoi(std::getenv("OSL_PORT")) : 8080;
    osl_log("INFO", "OSL Server running on port " + std::to_string(listen_port));
    
    svr.listen("0.0.0.0", listen_port);
    
    return 0;
}

/**
 * OSL: Open Source Ledger - Core Engine
 * Feature: Hybrid Authentication (SSO + Local Fallback)
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib> // For getenv
#include <pqxx/pqxx>
#include <httplib.h>
#include "crypto.hpp"
#include "ledger.cpp"

// --- CONFIGURATION ---
const std::string BACKUP_USER = std::getenv("OSL_BACKUP_USER") ? std::getenv("OSL_BACKUP_USER") : "admin";
const std::string BACKUP_PASS = std::getenv("OSL_BACKUP_PASS") ? std::getenv("OSL_BACKUP_PASS") : "password";
const std::string SESSION_SECRET = "osl_sovereign_session_token"; // Simple token for demo

// Helper: Format Money
std::string format_money(long long micros) {
    long long dollars = micros / 1000000;
    long long cents = (micros % 1000000) / 10000;
    return "$" + std::to_string(dollars) + "." + (cents < 10 ? "0" : "") + std::to_string(cents);
}

// --- HTML COMPONENTS ---
std::string get_login_page(std::string error_msg = "") {
    return R"(
        <html>
        <head><title>OSL Login</title><script src="https://cdn.tailwindcss.com"></script></head>
        <body class="bg-slate-900 flex items-center justify-center h-screen font-mono text-slate-100">
            <div class="bg-slate-800 p-8 rounded shadow-lg w-96 border border-slate-700">
                <h1 class="text-xl font-bold mb-6 text-blue-500 text-center">Sovereign Backup Login</h1>
                <p class="text-red-500 text-xs mb-4 text-center">)" + error_msg + R"(</p>
                <form action="/login" method="post" class="flex flex-col gap-4">
                    <input type="text" name="user" placeholder="Username" class="p-2 bg-slate-900 border border-slate-600 rounded text-white">
                    <input type="password" name="pass" placeholder="Password" class="p-2 bg-slate-900 border border-slate-600 rounded text-white">
                    <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded transition">Unlock Vault</button>
                </form>
                <div class="mt-4 text-center text-xs text-slate-500">Authelia Disconnected</div>
            </div>
        </body>
        </html>
    )";
}

int main() {
    // DB Connection
    std::string conn_str = "host=osl-vault user=osl_admin password=change_me_in_production_please dbname=osl_main";
    
    httplib::Server svr;
    std::cout << "[SEC] Hybrid Auth System Active." << std::endl;
    std::cout << "[SEC] Backup User: " << BACKUP_USER << std::endl;

    // --- GATEKEEPER MIDDLEWARE ---
    auto is_authenticated = [&](const httplib::Request &req) -> bool {
        // 1. Check for Authelia/Caddy Headers (Primary)
        if (req.has_header("Remote-User")) {
            // std::cout << "[AUTH] Authelia User Detected: " << req.get_header_value("Remote-User") << std::endl;
            return true;
        }

        // 2. Check for Local Session Cookie (Fallback)
        if (req.has_header("Cookie")) {
            std::string cookies = req.get_header_value("Cookie");
            if (cookies.find("OSL_SESSION=" + SESSION_SECRET) != std::string::npos) {
                return true;
            }
        }
        return false;
    };

    // --- ROUTES ---

    // 1. LOGIN PAGE (GET)
    svr.Get("/login", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(get_login_page(), "text/html");
    });

    // 2. LOGIN ACTION (POST)
    svr.Post("/login", [&](const httplib::Request &req, httplib::Response &res) {
        if (req.has_param("user") && req.has_param("pass")) {
            if (req.get_param_value("user") == BACKUP_USER && req.get_param_value("pass") == BACKUP_PASS) {
                // Success: Set Cookie and Redirect
                res.set_header("Set-Cookie", "OSL_SESSION=" + SESSION_SECRET + "; HttpOnly; Path=/; Max-Age=3600");
                res.set_redirect("/");
                std::cout << "[AUTH] Backup Login Successful." << std::endl;
            } else {
                res.set_content(get_login_page("Invalid Credentials"), "text/html");
            }
        } else {
            res.set_content(get_login_page("Missing Fields"), "text/html");
        }
    });

    // 3. DASHBOARD (Protected)
    svr.Get("/", [&](const httplib::Request &req, httplib::Response &res) {
        // Security Check
        if (!is_authenticated(req)) {
            std::cout << "[AUTH] Unauthorized Access Attempt. Redirecting to Login." << std::endl;
            res.set_redirect("/login");
            return;
        }

        // Render Dashboard
        try {
            pqxx::connection c(conn_str);
            pqxx::work txn(c);
            pqxx::result rows = txn.exec("SELECT id, created_at, description, debit, credit, left(curr_hash, 10) FROM osl_registry.ledger_entries ORDER BY id ASC");

            std::string html = R"(<!DOCTYPE html><html><head><title>OSL Dashboard</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-slate-900 text-slate-100 p-10 font-mono">)";
            
            // Add Logout Button if using Local Auth
            if (!req.has_header("Remote-User")) {
                html += R"(<div class="absolute top-5 right-5 text-xs text-orange-500">Backup Mode Active</div>)";
            } else {
                html += R"(<div class="absolute top-5 right-5 text-xs text-green-500">SSO Active: )" + req.get_header_value("Remote-User") + "</div>";
            }

            html += R"(<h1 class="text-3xl font-bold mb-6 text-blue-500">Sovereign Ledger</h1><table class="w-full text-left border-collapse"><thead><tr class="text-slate-400 border-b border-slate-700"><th class="p-2">ID</th><th class="p-2">Date</th><th class="p-2">Description</th><th class="p-2 text-right">Debit</th><th class="p-2 text-right">Credit</th><th class="p-2">Hash Seal</th></tr></thead><tbody>)";

            for (auto row : rows) {
                html += "<tr class='border-b border-slate-800 hover:bg-slate-800/50'><td class='p-2'>" + std::string(row[0].c_str()) + "</td><td class='p-2 text-xs text-slate-400'>" + std::string(row[1].c_str()) + "</td><td class='p-2'>" + std::string(row[2].c_str()) + "</td><td class='p-2 text-right text-green-400'>" + format_money(row[3].as<long long>()) + "</td><td class='p-2 text-right text-red-400'>" + format_money(row[4].as<long long>()) + "</td><td class='p-2 text-xs text-yellow-500 font-bold'>" + std::string(row[5].c_str()) + "...</td></tr>";
            }
            html += "</tbody></table></body></html>";
            res.set_content(html, "text/html");
        } catch (const std::exception &e) {
            res.set_content("DB Error: " + std::string(e.what()), "text/plain");
        }
    });

    svr.listen("0.0.0.0", 8080);
    return 0;
}

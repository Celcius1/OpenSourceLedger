/*
 * OSL: Sovereign Accounting Suite
 * Copyright (c) 2026 Cel-Tech-Serv Pty Ltd
 * * ViewEngine.cpp - Implementation of the Agnostic UI Assembler
 */

#include "ViewEngine.hpp"
#include <fstream>
#include <sstream>
#include <iostream>

std::string ViewEngine::read_file(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[OSL Core] CRITICAL: Failed to open template at " << filepath << std::endl;
        return ""; // Returning empty string will help us catch the error gracefully
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void ViewEngine::replace_all(std::string& str, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); 
    }
}

std::string ViewEngine::render_template(const std::string& template_path, const std::map<std::string, std::string>& context) {
    std::string html = read_file(template_path);
    
    if (html.empty()) {
        return "<h1>500 Internal Server Error</h1><p>Sovereign UI Template Missing: " + template_path + "</p>";
    }

    // Iterate through the provided context map and replace all tags
    for (const auto& pair : context) {
        std::string tag = "{{" + pair.first + "}}";
        replace_all(html, tag, pair.second);
    }

    return html;
}

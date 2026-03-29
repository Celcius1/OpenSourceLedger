/*
 * OSL: Sovereign Accounting Suite
 * Copyright (c) 2026 Cel-Tech-Serv Pty Ltd
 * * ViewEngine.hpp - Agnostic UI Assembler
 * Core component for rendering dynamic templates.
 */

#ifndef VIEW_ENGINE_HPP
#define VIEW_ENGINE_HPP

#include <string>
#include <map>

class ViewEngine {
public:
    // Loads the template and replaces tags with provided data
    static std::string render_template(const std::string& template_path, const std::map<std::string, std::string>& context);

private:
    // Helper to read the physical file from the Docker volume
    static std::string read_file(const std::string& filepath);
    
    // Helper to replace all instances of a tag (e.g., {{USERNAME}})
    static void replace_all(std::string& str, const std::string& from, const std::string& to);
};

#endif // VIEW_ENGINE_HPP

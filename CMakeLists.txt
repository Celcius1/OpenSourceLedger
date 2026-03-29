# ============================================================================
# SOFTWARE: OSL: Sovereign Accounting Suite
# AUTHOR & COPYRIGHT: Cel-Tech-Serv Pty Ltd
# ============================================================================
cmake_minimum_required(VERSION 3.10)

# Set the project name globally
project(OpenSourceLedger VERSION 1.0.0 LANGUAGES CXX)

# --- GLOBAL COMPILER SETTINGS ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- BRAND PROTECTION & METADATA ---
# These definitions are baked into every binary in the suite
add_definitions(-DOSL_VENDOR="Cel-Tech-Serv Pty Ltd")
add_definitions(-DOSL_SUITE="Sovereign Accounting Suite")
add_definitions(-DOSL_LEGAL_NOTICE="Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.")

# --- SHARED INCLUDE PATHS ---
# This ensures the Core and Plugins always know where the SDK headers are
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/interface
)

# --- MODULES ---
# This tells CMake to go into the Core folder and look for the logic there
add_subdirectory(src/core)

# (In the future, we can add subdirectories for official plugins here)
# add_subdirectory(src/plugins/official/invoicing)

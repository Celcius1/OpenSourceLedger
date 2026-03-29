# ============================================================================
# SOFTWARE: OSL: Sovereign Accounting Suite - Core Engine
# AUTHOR & COPYRIGHT: Cel-Tech-Serv Pty Ltd
# ============================================================================
# NOTE: This file is a subdirectory of the master OSL project. 
# It relies on the root CMakeLists.txt for global include paths and branding.
# ============================================================================

# 1. Locate System Dependencies
# -----------------------------
# OSL requires pqxx for Vault connectivity and OpenSSL for Ledger sealing.
find_package(PostgreSQL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# 2. Define Core Source Files
# ---------------------------
# Note: 'ledger.cpp' is currently #included in main.cpp, so it is not listed
# here as a separate compilation unit to avoid duplicate symbol errors.
set(CORE_SOURCES
    main.cpp
    crypto.cpp
    ViewEngine.cpp
    ../plugins/interface/PluginManager.cpp
)

# 3. Create the Executable
# ------------------------
add_executable(osl_core ${CORE_SOURCES})

# 4. Link Libraries
# -----------------
# We link the PostgreSQL client, OpenSSL, and Threading libraries.
# target_link_libraries ensures the binary has access to the Vault and Crypto logic.
target_link_libraries(osl_core
    PRIVATE
    PostgreSQL::PostgreSQL
    OpenSSL::SSL
    OpenSSL::Crypto
    pqxx
    Threads::Threads
)

# 5. Core-Specific Branding
# -------------------------
# While the root CMake handles global branding, these definitions are 
# specific to the Core binary itself to assist in debugging and brand protection.
target_compile_definitions(osl_core PRIVATE
    OSL_MODULE="Core_Engine"
    OSL_BUILD_DATE="${CMAKE_BUILD_TIMESTAMP}"
)

# 6. Output Configuration
# -----------------------
# This places the final binary into a 'bin' directory in your build folder
# for easier access when mapping into your Docker containers.
set_target_properties(osl_core PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ============================================================================
# END OF MODULE: src/core/CMakeLists.txt
# ============================================================================

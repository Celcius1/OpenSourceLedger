#ifndef OSL_PLUGIN_HPP
#define OSL_PLUGIN_HPP

#include <string>
#include <vector>
#include <cstdint>

// money_micro: $1.00 = 1,000,000
typedef int64_t money_micro;

struct LedgerLine {
    std::string account_code;
    money_micro debit = 0;
    money_micro credit = 0;
    std::string description;
};

// The Plugin Interface
// This allows you to write "AU-Tax" or "JP-Tax" as separate .so files
class IOSLPlugin {
public:
    virtual ~IOSLPlugin() {}
    virtual std::string get_plugin_name() = 0;
    
    // Plugins can "inspect" a transaction before it is committed to the chain
    virtual void pre_commit_hook(std::vector<LedgerLine>& transaction) = 0;
};

#endif

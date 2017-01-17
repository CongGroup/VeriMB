#ifndef PATTERNLOADER_H
#define PATTERNLOADER_H

#include "ringer_defs.h"

#include <string>
#include <vector>

class PatternLoader {
public:
    static void load_pattern_file(const char* file, PatternSet& ptnSet);

private:
    static char cap_hex_to_byte(const std::string& hex);

    static Binary ptrn_str_to_bytes(const std::string& str);
};

#endif
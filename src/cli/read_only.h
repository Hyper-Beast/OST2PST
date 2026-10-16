#pragma once

#include <string>

#include "ost2pst/util/file_reader.h"

namespace ost2pst::cli {

// CLI policy before interpreting Unicode structures or creating conversion outputs.
util::Status validate_input(const util::FileReader& file);
int input_error_exit(const util::DataError& error);
int report_input_error(const util::DataError& error);
int run_read_only(const std::wstring& input, const std::wstring& output, bool dry_run);
std::string to_utf8(const std::wstring& wide);

} // namespace ost2pst::cli

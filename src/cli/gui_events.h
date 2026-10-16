#pragma once
#include <string>

#include "ost2pst/util/status.h"

namespace ost2pst::cli {
// Presentation only: deliberately excluded from the durable conversion identity.
class GuiEvents {
  public:
    explicit GuiEvents(bool enabled) : enabled_(enabled) {}
    bool enabled() const { return enabled_; }
    void start();
    void progress(const char* phase, bool known_total, uint64_t total, uint64_t terminal,
                  uint64_t normal, uint64_t fai, uint64_t skipped);
    void error(const util::DataError& error, bool input_phase);
    bool result(int code, const std::wstring& output);

  private:
    bool enabled_;
    void emit(const std::string& fields);
};
} // namespace ost2pst::cli

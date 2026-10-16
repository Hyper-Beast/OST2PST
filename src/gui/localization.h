#pragma once
#include <string>
#include <vector>

#include "../../resources/gui/strings.h"
namespace ost2pst::gui {
std::vector<std::wstring> preferred_ui_languages();
class Strings {
  public:
    explicit Strings(const std::vector<std::wstring>& preferred = preferred_ui_languages());
    std::wstring get(Text key) const;
    std::wstring format(Text key, const std::wstring& first,
                        const std::wstring& second = L"") const;
    std::string locale() const;

  private:
    const Catalog* catalog_ = &kCatalogs[0];
};
std::wstring from_utf8(const std::string& text);
} // namespace ost2pst::gui

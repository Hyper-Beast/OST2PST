#include "localization.h"

#include "protocol.h"
#define NOMINMAX
#include <windows.h>

namespace ost2pst::gui {
std::vector<std::wstring> preferred_ui_languages() {
    ULONG count = 0, size = 0;
    if (!GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &count, nullptr, &size) || !size)
        return {};
    std::vector<wchar_t> buffer(size);
    if (!GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &count, buffer.data(), &size))
        return {};
    std::vector<std::wstring> result;
    for (size_t i = 0; i < buffer.size() && buffer[i];) {
        std::wstring tag(&buffer[i]);
        i += tag.size() + 1;
        result.push_back(std::move(tag));
    }
    return result;
}
Strings::Strings(const std::vector<std::wstring>& preferred) {
    const auto selected = resolve_locale(preferred);
    for (const auto& c : kCatalogs)
        if (c.locale == selected)
            catalog_ = &c;
}
std::wstring Strings::get(Text key) const {
    return std::wstring(catalog_->strings[static_cast<size_t>(key)]);
}
std::wstring Strings::format(Text key, const std::wstring& first,
                             const std::wstring& second) const {
    auto s = get(key);
    for (auto pair : {std::pair{L"{0}", first}, std::pair{L"{1}", second}}) {
        size_t start = 0;
        while ((start = s.find(pair.first, start)) != std::wstring::npos) {
            s.replace(start, 3, pair.second);
            start += pair.second.size();
        }
    }
    return s;
}
std::string Strings::locale() const {
    return std::string(catalog_->locale);
}
std::wstring from_utf8(const std::string& text) {
    if (text.empty())
        return {};
    auto count =
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(count, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), count);
    return out;
}
} // namespace ost2pst::gui

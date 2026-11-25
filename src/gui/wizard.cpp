#include "wizard.h"

#include <algorithm>
#include <commctrl.h>
#include <cwctype>
#include <filesystem>
#include <gdiplus.h>
#include <iomanip>
#include <shellapi.h>
#include <shobjidl.h>
#include <sstream>
#include <vector>
#include <windowsx.h>

namespace ost2pst::gui {
namespace {
constexpr COLORREF kBackground = RGB(245, 247, 251), kInk = RGB(27, 40, 60),
                   kMuted = RGB(76, 92, 115), kAccent = RGB(39, 83, 194),
                   kLine = RGB(214, 222, 234), kTint = RGB(240, 245, 255);
constexpr wchar_t kGithubUrl[] = L"https://github.com/Hyper-Beast/OST2PST";
constexpr wchar_t kCoffeeUrl[] = L"https://ko-fi.com/hyperbeast";
constexpr COLORREF kMetricFill = RGB(247, 249, 253);
int content_y(int height, int offset) {
    return height < 560 ? 95 + MulDiv(offset, 78, 100) : 112 + offset;
}
RECT metric_box(int width, int height, int step, int column) {
    const int col = (width - 128 + 12) / 3;
    const int x = 64 + column * col;
    const int y = step == 3 ? 129 : 210;
    return {x, content_y(height, y), x + col - 12, content_y(height, y + 87)};
}
std::wstring link_start(const wchar_t* url) {
    return std::wstring(L"<a href=\"") + url + L"\">";
}
// The caller saves/restores the DC around a group of shapes.
void panel(HDC dc, RECT box, int radius, COLORREF fill, COLORREF edge) {
    SelectObject(dc, GetStockObject(DC_BRUSH));
    SelectObject(dc, GetStockObject(DC_PEN));
    SetDCBrushColor(dc, fill);
    SetDCPenColor(dc, edge);
    RoundRect(dc, box.left, box.top, box.right, box.bottom, radius, radius);
}
// Render the outline and fill in device pixels; leave the number to native text rendering.
bool step_circle(HDC dc, const RECT& box, float border, COLORREF fill, COLORREF edge) {
    Gdiplus::Graphics g(dc);
    g.SetPageUnit(Gdiplus::UnitPixel);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
    auto disc = [&](float inset, COLORREF rgb) {
        Gdiplus::Color color;
        color.SetFromCOLORREF(rgb);
        Gdiplus::SolidBrush brush(color);
        const float size = static_cast<float>(box.right - box.left) - 2 * inset;
        return g.FillEllipse(&brush, static_cast<float>(box.left) + inset,
                             static_cast<float>(box.top) + inset, size, size) == Gdiplus::Ok;
    };
    return disc(0, edge) && (fill == edge || disc(border, fill));
}
std::wstring text(HWND w) {
    const int size = GetWindowTextLengthW(w);
    std::wstring s(static_cast<size_t>(size) + 1, L'\0');
    s.resize(GetWindowTextW(w, s.data(), size + 1));
    return s;
}
void caption(HWND w, const std::wstring& s) {
    SetWindowTextW(w, s.c_str());
}
bool exists(const std::wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}
std::wstring absolute(const std::wstring& s) {
    if (s.empty())
        return {};
    DWORD n = GetFullPathNameW(s.c_str(), 0, nullptr, nullptr);
    if (!n)
        return {};
    std::wstring out(n, L'\0');
    n = GetFullPathNameW(s.c_str(), n, out.data(), nullptr);
    if (!n || n >= out.size())
        return {};
    out.resize(n);
    return out;
}
std::wstring byte_size(uint64_t bytes) {
    std::wostringstream out;
    if (bytes < 1024)
        out << bytes << L" B";
    else if (bytes < 1024 * 1024)
        out << std::fixed << std::setprecision(1) << double(bytes) / 1024 << L" KiB";
    else if (bytes >= 1024 * 1024 * 1024)
        out << std::fixed << std::setprecision(2) << double(bytes) / (1024 * 1024 * 1024)
            << L" GiB";
    else
        out << std::fixed << std::setprecision(1) << double(bytes) / (1024 * 1024) << L" MiB";
    return out.str();
}
struct DetailState {
    std::wstring contents;
    Strings strings;
    HWND edit = nullptr;
    HFONT font = nullptr;
};
LRESULT CALLBACK detail_proc(HWND w, UINT m, WPARAM wp, LPARAM lp) {
    auto* s = reinterpret_cast<DetailState*>(GetWindowLongPtrW(w, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        s = static_cast<DetailState*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        SetWindowLongPtrW(w, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(s));
    }
    if (!s)
        return DefWindowProcW(w, m, wp, lp);
    if (m == WM_CREATE) {
        s->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", s->contents.c_str(),
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_READONLY |
                                      ES_AUTOVSCROLL | WS_VSCROLL | WS_HSCROLL | ES_AUTOHSCROLL,
                                  0, 0, 0, 0, w, reinterpret_cast<HMENU>(1), nullptr, nullptr);
        SendMessageW(s->edit, WM_SETFONT, reinterpret_cast<WPARAM>(s->font), TRUE);
        for (auto id : {2, 3}) {
            HWND b = CreateWindowW(
                L"BUTTON", s->strings.get(id == 2 ? Text::copy : Text::close).c_str(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (id == 3 ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON),
                0, 0, 0, 0, w, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
            SendMessageW(b, WM_SETFONT, reinterpret_cast<WPARAM>(s->font), TRUE);
        }
    }
    if (m == WM_SIZE) {
        const int scale = static_cast<int>(GetDpiForWindow(w));
        const auto p = [&](int v) { return MulDiv(v, scale, 96); };
        const int width = LOWORD(lp), height = HIWORD(lp);
        MoveWindow(s->edit, p(20), p(20), width - p(40), height - p(100), TRUE);
        MoveWindow(GetDlgItem(w, 2), width - p(252), height - p(60), p(108), p(36), TRUE);
        MoveWindow(GetDlgItem(w, 3), width - p(132), height - p(60), p(108), p(36), TRUE);
    }
    if (m == WM_COMMAND && LOWORD(wp) == 2 && OpenClipboard(w)) {
        EmptyClipboard();
        auto block = GlobalAlloc(GMEM_MOVEABLE, (s->contents.size() + 1) * sizeof(wchar_t));
        if (block) {
            auto p = GlobalLock(block);
            if (p) {
                memcpy(p, s->contents.c_str(), (s->contents.size() + 1) * sizeof(wchar_t));
                GlobalUnlock(block);
                if (!SetClipboardData(CF_UNICODETEXT, block))
                    GlobalFree(block);
            } else
                GlobalFree(block);
        }
        CloseClipboard();
        return 0;
    }
    if ((m == WM_COMMAND && LOWORD(wp) == 3) || m == WM_CLOSE) {
        DestroyWindow(w);
        return 0;
    }
    return DefWindowProcW(w, m, wp, lp);
}
} // namespace
Wizard::Wizard(Strings strings, UINT test_dpi, bool test_high_contrast)
    : strings_(std::move(strings)), test_dpi_(test_dpi), test_high_contrast_(test_high_contrast) {}
Wizard::~Wizard() {
    if (gdiplus_token_)
        Gdiplus::GdiplusShutdown(gdiplus_token_);
    for (auto font : {body_font_, title_font_, small_font_, value_font_, emphasis_font_})
        if (font)
            DeleteObject(font);
    if (white_)
        DeleteObject(white_);
    if (background_)
        DeleteObject(background_);
}
int Wizard::px(int value) const {
    return MulDiv(value, static_cast<int>(dpi_), 96);
}
bool Wizard::create(HINSTANCE instance, int show) {
    Gdiplus::GdiplusStartupInput graphics_settings;
    if (!gdiplus_token_ &&
        Gdiplus::GdiplusStartup(&gdiplus_token_, &graphics_settings, nullptr) != Gdiplus::Ok)
        gdiplus_token_ = 0;
    WNDCLASSEXW wc{sizeof(wc)};
    wc.lpfnWndProc = procedure;
    wc.hInstance = instance;
    wc.lpszClassName = L"OST2PST.Wizard";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    wc.hIconSm = wc.hIcon;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return false;
    dpi_ = test_dpi_ ? test_dpi_ : GetDpiForSystem();
    window_ = CreateWindowExW(WS_EX_CONTROLPARENT, wc.lpszClassName,
                              strings_.get(Text::app).c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                              CW_USEDEFAULT, px(900), px(660), nullptr, nullptr, instance, this);
    if (!window_)
        return false;
    ShowWindow(window_, show);
    UpdateWindow(window_);
    return true;
}
LRESULT CALLBACK Wizard::procedure(HWND w, UINT m, WPARAM wp, LPARAM lp) {
    auto* self = reinterpret_cast<Wizard*>(GetWindowLongPtrW(w, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        self = static_cast<Wizard*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        self->window_ = w;
        SetWindowLongPtrW(w, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    return self ? self->message(m, wp, lp) : DefWindowProcW(w, m, wp, lp);
}
void Wizard::fonts() {
    HIGHCONTRASTW contrast{sizeof(contrast)};
    SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(contrast), &contrast, 0);
    high_contrast_ = test_high_contrast_ || (contrast.dwFlags & HCF_HIGHCONTRASTON) != 0;
    if (white_)
        DeleteObject(white_);
    if (background_)
        DeleteObject(background_);
    white_ = CreateSolidBrush(high_contrast_ ? GetSysColor(COLOR_WINDOW) : RGB(255, 255, 255));
    background_ = CreateSolidBrush(high_contrast_ ? GetSysColor(COLOR_WINDOW) : kBackground);
    for (auto* pair : {&body_font_, &title_font_, &small_font_, &value_font_, &emphasis_font_})
        if (*pair) {
            DeleteObject(*pair);
            *pair = nullptr;
        }
    const auto locale = strings_.locale();
    const auto* face = locale == "zh-Hans"   ? L"Microsoft YaHei UI"
                       : locale == "zh-Hant" ? L"Microsoft JhengHei UI"
                       : locale == "ja"      ? L"Yu Gothic UI"
                       : locale == "ko"      ? L"Malgun Gothic"
                                             : L"Segoe UI";
    auto make = [&](int size, int weight) {
        return CreateFontW(-MulDiv(size, static_cast<int>(dpi_), 72), 0, 0, 0, weight, FALSE, FALSE,
                           FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH, face);
    };
    body_font_ = make(11, FW_NORMAL);
    title_font_ = make(22, FW_SEMIBOLD);
    small_font_ = make(10, FW_NORMAL);
    value_font_ = make(20, FW_SEMIBOLD);
    emphasis_font_ = make(13, FW_SEMIBOLD);
    for (HWND child = GetWindow(window_, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT))
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(body_font_), FALSE);
    if (heading_)
        SendMessageW(heading_, WM_SETFONT, reinterpret_cast<WPARAM>(title_font_), FALSE);
    for (HWND h : {github_, coffee_, language_label_})
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(small_font_), FALSE);
    for (auto h : stat_labels_)
        if (h)
            SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(small_font_), FALSE);
    for (auto h : stat_values_)
        if (h)
            SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(value_font_), FALSE);
}
void Wizard::build_controls() {
    auto control = [&](const wchar_t* type, const std::wstring& value, DWORD style, int id = 0,
                       DWORD ex = 0) {
        return CreateWindowExW(ex, type, value.c_str(), WS_CHILD | style, 0, 0, 0, 0, window_,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                               GetModuleHandleW(nullptr), nullptr);
    };
    heading_ = control(L"STATIC", L"", SS_LEFT);
    intro_ = control(L"STATIC", L"", SS_LEFT);
    label_ = control(L"STATIC", L"", SS_LEFT);
    browse_ = control(L"BUTTON", L"", WS_TABSTOP | BS_OWNERDRAW, kBrowse);
    path_ = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, kPath, WS_EX_CLIENTEDGE);
    SendMessageW(path_, EM_SETLIMITTEXT, 32760, 0);
    location_ = control(L"STATIC", L"", SS_PATHELLIPSIS);
    note_ = control(L"STATIC", L"", SS_LEFT);
    phase_ = control(L"STATIC", L"", SS_LEFT);
    progress_ = control(PROGRESS_CLASSW, L"", PBS_SMOOTH);
    SendMessageW(progress_, PBM_SETRANGE32, 0, 1000);
    processed_ = control(L"STATIC", L"", SS_LEFT);
    elapsed_ = control(L"STATIC", L"", SS_LEFT);
    for (int i = 0; i < 3; ++i) {
        stat_labels_[i] = control(L"STATIC",
                                  strings_.get(i == 0   ? Text::normal
                                               : i == 1 ? Text::fai
                                                        : Text::skipped),
                                  SS_LEFT);
        stat_values_[i] = control(L"STATIC", L"0", SS_LEFT);
    }
    back_ = control(L"BUTTON", strings_.get(Text::back), WS_TABSTOP | BS_OWNERDRAW, kBack);
    primary_ = control(L"BUTTON", L"", WS_TABSTOP | BS_OWNERDRAW, kPrimary);
    close_ = control(L"BUTTON", strings_.get(Text::close), WS_TABSTOP | BS_OWNERDRAW, kClose);
    details_ = control(L"BUTTON", strings_.get(Text::details), WS_TABSTOP | BS_OWNERDRAW, kDetails);
    report_ = control(L"BUTTON", strings_.get(Text::report), WS_TABSTOP | BS_OWNERDRAW, kReport);
    folder_ = control(L"BUTTON", strings_.get(Text::folder), WS_TABSTOP | BS_OWNERDRAW, kFolder);
    resume_ = control(L"BUTTON", strings_.get(Text::resume), WS_TABSTOP | BS_OWNERDRAW, kResume);
    language_label_ = control(L"STATIC", strings_.get(Text::language), SS_RIGHT);
    language_ = control(L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, kLanguage);
    INITCOMMONCONTROLSEX links{sizeof(links), ICC_LINK_CLASS};
    InitCommonControlsEx(&links);
    github_ = control(WC_LINK, link_start(kGithubUrl) + L"GitHub ↗</a>",
                      WS_TABSTOP | LWS_TRANSPARENT | LWS_NOPREFIX, kGithub);
    coffee_ = control(WC_LINK, L"", WS_TABSTOP | LWS_TRANSPARENT | LWS_NOPREFIX, kCoffee);
    for (size_t i = 0; i < std::size(kCatalogs); ++i) {
        const auto& catalog = kCatalogs[i];
        SendMessageW(language_, CB_ADDSTRING, 0,
                     reinterpret_cast<LPARAM>(
                         catalog.strings[static_cast<size_t>(Text::language_name)].data()));
        if (catalog.locale == strings_.locale())
            SendMessageW(language_, CB_SETCURSEL, i, 0);
    }
    fonts();
    DragAcceptFiles(window_, TRUE);
}
void Wizard::layout() {
    RECT r;
    GetClientRect(window_, &r);
    const int width = MulDiv(r.right, 96, static_cast<int>(dpi_)),
              height = MulDiv(r.bottom, 96, static_cast<int>(dpi_));
    auto place = [&](HWND w, int x, int y, int cx, int cy) {
        MoveWindow(w, px(x), px(y), px(cx), px(cy), TRUE);
    };
    const int left = 64, right = width - 64, content = right - left;
    place(github_, 180, 25, 72, 23);
    place(language_label_, width - 358, 29, 140, 24);
    place(language_, width - 208, 22, 176, 300);
    const bool compact = height < 560;
    const auto y = [&](int offset) { return content_y(height, offset); };
    const bool complete = step_ == 3 && snapshot_.verdict == Verdict::kComplete;
    const int heading_inset = complete ? 52 : 0;
    place(heading_, left + heading_inset, y(22), content - heading_inset, 44);
    place(intro_, left, y(82), content, 24);
    place(label_, left, y(step_ == 1 ? 130 : 250), content, 24);
    const int browse_width = 160;
    if (step_ == 0) {
        place(browse_, left, y(116), content, compact ? 86 : 110);
        place(path_, left, y(282), content, compact ? 30 : 36);
        SendMessageW(path_, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                     MAKELPARAM(px(8), px(8)));
    } else {
        place(path_, left, y(164), content - browse_width - 12, 40);
        place(browse_, right - browse_width, y(164), browse_width, 40);
    }
    place(location_, left, y(compact ? 91 : 84), content, 24);
    place(note_, left, y(step_ == 1 ? 226 : 332), content, step_ == 0 ? 24 : 76);
    if (step_ == 3)
        place(note_, left, y(241), content, complete ? 28 : compact ? 56 : 72);
    place(coffee_, left, height - 135, content, 30);
    place(phase_, left, y(97), content, 28);
    place(progress_, left, y(141), content, 8);
    place(processed_, left, y(166), content, 24);
    place(elapsed_, left, y(308), content, 26);
    for (int i = 0; i < 3; ++i) {
        const RECT box = metric_box(width, height, step_, i);
        const int x = box.left + 16, cx = box.right - x - 12;
        place(stat_labels_[i], x, box.top + (compact ? 6 : 12), cx, 22);
        place(stat_values_[i], x, box.bottom - (compact ? 38 : 45), cx, 36);
    }
    const int bottom = height - 65;
    // Measure localized action labels, sharing remaining space without hardcoded English widths.
    HDC dc = GetDC(window_);
    auto old = SelectObject(dc, body_font_);
    auto button_width = [&](HWND w, int minimum) {
        SIZE size{};
        auto s = text(w);
        GetTextExtentPoint32W(dc, s.data(), static_cast<int>(s.size()), &size);
        return std::max(minimum, MulDiv(size.cx, 96, static_cast<int>(dpi_)) + 34);
    };
    int primary_width = button_width(primary_, 160), close_width = button_width(close_, 100),
        back_width = button_width(back_, 100);
    place(close_, width - 32 - close_width, bottom, close_width, 38);
    place(primary_, width - 44 - close_width - primary_width, bottom, primary_width, 38);
    place(back_, 32, bottom, back_width, 38);
    if (step_ == 3) {
        // Every result action shares the footer baseline, including recovery actions.
        int x = 32;
        for (HWND button : {details_, report_, folder_, resume_}) {
            if (!IsWindowVisible(button))
                continue;
            int size = button_width(button, 70) - 10;
            place(button, x, bottom, size, 38);
            x += size + 8;
        }
        primary_width = button_width(primary_, 120) - 10;
        close_width = button_width(close_, 70) - 10;
        place(close_, width - 32 - close_width, bottom, close_width, 38);
        place(primary_, width - 40 - close_width - primary_width, bottom, primary_width, 38);
    }
    SelectObject(dc, old);
    ReleaseDC(window_, dc);
    InvalidateRect(window_, nullptr, TRUE);
}
void Wizard::page(bool focus) {
    auto show = [](HWND w, bool yes) { ShowWindow(w, yes ? SW_SHOW : SW_HIDE); };
    show(heading_, true);
    show(language_, true);
    show(language_label_, true);
    show(github_, true);
    show(intro_, step_ == 0);
    caption(intro_, strings_.get(Text::source_intro));
    const bool complete = step_ == 3 && snapshot_.verdict == Verdict::kComplete;
    show(coffee_, complete);
    if (complete)
        caption(coffee_, strings_.format(Text::coffee, link_start(kCoffeeUrl), L"</a>"));
    caption(language_label_, strings_.get(Text::language));
    for (const auto& pair : {std::pair{back_, Text::back},
                             {close_, Text::close},
                             {details_, Text::details},
                             {report_, Text::report},
                             {folder_, Text::folder},
                             {resume_, Text::resume}})
        caption(pair.first, strings_.get(pair.second));
    for (int i = 0; i < 3; ++i)
        caption(stat_labels_[i], strings_.get(i == 0   ? Text::normal
                                              : i == 1 ? Text::fai
                                                       : Text::skipped));
    show(path_, step_ < 2);
    show(browse_, step_ < 2);
    show(label_, step_ < 2);
    show(location_, step_ == 1 || step_ == 3);
    show(back_, step_ == 1);
    show(primary_, true);
    show(close_, true);
    show(phase_, step_ == 2);
    show(progress_, step_ == 2);
    show(processed_, step_ == 2);
    show(elapsed_, step_ == 2);
    for (int i = 0; i < 3; ++i) {
        show(stat_labels_[i], step_ >= 2);
        show(stat_values_[i], step_ >= 2);
    }
    show(details_, step_ == 3);
    show(report_, step_ == 3 && snapshot_.session.result.has_value() &&
                      (snapshot_.verdict == Verdict::kComplete ||
                       snapshot_.verdict == Verdict::kIncomplete));
    show(folder_, step_ == 3 && !output_.empty());
    show(resume_,
         step_ == 3 && snapshot_.verdict != Verdict::kComplete && exists(output_ + L".work"));
    show(note_, step_ != 2);
    if (step_ < 2) {
        caption(heading_, strings_.get(step_ == 0 ? Text::source_title : Text::destination_title));
        caption(label_, strings_.get(step_ == 0 ? Text::source_label : Text::destination_label));
        caption(path_, step_ == 0 ? source_ : output_);
        const auto hint = step_ == 0 ? strings_.get(Text::path_hint) : std::wstring{};
        SendMessageW(path_, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(hint.c_str()));
        caption(browse_, strings_.get(step_ == 1 ? Text::browse
                                                 : (source_.empty() ? Text::choose_file
                                                                    : Text::change_file)));
        caption(location_, strings_.get(Text::source) + L"   ·   " + source_);
        caption(note_, L"");
        note_key_ = Text::kSize;
    }
    caption(primary_,
            strings_.get(step_ < 1    ? Text::next
                         : step_ == 1 ? (exists(absolute(text(path_)) + L".work") ? Text::resume
                                                                                  : Text::start)
                         : step_ == 2 ? (stopping_ ? Text::stopping : Text::stop)
                                      : Text::another));
    if (step_ == 1 && exists(output_ + L".work"))
        set_note(Text::recovery);
    EnableWindow(primary_, !stopping_ && (step_ != 0 || GetWindowTextLengthW(path_) != 0));
    EnableWindow(close_, !closing_);
    if (step_ == 2)
        caption(heading_, strings_.get(Text::conversion_title));
    render_state();
    layout();
    if (focus)
        SetFocus(step_ == 0   ? (source_.empty() ? browse_ : primary_)
                 : step_ == 1 ? path_
                              : primary_);
}
void Wizard::change_language() {
    auto index = SendMessageW(language_, CB_GETCURSEL, 0, 0);
    if (index == CB_ERR || static_cast<size_t>(index) >= std::size(kCatalogs))
        return;
    if (step_ == 0)
        source_ = text(path_);
    else if (step_ == 1)
        output_ = text(path_);
    const auto note = note_key_;
    strings_ = Strings({from_utf8(std::string(kCatalogs[index].locale))});
    fonts();
    page(false);
    if (step_ < 2 && note != Text::kSize)
        set_note(note);
    if (running_)
        SendMessageW(window_, WM_TIMER, 1, 0);
}
void Wizard::set_note(Text t) {
    note_key_ = t;
    caption(note_, strings_.get(t));
}
bool Wizard::validate_source() {
    source_ = absolute(text(path_));
    DWORD attr = GetFileAttributesW(source_.c_str());
    if (source_.empty() || attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        set_note(Text::invalid_source);
        return false;
    }
    return true;
}
bool Wizard::validate_destination(bool& resume) {
    const auto entered = text(path_);
    const auto original_leaf = std::filesystem::path(entered).filename().wstring();
    output_ = absolute(entered);
    const auto path = std::filesystem::path(output_);
    auto extension = path.extension().wstring();
    for (auto& c : extension)
        c = static_cast<wchar_t>(towlower(c));
    std::error_code ec;
    auto device = original_leaf.substr(0, original_leaf.find(L'.'));
    while (!device.empty() && device.back() == L' ')
        device.pop_back();
    for (auto& c : device)
        c = static_cast<wchar_t>(towupper(c));
    const bool reserved =
        device == L"CON" || device == L"PRN" || device == L"AUX" || device == L"NUL" ||
        device == L"CONIN$" || device == L"CONOUT$" ||
        (device.size() == 4 && (device.starts_with(L"COM") || device.starts_with(L"LPT")) &&
         (device[3] >= L'1' && device[3] <= L'9'));
    if (output_.empty() || original_leaf.empty() || original_leaf.back() == L'.' ||
        original_leaf.back() == L' ' ||
        original_leaf.find_first_of(L"<>:\"/\\|?*") != std::wstring::npos || extension != L".pst" ||
        reserved ||
        std::any_of(original_leaf.begin(), original_leaf.end(), [](wchar_t c) { return c < 32; }) ||
        !std::filesystem::is_directory(path.parent_path(), ec)) {
        set_note(Text::invalid_destination);
        return false;
    }
    resume = exists(output_ + L".work");
    ec.clear();
    if (CompareStringOrdinal(source_.c_str(), -1, output_.c_str(), -1, TRUE) == CSTR_EQUAL ||
        std::filesystem::equivalent(std::filesystem::path(source_), path, ec)) {
        set_note(Text::collision);
        return false;
    }
    if (!resume && (exists(output_) || exists(output_ + L".report.json") ||
                    exists(output_ + L".items.jsonl"))) {
        set_note(Text::collision);
        return false;
    }
    return true;
}
void Wizard::select_source(const std::wstring& path) {
    // Only probe a file explicitly picked/dropped, never probe disk per keystroke.
    picked_path_ = path;
    WIN32_FILE_ATTRIBUTE_DATA data{};
    picked_size_.clear();
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data) &&
        !(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        picked_size_ = byte_size((uint64_t(data.nFileSizeHigh) << 32) | data.nFileSizeLow);
    caption(path_, path);
    SetFocus(primary_);
}
void Wizard::browse() {
    IFileDialog* dialog = nullptr;
    HRESULT hr = CoCreateInstance(step_ == 0 ? CLSID_FileOpenDialog : CLSID_FileSaveDialog, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
    if (FAILED(hr))
        return;
    COMDLG_FILTERSPEC filter{step_ == 0 ? L"Outlook OST (*.ost)" : L"Outlook PST (*.pst)",
                             step_ == 0 ? L"*.ost" : L"*.pst"};
    dialog->SetFileTypes(1, &filter);
    dialog->SetDefaultExtension(step_ == 0 ? L"ost" : L"pst");
    dialog->SetTitle(
        strings_.get(step_ == 0 ? Text::source_title : Text::destination_title).c_str());
    DWORD options = 0;
    dialog->GetOptions(&options);
    options |= FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR;
    if (step_ == 0)
        options |= FOS_FILEMUSTEXIST;
    else {
        options &= ~FOS_OVERWRITEPROMPT;
        if (!output_.empty())
            dialog->SetFileName(std::filesystem::path(output_).filename().c_str());
    }
    dialog->SetOptions(options);
    if (SUCCEEDED(dialog->Show(window_))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dialog->GetResult(&item))) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                if (step_ == 0)
                    select_source(path);
                else
                    caption(path_, path);
                CoTaskMemFree(path);
                caption(note_, L"");
                note_key_ = Text::kSize;
            }
            item->Release();
        }
    }
    dialog->Release();
}
void Wizard::start(bool resume) {
    running_ = true;
    stopping_ = false;
    snapshot_ = {};
    snapshot_.run = ++run_id_;
    started_ = std::chrono::steady_clock::now();
    step_ = 2;
    page();
    caption(phase_, strings_.get(Text::phase_identity));
    caption(processed_, L"");
    caption(elapsed_, L"");
    for (auto h : stat_values_)
        caption(h, L"0");
    render_progress(false);
    SetTimer(window_, 1, 1000, nullptr);
    host_.start(window_, run_id_, worker_path(), source_, output_, resume);
}
void Wizard::updated() {
    auto s = host_.snapshot();
    if (s.run != run_id_)
        return;
    snapshot_ = std::move(s);
    render_state();
    if (!snapshot_.finished)
        return;
    running_ = false;
    stopping_ = false;
    KillTimer(window_, 1);
    if (closing_) {
        DestroyWindow(window_);
        return;
    }
    step_ = 3;
    page();
}
void Wizard::render_state() {
    const auto& session = snapshot_.session;
    if (step_ >= 2) {
        Text phase = Text::phase_identity;
        const std::pair<const char*, Text> phases[] = {{"index", Text::phase_index},
                                                       {"items", Text::phase_items},
                                                       {"folders", Text::phase_folders},
                                                       {"assembly", Text::phase_assembly},
                                                       {"verification", Text::phase_verification},
                                                       {"publication", Text::phase_publication},
                                                       {"published", Text::phase_published}};
        for (const auto& p : phases)
            if (session.phase == p.first)
                phase = p.second;
        caption(phase_, strings_.get(phase));
        const bool items = session.phase == "items" && session.total && *session.total > 0;
        render_progress(items,
                        items ? static_cast<int>(static_cast<long double>(session.counts.terminal) *
                                                 1000 / *session.total)
                              : 0);
        caption(processed_,
                strings_.get(Text::processed) + L"   " +
                    (session.total
                         ? strings_.format(Text::count, std::to_wstring(session.counts.terminal),
                                           std::to_wstring(*session.total))
                         : std::to_wstring(session.counts.terminal)));
        caption(stat_values_[0], std::to_wstring(session.counts.normal));
        caption(stat_values_[1], std::to_wstring(session.counts.fai));
        caption(stat_values_[2], std::to_wstring(session.counts.skipped));
    }
    if (step_ != 3)
        return;
    const auto verdict = snapshot_.verdict;
    caption(heading_, strings_.get(verdict == Verdict::kComplete     ? Text::complete
                                   : verdict == Verdict::kIncomplete ? Text::incomplete
                                   : verdict == Verdict::kStopped    ? Text::stopped
                                                                     : Text::failed));
    caption(location_, output_);
    if (verdict == Verdict::kComplete) {
        const auto& r = *session.result;
        caption(note_, strings_.get(Text::folders) + L"   " + std::to_wstring(r.folders) +
                           L"     ·     " + strings_.get(Text::size) + L"   " + byte_size(r.bytes));
    } else if (verdict == Verdict::kIncomplete)
        set_note(Text::incomplete_note);
    else if (verdict == Verdict::kStopped)
        set_note(Text::retained);
    else if (snapshot_.launch_error)
        set_note(Text::worker_missing);
    else if (session.broken || !session.terminal || !session.error_seen)
        set_note(Text::protocol_error);
    else if (session.error_kind == "unsupported")
        set_note(Text::unsupported);
    else if (session.error_scope == "input")
        set_note(Text::input_error);
    else
        set_note(Text::operation_error);
}
void Wizard::render_progress(bool items, int position) {
    const bool marquee = !items && running_ && !snapshot_.finished;
    if (marquee != progress_marquee_) {
        // Changing range/style or reissuing SETMARQUEE on each snapshot restarts native
        // animation. Change mode only once at a phase boundary, including language refreshes.
        if (progress_marquee_)
            SendMessageW(progress_, PBM_SETMARQUEE, FALSE, 0);
        LONG_PTR style = GetWindowLongPtrW(progress_, GWL_STYLE);
        SetWindowLongPtrW(progress_, GWL_STYLE,
                          marquee ? style | PBS_MARQUEE : style & ~PBS_MARQUEE);
        if (marquee)
            SendMessageW(progress_, PBM_SETMARQUEE, TRUE, 30);
        progress_marquee_ = marquee;
        progress_position_ = -1;
    }
    if (!marquee) {
        position = std::clamp(position, 0, 1000);
        if (position != progress_position_) {
            SendMessageW(progress_, PBM_SETPOS, position, 0);
            progress_position_ = position;
        }
    }
}
void Wizard::command(int id) {
    if (id == kBrowse && step_ < 2)
        browse();
    else if (id == kBack && step_ == 1) {
        output_ = text(path_);
        step_ = 0;
        page();
    } else if (id == kPrimary) {
        if (step_ == 0 && validate_source()) {
            if (output_.empty()) {
                auto p = std::filesystem::path(source_);
                p.replace_extension(L".pst");
                output_ = p.wstring();
                for (int n = 2;
                     exists(output_) || exists(output_ + L".work") ||
                     exists(output_ + L".report.json") || exists(output_ + L".items.jsonl");
                     ++n)
                    output_ = (p.parent_path() /
                               (p.stem().wstring() + L" (" + std::to_wstring(n) + L").pst"))
                                  .wstring();
            }
            step_ = 1;
            page();
        } else if (step_ == 1) {
            bool resume = false;
            if (validate_destination(resume))
                start(resume);
        } else if (step_ == 2 && !stopping_) {
            stopping_ = true;
            caption(primary_, strings_.get(Text::stopping));
            EnableWindow(primary_, FALSE);
            host_.stop();
        } else if (step_ == 3) {
            source_.clear();
            output_.clear();
            picked_path_.clear();
            picked_size_.clear();
            step_ = 0;
            page();
        }
    } else if (id == kClose)
        SendMessageW(window_, WM_CLOSE, 0, 0);
    else if (id == kResume && step_ == 3 && !running_)
        start(true);
    else if (id == kDetails && step_ == 3)
        show_details();
    else if (id == kReport && step_ == 3 && snapshot_.session.result &&
             (snapshot_.verdict == Verdict::kComplete || snapshot_.verdict == Verdict::kIncomplete))
        open_path(output_ + L".report.json");
    else if (id == kFolder && step_ == 3)
        open_path(std::filesystem::path(output_).parent_path().wstring());
}
void Wizard::open_path(const std::wstring& path, Text on_error) {
    if (reinterpret_cast<INT_PTR>(
            ShellExecuteW(window_, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL)) <= 32)
        MessageBoxW(window_, strings_.get(on_error).c_str(), strings_.get(Text::app).c_str(),
                    MB_OK | MB_ICONERROR);
}
void Wizard::show_details() {
    DetailState state;
    state.strings = strings_;
    state.font = body_font_;
    state.contents =
        snapshot_.diagnostics_truncated ? strings_.get(Text::truncated) + L"\r\n\r\n" : L"";
    state.contents +=
        from_utf8(snapshot_.session.error_detail) + L"\r\n" + from_utf8(snapshot_.diagnostics);
    state.contents += L"\r\nexit=" + std::to_wstring(snapshot_.exit_code) + L"  Win32=" +
                      std::to_wstring(snapshot_.launch_error);
    // Read-only edit controls require CRLF for diagnostics produced with Unix newlines.
    for (size_t i = 0; (i = state.contents.find(L'\n', i)) != std::wstring::npos; ++i)
        if (i == 0 || state.contents[i - 1] != L'\r') {
            state.contents.insert(i, 1, L'\r');
            ++i;
        }
    WNDCLASSW wc{};
    wc.lpfnWndProc = detail_proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"OST2PST.Details";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
    RegisterClassW(&wc);
    RECT parent;
    GetWindowRect(window_, &parent);
    HWND detail =
        CreateWindowExW(WS_EX_CONTROLPARENT, wc.lpszClassName, strings_.get(Text::details).c_str(),
                        WS_OVERLAPPEDWINDOW, parent.left + px(20), parent.top + px(20), px(800),
                        px(500), window_, nullptr, wc.hInstance, &state);
    if (!detail)
        return;
    EnableWindow(window_, FALSE);
    ShowWindow(detail, SW_SHOW);
    SetFocus(state.edit);
    MSG msg{};
    while (IsWindow(detail) && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
            DestroyWindow(detail);
            continue;
        }
        if (!IsDialogMessageW(detail, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(window_, TRUE);
    SetActiveWindow(window_);
    SetFocus(details_);
}
void Wizard::draw_button(const DRAWITEMSTRUCT& item) {
    if (item.hwndItem == browse_ && step_ == 0) {
        draw_source_picker(item);
        return;
    }
    const bool disabled = (item.itemState & ODS_DISABLED) != 0;
    const bool secondary = item.hwndItem != primary_;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    const bool highlighted = !disabled && (!secondary || pressed);
    const auto fill = high_contrast_ ? GetSysColor(highlighted ? COLOR_HIGHLIGHT : COLOR_WINDOW)
                      : disabled     ? RGB(228, 233, 241)
                      : secondary    ? (pressed ? kTint : RGB(255, 255, 255))
                      : pressed      ? RGB(25, 65, 170)
                                     : kAccent;
    const auto saved = SaveDC(item.hDC);
    FillRect(item.hDC, &item.rcItem, item.hwndItem == browse_ ? white_ : background_);
    panel(item.hDC, item.rcItem, px(10), fill,
          secondary ? (high_contrast_ ? GetSysColor(COLOR_WINDOWTEXT) : kLine) : fill);
    SetBkMode(item.hDC, TRANSPARENT);
    SetTextColor(item.hDC, high_contrast_ ? GetSysColor(disabled      ? COLOR_GRAYTEXT
                                                        : highlighted ? COLOR_HIGHLIGHTTEXT
                                                                      : COLOR_WINDOWTEXT)
                           : disabled     ? kMuted
                           : secondary    ? kInk
                                          : RGB(255, 255, 255));
    SelectObject(item.hDC, body_font_);
    auto t = text(item.hwndItem);
    RECT r = item.rcItem;
    DrawTextW(item.hDC, t.c_str(), -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) {
        InflateRect(&r, -px(4), -px(4));
        DrawFocusRect(item.hDC, &r);
    }
    RestoreDC(item.hDC, saved);
}
void Wizard::draw_source_picker(const DRAWITEMSTRUCT& item) {
    const HDC dc = item.hDC;
    const int saved = SaveDC(dc);
    const RECT r = item.rcItem;
    const int mid = (r.top + r.bottom) / 2;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    const auto paper = high_contrast_ ? GetSysColor(COLOR_WINDOW) : RGB(255, 255, 255);
    const auto ink = high_contrast_ ? GetSysColor(COLOR_WINDOWTEXT) : kInk;
    const auto accent = high_contrast_ ? GetSysColor(COLOR_HIGHLIGHT) : kAccent;
    FillRect(dc, &r, white_);
    panel(dc, r, px(18),
          high_contrast_ ? paper
          : pressed      ? RGB(227, 237, 255)
                         : kTint,
          high_contrast_ ? ink : RGB(188, 206, 242));
    // A stacked envelope, drawn in logical pixels. No image assets or icon font.
    const int x = px(22);
    panel(dc, {x, mid - px(28), x + px(56), mid + px(28)}, px(14), paper,
          high_contrast_ ? ink : kLine);
    panel(dc, {x + px(18), mid - px(13), x + px(39), mid + px(6)}, px(4),
          high_contrast_ ? paper : RGB(217, 230, 255), accent);
    panel(dc, {x + px(11), mid - px(6), x + px(43), mid + px(14)}, px(4), paper, accent);
    POINT flap[] = {
        {x + px(12), mid - px(5)}, {x + px(27), mid + px(5)}, {x + px(41), mid - px(5)}};
    Polyline(dc, flap, 3);
    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, body_font_);
    const auto action = text(browse_);
    SIZE size{};
    GetTextExtentPoint32W(dc, action.c_str(), static_cast<int>(action.size()), &size);
    RECT button{r.right - px(20) - std::max(px(124), static_cast<int>(size.cx) + px(32)),
                mid - px(19), r.right - px(20), mid + px(19)};
    auto entered = text(path_);
    bool empty = entered.empty();
    const auto button_fill = empty || high_contrast_ ? accent : paper;
    panel(dc, button, px(9), button_fill, empty || high_contrast_ ? accent : kLine);
    SetTextColor(dc, high_contrast_ ? GetSysColor(COLOR_HIGHLIGHTTEXT)
                     : empty        ? RGB(255, 255, 255)
                                    : kAccent);
    DrawTextW(dc, action.c_str(), -1, &button,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    RECT name{x + px(72), mid - px(25), button.left - px(16), mid + px(3)};
    auto title = empty ? strings_.get(Text::drop_title)
                       : std::filesystem::path(entered).filename().wstring();
    if (title.empty())
        title = entered;
    SetTextColor(dc, ink);
    SelectObject(dc, emphasis_font_);
    DrawTextW(dc, title.c_str(), -1, &name,
              DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    RECT type{name.left, mid + px(4), name.right, mid + px(27)};
    SelectObject(dc, small_font_);
    SetTextColor(dc, high_contrast_ ? ink : kMuted);
    std::wstring detail = L"Outlook  ·  .ost";
    if (!empty && entered == picked_path_ && !picked_size_.empty())
        detail += L"  ·  " + picked_size_;
    DrawTextW(dc, detail.c_str(), -1, &type, DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) {
        RECT focus = button;
        InflateRect(&focus, px(3), px(3));
        if (high_contrast_)
            DrawFocusRect(dc, &focus);
        else {
            SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
            SelectObject(dc, GetStockObject(DC_PEN));
            SetDCPenColor(dc, accent);
            RoundRect(dc, focus.left, focus.top, focus.right, focus.bottom, px(11), px(11));
        }
    }
    RestoreDC(dc, saved);
}
void Wizard::paint() {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(window_, &ps);
    RECT r;
    GetClientRect(window_, &r);
    FillRect(dc, &r, background_);
    const bool compact = MulDiv(r.bottom, 96, static_cast<int>(dpi_)) < 560;
    const int saved = SaveDC(dc);
    const auto paper = high_contrast_ ? GetSysColor(COLOR_WINDOW) : RGB(255, 255, 255);
    const auto ink = high_contrast_ ? GetSysColor(COLOR_WINDOWTEXT) : kInk;
    RECT header{0, 0, r.right, px(56)};
    FillRect(dc, &header, white_);
    RECT card{px(32), px(compact ? 95 : 112), r.right - px(32), r.bottom - px(88)};
    panel(dc, card, px(18), paper, high_contrast_ ? ink : kLine);
    const int width = MulDiv(r.right, 96, static_cast<int>(dpi_));
    const int height = MulDiv(r.bottom, 96, static_cast<int>(dpi_));
    if (step_ >= 2) {
        for (int i = 0; i < 3; ++i) {
            const RECT box = metric_box(width, height, step_, i);
            panel(dc, {px(box.left), px(box.top), px(box.right), px(box.bottom)}, px(12),
                  high_contrast_ ? paper : kMetricFill, high_contrast_ ? ink : kLine);
        }
    }
    if (step_ == 3 && snapshot_.verdict == Verdict::kComplete) {
        const int top = px(content_y(height, 22) + 3);
        const auto green = high_contrast_ ? ink : RGB(26, 112, 79);
        const auto tint = high_contrast_ ? paper : RGB(229, 245, 235);
        panel(dc, {px(64), top, px(102), top + px(38)}, px(38), tint, high_contrast_ ? ink : tint);
        const auto pen = CreatePen(PS_SOLID, px(3), green);
        const auto old = SelectObject(dc, pen);
        POINT mark[] = {{px(74), top + px(19)}, {px(80), top + px(25)}, {px(92), top + px(12)}};
        Polyline(dc, mark, 3);
        SelectObject(dc, old);
        DeleteObject(pen);
        RECT rule{px(64), r.bottom - px(150), r.right - px(64), r.bottom - px(149)};
        SetDCBrushColor(dc, high_contrast_ ? ink : kLine);
        FillRect(dc, &rule, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
    }
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, ink);
    SelectObject(dc, emphasis_font_);
    auto icon = reinterpret_cast<HICON>(GetClassLongPtrW(window_, GCLP_HICON));
    DrawIconEx(dc, px(32), px(20), icon, px(30), px(30), 0, nullptr, DI_NORMAL);
    RECT brand{px(72), px(20), px(157), px(50)};
    DrawTextW(dc, L"OST2PST", -1, &brand, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT divider{px(162), px(26), px(163), px(45)};
    FillRect(dc, &divider, GetSysColorBrush(COLOR_3DSHADOW));
    SelectObject(dc, small_font_);
    const Text labels[] = {Text::source, Text::destination, Text::conversion, Text::result};
    const int col = (r.right - px(64)) / 4;
    for (int i = 0; i < 4; ++i) {
        const int left = px(32) + col * i;
        const COLORREF color = high_contrast_ ? GetSysColor(COLOR_WINDOWTEXT)
                               : i == step_   ? kAccent
                                              : kMuted;
        SetTextColor(dc, color);
        const int top = px(compact ? 61 : 69);
        const bool marked = i <= step_;
        const auto marker = high_contrast_ ? GetSysColor(COLOR_HIGHLIGHT) : kAccent;
        RECT number{left, top, left + px(23), top + px(23)};
        const auto fill = marked ? marker : paper;
        const auto edge = marked ? marker : (high_contrast_ ? ink : kLine);
        if (!gdiplus_token_ || !step_circle(dc, number, dpi_ / 96.0f, fill, edge))
            panel(dc, number, px(23), fill, edge);
        SetTextColor(
            dc, marked ? (high_contrast_ ? GetSysColor(COLOR_HIGHLIGHTTEXT) : RGB(255, 255, 255))
                       : color);
        const auto n = std::to_wstring(i + 1);
        DrawTextW(dc, n.c_str(), -1, &number, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
        SetTextColor(dc, color);
        const auto s = strings_.get(labels[i]);
        RECT label{left + px(32), top, left + col - px(8), top + px(23)};
        DrawTextW(dc, s.c_str(), -1, &label, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        SIZE extent{};
        GetTextExtentPoint32W(dc, s.c_str(), static_cast<int>(s.size()), &extent);
        RECT line{label.left + extent.cx + px(12), top + px(11), left + col - px(12), top + px(12)};
        if (i != 3 && line.left < line.right) {
            SetDCBrushColor(dc, high_contrast_ ? ink : kLine);
            FillRect(dc, &line, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
        }
    }
    RestoreDC(dc, saved);
    EndPaint(window_, &ps);
}
bool Wizard::layout_valid() const {
    RECT client;
    GetClientRect(window_, &client);
    std::vector<RECT> buttons;
    for (auto child = GetWindow(window_, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        if (!IsWindowVisible(child))
            continue;
        RECT r;
        GetWindowRect(child, &r);
        MapWindowPoints(nullptr, window_, reinterpret_cast<POINT*>(&r), 2);
        // A closed combo's window rect includes its drop-down height on some Windows versions.
        if (child == language_)
            r.bottom = r.top + px(32);
        if (r.left < 0 || r.top < 0 || r.right > client.right || r.bottom > client.bottom ||
            r.right <= r.left || r.bottom <= r.top)
            return false;
        if (child == github_ || child == coffee_) {
            SIZE ideal{};
            if (!SendMessageW(child, LM_GETIDEALSIZE, r.right - r.left,
                              reinterpret_cast<LPARAM>(&ideal)) ||
                ideal.cy > r.bottom - r.top)
                return false;
        }
        wchar_t name[32];
        GetClassNameW(child, name, 32);
        if (std::wstring(name) == L"Button") {
            for (const auto& b : buttons) {
                RECT overlap;
                if (IntersectRect(&overlap, &r, &b))
                    return false;
            }
            buttons.push_back(r);
            HDC dc = GetDC(child);
            SelectObject(dc, body_font_);
            SIZE sz;
            auto s = text(child);
            GetTextExtentPoint32W(dc, s.c_str(), static_cast<int>(s.size()), &sz);
            ReleaseDC(child, dc);
            if (sz.cx + px(12) > r.right - r.left || sz.cy > r.bottom - r.top) {
                std::fprintf(stderr, "Control %d size=%ldx%ld text=%ldx%ld\n", GetDlgCtrlID(child),
                             r.right - r.left, r.bottom - r.top, sz.cx, sz.cy);
                return false;
            }
        }
    }
    return true;
}
LRESULT Wizard::message(UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case DM_GETDEFID:
        return MAKELONG(step_ == 0 && !GetWindowTextLengthW(path_) ? kBrowse : kPrimary,
                        DC_HASDEFID);
    case DM_SETDEFID:
        return TRUE;
    case WM_CREATE:
        dpi_ = test_dpi_ ? test_dpi_ : GetDpiForWindow(window_);
        build_controls();
        page();
        return 0;
    case WM_SIZE:
        if (heading_)
            layout();
        return 0;
    case WM_GETMINMAXINFO: {
        auto* limits = reinterpret_cast<MINMAXINFO*>(lp);
        limits->ptMinTrackSize = {px(900), px(540)};
        return 0;
    }
    case WM_DPICHANGED: {
        dpi_ = HIWORD(wp);
        auto* r = reinterpret_cast<RECT*>(lp);
        fonts();
        SetWindowPos(window_, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        layout();
        return 0;
    }
    case WM_SETTINGCHANGE:
    case WM_THEMECHANGED:
        fonts();
        layout();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == kPath && HIWORD(wp) == EN_CHANGE && step_ < 2) {
            caption(note_, L"");
            note_key_ = Text::kSize;
            if (step_ == 0) {
                const bool entered = GetWindowTextLengthW(path_) != 0;
                EnableWindow(primary_, entered);
                caption(browse_, strings_.get(entered ? Text::change_file : Text::choose_file));
                InvalidateRect(browse_, nullptr, TRUE);
            } else {
                const auto value = absolute(text(path_));
                const bool recovery = exists(value + L".work");
                caption(primary_, strings_.get(recovery ? Text::resume : Text::start));
                if (recovery)
                    set_note(Text::recovery);
            }
        } else if (LOWORD(wp) == kLanguage && HIWORD(wp) == CBN_SELCHANGE)
            change_language();
        else if (HIWORD(wp) == BN_CLICKED)
            command(LOWORD(wp));
        return 0;
    case WM_NOTIFY: {
        const auto* notice = reinterpret_cast<const NMHDR*>(lp);
        if (notice->code == NM_CLICK || notice->code == NM_RETURN) {
            if (notice->hwndFrom == github_)
                open_path(kGithubUrl, Text::open_link_error);
            else if (notice->hwndFrom == coffee_ && step_ == 3 &&
                     snapshot_.verdict == Verdict::kComplete)
                open_path(kCoffeeUrl, Text::open_link_error);
        }
        break;
    }
    case WM_DROPFILES: {
        auto drop = reinterpret_cast<HDROP>(wp);
        if (step_ == 0 && DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0) == 1) {
            auto n = DragQueryFileW(drop, 0, nullptr, 0);
            std::wstring path(n + 1, L'\0');
            DragQueryFileW(drop, 0, path.data(), n + 1);
            path.resize(n);
            select_source(path);
        }
        DragFinish(drop);
        return 0;
    }
    case WM_DRAWITEM:
        if (reinterpret_cast<const DRAWITEMSTRUCT*>(lp)->CtlType == ODT_BUTTON) {
            draw_button(*reinterpret_cast<DRAWITEMSTRUCT*>(lp));
            return TRUE;
        }
        break;
    case WM_SETCURSOR:
        if (step_ == 0 && reinterpret_cast<HWND>(wp) == browse_ && LOWORD(lp) == HTCLIENT) {
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        const HWND child = reinterpret_cast<HWND>(lp);
        const bool value = std::find(std::begin(stat_values_), std::end(stat_values_), child) !=
                           std::end(stat_values_);
        const bool metric = value || std::find(std::begin(stat_labels_), std::end(stat_labels_),
                                               child) != std::end(stat_labels_);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, high_contrast_               ? GetSysColor(COLOR_WINDOWTEXT)
                         : child == heading_ || value ? kInk
                                                      : kMuted);
        if (metric && !high_contrast_) {
            SetDCBrushColor(dc, kMetricFill);
            return reinterpret_cast<LRESULT>(GetStockObject(DC_BRUSH));
        }
        return reinterpret_cast<LRESULT>(white_);
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        paint();
        return 0;
    case WM_TIMER:
        if (running_) {
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now() - started_)
                            .count();
            std::wostringstream out;
            out << strings_.get(Text::elapsed) << L"   " << secs / 3600 << L":" << std::setw(2)
                << std::setfill(L'0') << secs / 60 % 60 << L":" << std::setw(2) << secs % 60;
            caption(elapsed_, out.str());
        }
        return 0;
    case kWorkerChanged:
        updated();
        return 0;
    case WM_KEYDOWN:
        if (wp == VK_RETURN) {
            command(kPrimary);
            return 0;
        }
        break;
    case WM_CLOSE:
        if (running_) {
            if (!closing_ && MessageBoxW(window_, strings_.get(Text::confirm_close).c_str(),
                                         strings_.get(Text::app).c_str(),
                                         MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION) == IDYES) {
                closing_ = true;
                stopping_ = true;
                host_.stop();
                caption(primary_, strings_.get(Text::stopping));
                EnableWindow(primary_, FALSE);
                EnableWindow(close_, FALSE);
            }
        } else
            DestroyWindow(window_);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window_, m, wp, lp);
}
} // namespace ost2pst::gui

#include "wizard.h"

#include <algorithm>
#include <commctrl.h>
#include <cwctype>
#include <filesystem>
#include <iomanip>
#include <shellapi.h>
#include <shobjidl.h>
#include <sstream>
#include <vector>
#include <windowsx.h>

namespace ost2pst::gui {
namespace {
constexpr COLORREF kBackground = RGB(244, 246, 249), kInk = RGB(28, 36, 50),
                   kMuted = RGB(96, 108, 127), kAccent = RGB(40, 91, 215);
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
    if (bytes >= 1024 * 1024 * 1024)
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
    for (auto font : {body_font_, title_font_, small_font_, value_font_})
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
    for (auto* pair : {&body_font_, &title_font_, &small_font_, &value_font_})
        if (*pair) {
            DeleteObject(*pair);
            *pair = nullptr;
        }
    auto make = [&](int size, int weight) {
        return CreateFontW(-MulDiv(size, static_cast<int>(dpi_), 72), 0, 0, 0, weight, FALSE, FALSE,
                           FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    };
    body_font_ = make(11, FW_NORMAL);
    title_font_ = make(23, FW_SEMIBOLD);
    small_font_ = make(10, FW_NORMAL);
    value_font_ = make(20, FW_SEMIBOLD);
    for (HWND child = GetWindow(window_, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT))
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(body_font_), FALSE);
    if (heading_)
        SendMessageW(heading_, WM_SETFONT, reinterpret_cast<WPARAM>(title_font_), FALSE);
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
    label_ = control(L"STATIC", L"", SS_LEFT);
    path_ = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, kPath, WS_EX_CLIENTEDGE);
    SendMessageW(path_, EM_SETLIMITTEXT, 32760, 0);
    browse_ = control(L"BUTTON", strings_.get(Text::browse), WS_TABSTOP | BS_PUSHBUTTON, kBrowse);
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
    back_ = control(L"BUTTON", strings_.get(Text::back), WS_TABSTOP | BS_PUSHBUTTON, kBack);
    primary_ = control(L"BUTTON", L"", WS_TABSTOP | BS_OWNERDRAW, kPrimary);
    close_ = control(L"BUTTON", strings_.get(Text::close), WS_TABSTOP | BS_PUSHBUTTON, kClose);
    details_ =
        control(L"BUTTON", strings_.get(Text::details), WS_TABSTOP | BS_PUSHBUTTON, kDetails);
    report_ = control(L"BUTTON", strings_.get(Text::report), WS_TABSTOP | BS_PUSHBUTTON, kReport);
    folder_ = control(L"BUTTON", strings_.get(Text::folder), WS_TABSTOP | BS_PUSHBUTTON, kFolder);
    resume_ = control(L"BUTTON", strings_.get(Text::resume), WS_TABSTOP | BS_PUSHBUTTON, kResume);
    language_label_ = control(L"STATIC", strings_.get(Text::language), SS_RIGHT);
    language_ = control(L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, kLanguage);
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
    place(language_label_, width - 358, 29, 140, 24);
    place(language_, width - 208, 22, 176, 300);
    const bool compact = height < 560;
    const int top = compact ? 96 : 124;
    const auto y = [&](int offset) { return top + (compact ? MulDiv(offset, 78, 100) : offset); };
    place(heading_, left, y(27), content, 48);
    place(label_, left, y(step_ == 1 ? 130 : 100), content, 24);
    const int browse_width = 160;
    place(path_, left, y(step_ == 1 ? 164 : 134), content - browse_width - 12, 40);
    place(browse_, right - browse_width, y(step_ == 1 ? 164 : 134), browse_width, 40);
    place(location_, left, y(compact ? 91 : 84), content, 24);
    place(note_, left, y(step_ == 1 ? 226 : 196), content, 76);
    if (step_ == 3)
        place(note_, left, y(241), content, compact ? 56 : 72);
    place(phase_, left, y(97), content, 28);
    place(progress_, left, y(141), content, 8);
    place(processed_, left, y(166), content, 24);
    place(elapsed_, left, y(308), content, 26);
    for (int i = 0; i < 3; ++i) {
        int col = content / 3;
        place(stat_labels_[i], left + i * col, y(step_ == 3 ? 145 : 229), col - 16, 24);
        place(stat_values_[i], left + i * col, y(step_ == 3 ? 177 : 261), col - 16, 36);
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
    caption(language_label_, strings_.get(Text::language));
    for (const auto& pair : {std::pair{browse_, Text::browse},
                             {back_, Text::back},
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
        caption(location_, source_);
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
    EnableWindow(primary_, !stopping_);
    EnableWindow(close_, !closing_);
    if (step_ == 2)
        caption(heading_, strings_.get(Text::conversion_title));
    render_state();
    layout();
    if (focus)
        SetFocus(step_ < 2 ? path_ : primary_);
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
void Wizard::open_path(const std::wstring& path) {
    if (reinterpret_cast<INT_PTR>(
            ShellExecuteW(window_, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL)) <= 32)
        MessageBoxW(window_, strings_.get(Text::open_error).c_str(),
                    strings_.get(Text::app).c_str(), MB_OK | MB_ICONERROR);
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
    const bool disabled = (item.itemState & ODS_DISABLED) != 0;
    COLORREF fill = high_contrast_ ? GetSysColor(disabled ? COLOR_BTNFACE : COLOR_HIGHLIGHT)
                    : disabled     ? RGB(180, 192, 217)
                    : (item.itemState & ODS_SELECTED) ? RGB(25, 65, 170)
                                                      : kAccent;
    auto brush = CreateSolidBrush(fill);
    auto pen = CreatePen(PS_SOLID, 1, fill);
    auto ob = SelectObject(item.hDC, brush), op = SelectObject(item.hDC, pen);
    RoundRect(item.hDC, item.rcItem.left, item.rcItem.top, item.rcItem.right, item.rcItem.bottom,
              px(8), px(8));
    SelectObject(item.hDC, ob);
    SelectObject(item.hDC, op);
    DeleteObject(brush);
    DeleteObject(pen);
    SetBkMode(item.hDC, TRANSPARENT);
    SetTextColor(item.hDC, high_contrast_ ? GetSysColor(COLOR_HIGHLIGHTTEXT) : RGB(255, 255, 255));
    SelectObject(item.hDC, body_font_);
    auto t = text(item.hwndItem);
    RECT r = item.rcItem;
    DrawTextW(item.hDC, t.c_str(), -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) {
        InflateRect(&r, -px(4), -px(4));
        DrawFocusRect(item.hDC, &r);
    }
}
void Wizard::paint() {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(window_, &ps);
    RECT r;
    GetClientRect(window_, &r);
    FillRect(dc, &r, background_);
    const bool compact = MulDiv(r.bottom, 96, static_cast<int>(dpi_)) < 560;
    RECT card{px(32), px(compact ? 96 : 124), r.right - px(32), r.bottom - px(88)};
    FillRect(dc, &card, white_);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, high_contrast_ ? GetSysColor(COLOR_WINDOWTEXT) : kInk);
    SelectObject(dc, body_font_);
    RECT brand{px(32), px(24), r.right - px(390), px(52)};
    DrawTextW(dc, L"OST2PST", -1, &brand, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, small_font_);
    const Text labels[] = {Text::source, Text::destination, Text::conversion, Text::result};
    const int col = (r.right - px(64)) / 4;
    for (int i = 0; i < 4; ++i) {
        const int left = px(32) + col * i;
        const COLORREF color = high_contrast_ ? GetSysColor(COLOR_WINDOWTEXT)
                               : i == step_   ? kAccent
                                              : kMuted;
        SetTextColor(dc, color);
        auto s = std::to_wstring(i + 1) + L"  " + strings_.get(labels[i]);
        RECT label{left, px(compact ? 60 : 74), left + col - px(8), px(compact ? 85 : 99)};
        DrawTextW(dc, s.c_str(), -1, &label, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        RECT line{left, px(compact ? 88 : 108), left + col - px(10), px(compact ? 91 : 111)};
        auto brush = CreateSolidBrush(i <= step_       ? color
                                      : high_contrast_ ? GetSysColor(COLOR_GRAYTEXT)
                                                       : RGB(220, 226, 235));
        FillRect(dc, &line, brush);
        DeleteObject(brush);
    }
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
        return MAKELONG(kPrimary, DC_HASDEFID);
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
            if (step_ == 1) {
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
    case WM_DROPFILES: {
        auto drop = reinterpret_cast<HDROP>(wp);
        if (step_ == 0 && DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0) == 1) {
            auto n = DragQueryFileW(drop, 0, nullptr, 0);
            std::wstring path(n + 1, L'\0');
            DragQueryFileW(drop, 0, path.data(), n + 1);
            path.resize(n);
            caption(path_, path);
        }
        DragFinish(drop);
        return 0;
    }
    case WM_DRAWITEM:
        if (wp == kPrimary) {
            draw_button(*reinterpret_cast<DRAWITEMSTRUCT*>(lp));
            return TRUE;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, high_contrast_ ? GetSysColor(COLOR_WINDOWTEXT)
                         : reinterpret_cast<HWND>(lp) == heading_ ||
                                 std::find(std::begin(stat_values_), std::end(stat_values_),
                                           reinterpret_cast<HWND>(lp)) != std::end(stat_values_)
                             ? kInk
                             : kMuted);
        return reinterpret_cast<LRESULT>(reinterpret_cast<HWND>(lp) == language_label_ ? background_
                                                                                       : white_);
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

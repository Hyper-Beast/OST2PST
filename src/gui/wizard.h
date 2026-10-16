#pragma once
#include <chrono>

#include "localization.h"
#include "process_host.h"

namespace ost2pst::gui {
// Stable control IDs also allow native interaction tests without production command-line hooks.
enum ControlId {
    kPath = 101,
    kBrowse,
    kBack,
    kPrimary,
    kClose,
    kDetails,
    kReport,
    kFolder,
    kResume,
    kLanguage
};
class Wizard {
  public:
    explicit Wizard(Strings strings = Strings(), UINT test_dpi = 0,
                    bool test_high_contrast = false);
    ~Wizard();
    bool create(HINSTANCE instance, int show);
    HWND window() const { return window_; }
    bool layout_valid() const;

  private:
    Strings strings_;
    ProcessHost host_;
    HWND window_ = nullptr, path_ = nullptr, browse_ = nullptr, back_ = nullptr, primary_ = nullptr,
         close_ = nullptr, details_ = nullptr, report_ = nullptr, folder_ = nullptr,
         resume_ = nullptr, heading_ = nullptr, label_ = nullptr, note_ = nullptr, phase_ = nullptr,
         progress_ = nullptr, processed_ = nullptr, elapsed_ = nullptr, location_ = nullptr,
         language_ = nullptr, language_label_ = nullptr;
    HWND stat_labels_[3]{}, stat_values_[3]{};
    HFONT body_font_ = nullptr, title_font_ = nullptr, small_font_ = nullptr, value_font_ = nullptr;
    HBRUSH white_ = nullptr, background_ = nullptr;
    UINT dpi_ = 96, test_dpi_ = 0;
    bool test_high_contrast_ = false;
    int step_ = 0;
    uint64_t run_id_ = 0;
    bool running_ = false, stopping_ = false, closing_ = false, recovery_ = false,
         high_contrast_ = false;
    bool progress_marquee_ = false;
    int progress_position_ = -1;
    std::wstring source_, output_;
    Snapshot snapshot_;
    Text note_key_ = Text::kSize;
    std::chrono::steady_clock::time_point started_;
    static LRESULT CALLBACK procedure(HWND, UINT, WPARAM, LPARAM);
    LRESULT message(UINT, WPARAM, LPARAM);
    int px(int value) const;
    void build_controls();
    void fonts();
    void layout();
    void page(bool focus = true);
    void render_state();
    void render_progress(bool items, int position = 0);
    void change_language();
    void paint();
    void draw_button(const DRAWITEMSTRUCT& item);
    void command(int id);
    void browse();
    void start(bool resume);
    void updated();
    void show_details();
    bool validate_source();
    bool validate_destination(bool& resume);
    void set_note(Text text);
    void open_path(const std::wstring& path);
};
} // namespace ost2pst::gui

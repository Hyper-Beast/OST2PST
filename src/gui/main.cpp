#define NOMINMAX
// Windows extension headers require the base Windows types before include sorting.
// clang-format off
#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
// clang-format on

#include "wizard.h"

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(com))
        return 1;
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&controls);
    int code = 1;
    {
        ost2pst::gui::Wizard wizard;
        if (wizard.create(instance, show)) {
            MSG message{};
            int result;
            while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0) {
                if (message.message == WM_KEYDOWN && message.wParam == VK_RETURN &&
                    (message.hwnd == GetDlgItem(wizard.window(), ost2pst::gui::kPath) ||
                     message.hwnd == wizard.window())) {
                    SendMessageW(wizard.window(), WM_COMMAND, ost2pst::gui::kPrimary, 0);
                    continue;
                }
                if (!IsDialogMessageW(wizard.window(), &message)) {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
            code = result == -1 ? 1 : static_cast<int>(message.wParam);
        }
    }
    CoUninitialize();
    return code;
}

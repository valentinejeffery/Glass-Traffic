use eframe::egui;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared signals between the native system tray thread and the egui UI thread.
pub struct TrayHandle {
    pub show_requested: Arc<AtomicBool>,
    pub toggle_pause_requested: Arc<AtomicBool>,
    pub quit_requested: Arc<AtomicBool>,
    pub supported: bool,
}

impl TrayHandle {
    pub fn start(ctx: egui::Context) -> Self {
        let show_requested = Arc::new(AtomicBool::new(false));
        let toggle_pause_requested = Arc::new(AtomicBool::new(false));
        let quit_requested = Arc::new(AtomicBool::new(false));

        #[cfg(windows)]
        let supported = {
            windows_tray::spawn_tray_thread(
                ctx,
                Arc::clone(&show_requested),
                Arc::clone(&toggle_pause_requested),
                Arc::clone(&quit_requested),
            );
            true
        };

        #[cfg(not(windows))]
        let supported = {
            let _ = ctx;
            false
        };

        Self {
            show_requested,
            toggle_pause_requested,
            quit_requested,
            supported,
        }
    }

    pub fn take_show(&self) -> bool {
        self.show_requested.swap(false, Ordering::SeqCst)
    }

    pub fn take_toggle_pause(&self) -> bool {
        self.toggle_pause_requested.swap(false, Ordering::SeqCst)
    }

    pub fn take_quit(&self) -> bool {
        self.quit_requested.swap(false, Ordering::SeqCst)
    }
}

#[cfg(windows)]
mod windows_tray {
    use eframe::egui;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::thread;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DispatchMessageW,
        GetCursorPos, GetMessageW, LoadIconW, LoadImageW, PostQuitMessage, RegisterClassW,
        SetForegroundWindow, TrackPopupMenu, TranslateMessage, CW_USEDEFAULT, IDI_APPLICATION,
        IMAGE_ICON, LR_DEFAULTCOLOR, MF_SEPARATOR, MF_STRING, MSG, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
        TPM_RETURNCMD, WM_APP, WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_RBUTTONUP,
        WNDCLASSW, WS_OVERLAPPEDWINDOW,
    };

    const WM_TRAYICON: u32 = WM_APP + 1;
    const CMD_SHOW: u32 = 1001;
    const CMD_PAUSE: u32 = 1002;
    const CMD_QUIT: u32 = 1003;

    struct TrayState {
        ctx: egui::Context,
        show: Arc<AtomicBool>,
        pause: Arc<AtomicBool>,
        quit: Arc<AtomicBool>,
    }

    static TRAY_STATE: OnceLock<TrayState> = OnceLock::new();

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn spawn_tray_thread(
        ctx: egui::Context,
        show: Arc<AtomicBool>,
        pause: Arc<AtomicBool>,
        quit: Arc<AtomicBool>,
    ) {
        let _ = TRAY_STATE.set(TrayState {
            ctx,
            show,
            pause,
            quit,
        });

        let _ = thread::Builder::new()
            .name("glasstrace-tray".into())
            .spawn(move || unsafe {
                let hinstance = GetModuleHandleW(null());
                let class_name = to_wide("GlassTraceTrayHiddenWindow");

                let wc = WNDCLASSW {
                    style: 0,
                    lpfnWndProc: Some(tray_wnd_proc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinstance,
                    hIcon: null_mut(),
                    hCursor: null_mut(),
                    hbrBackground: null_mut(),
                    lpszMenuName: null(),
                    lpszClassName: class_name.as_ptr(),
                };
                RegisterClassW(&wc);

                let hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    class_name.as_ptr(),
                    WS_OVERLAPPEDWINDOW,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    null_mut(),
                    null_mut(),
                    hinstance,
                    null(),
                );
                if hwnd.is_null() {
                    return;
                }

                // Load embedded exe icon (resource ID 1 set by winresource), fallback to default app icon
                let mut hicon = LoadImageW(
                    hinstance,
                    1usize as *const u16,
                    IMAGE_ICON,
                    16,
                    16,
                    LR_DEFAULTCOLOR,
                );
                if hicon.is_null() {
                    hicon = LoadIconW(null_mut(), IDI_APPLICATION);
                }

                let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
                nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                nid.hWnd = hwnd;
                nid.uID = 1;
                nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
                nid.uCallbackMessage = WM_TRAYICON;
                nid.hIcon = hicon;

                let tip = to_wide("GlassTrace Desktop — Recording Traffic");
                let copy_len = tip.len().min(nid.szTip.len());
                nid.szTip[..copy_len].copy_from_slice(&tip[..copy_len]);

                Shell_NotifyIconW(NIM_ADD, &nid);

                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }

                Shell_NotifyIconW(NIM_DELETE, &nid);
            });
    }

    unsafe extern "system" fn tray_wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_TRAYICON {
            let event = (lparam & 0xFFFF) as u32;
            if event == WM_LBUTTONUP || event == WM_LBUTTONDBLCLK {
                if let Some(st) = TRAY_STATE.get() {
                    st.show.store(true, Ordering::SeqCst);
                    st.ctx.request_repaint();
                }
                return 0;
            } else if event == WM_RBUTTONUP {
                let menu = CreatePopupMenu();
                if !menu.is_null() {
                    let s_show = to_wide("Show GlassTrace Desktop");
                    let s_pause = to_wide("Pause / Resume Recording");
                    let s_quit = to_wide("Quit GlassTrace");

                    AppendMenuW(menu, MF_STRING, CMD_SHOW as usize, s_show.as_ptr());
                    AppendMenuW(menu, MF_STRING, CMD_PAUSE as usize, s_pause.as_ptr());
                    AppendMenuW(menu, MF_SEPARATOR, 0, null());
                    AppendMenuW(menu, MF_STRING, CMD_QUIT as usize, s_quit.as_ptr());

                    let mut pt: POINT = std::mem::zeroed();
                    GetCursorPos(&mut pt);
                    SetForegroundWindow(hwnd);
                    let cmd = TrackPopupMenu(
                        menu,
                        TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                        pt.x,
                        pt.y,
                        0,
                        hwnd,
                        null(),
                    ) as u32;
                    DestroyMenu(menu);

                    if let Some(st) = TRAY_STATE.get() {
                        match cmd {
                            CMD_SHOW => {
                                st.show.store(true, Ordering::SeqCst);
                                st.ctx.request_repaint();
                            }
                            CMD_PAUSE => {
                                st.pause.store(true, Ordering::SeqCst);
                                st.ctx.request_repaint();
                            }
                            CMD_QUIT => {
                                st.quit.store(true, Ordering::SeqCst);
                                st.ctx.request_repaint();
                                PostQuitMessage(0);
                            }
                            _ => {}
                        }
                    }
                }
                return 0;
            }
        } else if msg == WM_DESTROY {
            PostQuitMessage(0);
            return 0;
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

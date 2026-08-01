use crate::{BootstrapInput, LauncherError};
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
mod imp {
    use super::{BootstrapInput, LauncherError, Path, PathBuf};
    use crate::signer_identity_allowed;
    use sha2::{Digest, Sha256};
    use std::ffi::{OsStr, c_void};
    use std::fs;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::{Component, Prefix};
    use std::ptr::{null, null_mut};
    use std::slice;
    use zeroize::{Zeroize, Zeroizing};

    const CERT_FIND_SUBJECT_CERT: u32 = 0x000b_0000;
    const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
    const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: u32 = 0x0000_0400;
    const CERT_QUERY_FORMAT_FLAG_BINARY: u32 = 0x0000_0002;
    const COLOR_BTNFACE: usize = 15;
    const CMSG_SIGNER_COUNT_PARAM: u32 = 5;
    const CMSG_SIGNER_CERT_INFO_PARAM: u32 = 7;
    const EM_SETLIMITTEXT: u32 = 0x00c5;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;
    const FILE_ADD_FILE: u32 = 0x0000_0002;
    const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const MB_ICONERROR: u32 = 0x0000_0010;
    const MB_ICONINFORMATION: u32 = 0x0000_0040;
    const MB_ICONWARNING: u32 = 0x0000_0030;
    const MB_DEFBUTTON2: u32 = 0x0000_0100;
    const MB_OK: u32 = 0x0000_0000;
    const MB_YESNO: u32 = 0x0000_0004;
    const IDYES: i32 = 6;
    const IDOK: usize = 1;
    const IDCANCEL: usize = 2;
    const OPEN_EXISTING: u32 = 3;
    const PF_SECOND_LEVEL_ADDRESS_TRANSLATION: u32 = 20;
    const PF_VIRT_FIRMWARE_ENABLED: u32 = 21;
    const SW_SHOWNORMAL: i32 = 1;
    const SW_SHOW: i32 = 5;
    const SM_CXSCREEN: i32 = 0;
    const SM_CYSCREEN: i32 = 1;
    const WM_CLOSE: u32 = 0x0010;
    const WM_COMMAND: u32 = 0x0111;
    const WM_DESTROY: u32 = 0x0002;
    const WM_NCCREATE: u32 = 0x0081;
    const WM_NCDESTROY: u32 = 0x0082;
    const WM_SETFONT: u32 = 0x0030;
    const GWLP_USERDATA: i32 = -21;
    const WS_BORDER: u32 = 0x0080_0000;
    const WS_CAPTION: u32 = 0x00c0_0000;
    const WS_CHILD: u32 = 0x4000_0000;
    const WS_SYSMENU: u32 = 0x0008_0000;
    const WS_TABSTOP: u32 = 0x0001_0000;
    const WS_VISIBLE: u32 = 0x1000_0000;
    const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
    const ES_AUTOHSCROLL: u32 = 0x0080;
    const ES_PASSWORD: u32 = 0x0020;
    const BS_DEFPUSHBUTTON: u32 = 0x0001;
    const DEFAULT_GUI_FONT: i32 = 17;
    const IDC_ARROW: usize = 32_512;
    const VER_NT_WORKSTATION: u8 = 1;
    const WINDOWS_11_MIN_BUILD: u32 = 22_000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_REVOKE_WHOLECHAIN: u32 = 1;
    const WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT: u32 = 0x0000_0080;
    const WTD_STATEACTION_CLOSE: u32 = 2;
    const WTD_STATEACTION_VERIFY: u32 = 1;
    const WTD_UI_NONE: u32 = 2;
    const X509_ASN_ENCODING: u32 = 0x0000_0001;
    const PKCS_7_ASN_ENCODING: u32 = 0x0001_0000;
    const MIN_TOTAL_MEMORY_BYTES: u64 = 16 * 1024 * 1024 * 1024;
    const MIN_AVAILABLE_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    const MIN_FREE_DISK_BYTES: u64 = 40 * 1024 * 1024 * 1024;

    type Handle = *mut c_void;

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const FOLDER_ID_PROGRAM_FILES: Guid = Guid {
        data1: 0x905e63b6,
        data2: 0xc1bf,
        data3: 0x494e,
        data4: [0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a],
    };

    const FOLDER_ID_LOCAL_APP_DATA: Guid = Guid {
        data1: 0xf1b32785,
        data2: 0x6fba,
        data3: 0x4fcf,
        data4: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
    };

    const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };

    #[repr(C)]
    struct RtlOsVersionInfoExW {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform_id: u32,
        service_pack: [u16; 128],
        service_pack_major: u16,
        service_pack_minor: u16,
        suite_mask: u16,
        product_type: u8,
        reserved: u8,
    }

    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_physical: u64,
        available_physical: u64,
        total_page_file: u64,
        available_page_file: u64,
        total_virtual: u64,
        available_virtual: u64,
        available_extended_virtual: u64,
    }

    #[repr(C)]
    struct WinTrustFileInfo {
        size: u32,
        file_path: *const u16,
        file: Handle,
        known_subject: *const Guid,
    }

    #[repr(C)]
    struct WinTrustData {
        size: u32,
        policy_callback_data: *mut c_void,
        sip_client_data: *mut c_void,
        ui_choice: u32,
        revocation_checks: u32,
        union_choice: u32,
        file_info: *mut WinTrustFileInfo,
        state_action: u32,
        state_data: Handle,
        url_reference: *mut u16,
        provider_flags: u32,
        ui_context: u32,
        signature_settings: *mut c_void,
    }

    #[repr(C)]
    struct CertContext {
        encoding_type: u32,
        encoded_cert: *const u8,
        encoded_cert_size: u32,
        cert_info: *const c_void,
        cert_store: Handle,
    }

    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct Message {
        window: Handle,
        message: u32,
        w_param: usize,
        l_param: isize,
        time: u32,
        point: Point,
        private: u32,
    }

    #[repr(C)]
    struct CreateStructW {
        create_parameters: *mut c_void,
        instance: Handle,
        menu: Handle,
        parent: Handle,
        height: i32,
        width: i32,
        y: i32,
        x: i32,
        style: i32,
        name: *const u16,
        class: *const u16,
        extended_style: u32,
    }

    type WindowProcedure = unsafe extern "system" fn(Handle, u32, usize, isize) -> isize;

    #[repr(C)]
    struct WindowClassExW {
        size: u32,
        style: u32,
        window_procedure: Option<WindowProcedure>,
        class_extra: i32,
        window_extra: i32,
        instance: Handle,
        icon: Handle,
        cursor: Handle,
        background: Handle,
        menu_name: *const u16,
        class_name: *const u16,
        small_icon: Handle,
    }

    struct BootstrapDialogState {
        email: Handle,
        display_name: Handle,
        password: Handle,
        confirm_password: Handle,
        result: Option<BootstrapInput>,
    }

    impl BootstrapDialogState {
        fn new() -> Self {
            Self {
                email: null_mut(),
                display_name: null_mut(),
                password: null_mut(),
                confirm_password: null_mut(),
                result: None,
            }
        }
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CloseHandle(handle: Handle) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn CreateMutexW(attributes: *const c_void, initial_owner: i32, name: *const u16) -> Handle;
        fn GetCurrentProcess() -> Handle;
        fn GetDiskFreeSpaceExW(
            directory_name: *const u16,
            free_bytes_available: *mut u64,
            total_bytes: *mut u64,
            total_free_bytes: *mut u64,
        ) -> i32;
        fn GetLastError() -> u32;
        fn GetModuleHandleW(module_name: *const u16) -> Handle;
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
        fn IsProcessorFeaturePresent(feature: u32) -> i32;
        fn IsWow64Process2(
            process: Handle,
            process_machine: *mut u16,
            native_machine: *mut u16,
        ) -> i32;
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(version: *mut RtlOsVersionInfoExW) -> i32;
    }

    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoTaskMemFree(memory: *mut c_void);
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHGetKnownFolderPath(
            folder_id: *const Guid,
            flags: u32,
            token: Handle,
            path: *mut *mut u16,
        ) -> i32;
        fn ShellExecuteW(
            window: Handle,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_command: i32,
        ) -> isize;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn CreateWindowExW(
            extended_style: u32,
            class_name: *const u16,
            window_name: *const u16,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: Handle,
            menu: Handle,
            instance: Handle,
            parameter: *mut c_void,
        ) -> Handle;
        fn DefWindowProcW(window: Handle, message: u32, w_param: usize, l_param: isize) -> isize;
        fn DestroyWindow(window: Handle) -> i32;
        fn DispatchMessageW(message: *const Message) -> isize;
        fn GetMessageW(message: *mut Message, window: Handle, minimum: u32, maximum: u32) -> i32;
        fn GetSystemMetrics(index: i32) -> i32;
        fn GetWindowLongPtrW(window: Handle, index: i32) -> isize;
        fn GetWindowTextLengthW(window: Handle) -> i32;
        fn GetWindowTextW(window: Handle, text: *mut u16, maximum: i32) -> i32;
        fn IsDialogMessageW(window: Handle, message: *mut Message) -> i32;
        fn LoadCursorW(instance: Handle, cursor_name: *const u16) -> Handle;
        fn MessageBoxW(window: Handle, text: *const u16, caption: *const u16, kind: u32) -> i32;
        fn PostQuitMessage(exit_code: i32);
        fn RegisterClassExW(window_class: *const WindowClassExW) -> u16;
        fn SendMessageW(window: Handle, message: u32, w_param: usize, l_param: isize) -> isize;
        fn SetFocus(window: Handle) -> Handle;
        fn SetForegroundWindow(window: Handle) -> i32;
        fn SetWindowLongPtrW(window: Handle, index: i32, value: isize) -> isize;
        fn SetWindowTextW(window: Handle, text: *const u16) -> i32;
        fn ShowWindow(window: Handle, command: i32) -> i32;
        fn TranslateMessage(message: *const Message) -> i32;
        fn UpdateWindow(window: Handle) -> i32;
    }

    #[link(name = "gdi32")]
    unsafe extern "system" {
        fn GetStockObject(object: i32) -> Handle;
    }

    #[link(name = "wintrust")]
    unsafe extern "system" {
        fn WinVerifyTrust(window: Handle, action: *const Guid, trust_data: *mut c_void) -> i32;
    }

    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CertCloseStore(store: Handle, flags: u32) -> i32;
        fn CertFindCertificateInStore(
            store: Handle,
            encoding_type: u32,
            find_flags: u32,
            find_type: u32,
            find_parameter: *const c_void,
            previous_context: *const CertContext,
        ) -> *const CertContext;
        fn CertFreeCertificateContext(context: *const CertContext) -> i32;
        fn CertGetNameStringW(
            context: *const CertContext,
            name_type: u32,
            flags: u32,
            type_parameter: *const c_void,
            name: *mut u16,
            name_length: u32,
        ) -> u32;
        fn CryptMsgClose(message: Handle) -> i32;
        fn CryptMsgGetParam(
            message: Handle,
            parameter_type: u32,
            index: u32,
            data: *mut c_void,
            data_size: *mut u32,
        ) -> i32;
        fn CryptQueryObject(
            object_type: u32,
            object: *const c_void,
            expected_content_flags: u32,
            expected_format_flags: u32,
            flags: u32,
            encoding_type: *mut u32,
            content_type: *mut u32,
            format_type: *mut u32,
            cert_store: *mut Handle,
            message: *mut Handle,
            context: *mut *const c_void,
        ) -> i32;
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn wide_text(value: &str) -> Vec<u16> {
        wide(OsStr::new(value))
    }

    fn is_invalid_handle(handle: Handle) -> bool {
        handle as isize == -1
    }

    pub struct InstanceGuard {
        handle: Handle,
    }

    impl Drop for InstanceGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                // SAFETY: handle was returned by CreateMutexW and is owned by this guard.
                unsafe {
                    CloseHandle(self.handle);
                }
            }
        }
    }

    pub fn acquire_single_instance() -> Result<InstanceGuard, LauncherError> {
        let name = wide_text(r"Local\DataXEnterpriseStudio.Launcher.v1");
        // SAFETY: name is NUL terminated and remains alive for the duration of the call.
        let handle = unsafe { CreateMutexW(null(), 1, name.as_ptr()) };
        if handle.is_null() {
            return Err(LauncherError::new(
                "LAUNCHER_MUTEX_FAILED",
                "无法创建本机单实例锁。",
            ));
        }
        // SAFETY: GetLastError has no preconditions and is called immediately after CreateMutexW.
        let last_error = unsafe { GetLastError() };
        if last_error == ERROR_ALREADY_EXISTS {
            // SAFETY: this process owns the returned handle and will not use it again.
            unsafe {
                CloseHandle(handle);
            }
            return Err(LauncherError::new(
                "LAUNCHER_ALREADY_RUNNING",
                "另一个 Launcher 实例正在执行，请等待其完成后重试。",
            ));
        }
        Ok(InstanceGuard { handle })
    }

    pub fn ensure_supported_host() -> Result<(), LauncherError> {
        let mut version = RtlOsVersionInfoExW {
            size: size_of::<RtlOsVersionInfoExW>() as u32,
            major: 0,
            minor: 0,
            build: 0,
            platform_id: 0,
            service_pack: [0; 128],
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 0,
            reserved: 0,
        };
        // SAFETY: version points to a correctly sized writable RTL_OSVERSIONINFOEXW value.
        let status = unsafe { RtlGetVersion(&mut version) };
        if status < 0 || version.major != 10 || version.build < WINDOWS_11_MIN_BUILD {
            return Err(LauncherError::new(
                "WINDOWS_11_REQUIRED",
                "需要 Windows 11（build 22000 或更高版本）。",
            ));
        }
        if version.product_type != VER_NT_WORKSTATION {
            return Err(LauncherError::new(
                "WINDOWS_WORKSTATION_REQUIRED",
                "Windows Server SKU 不属于 V1 支持范围；仅支持 Windows 11 客户端。",
            ));
        }

        let mut process_machine = 0_u16;
        let mut native_machine = 0_u16;
        // SAFETY: output pointers are valid and GetCurrentProcess returns a pseudo-handle.
        let architecture_ok = unsafe {
            IsWow64Process2(
                GetCurrentProcess(),
                &mut process_machine,
                &mut native_machine,
            )
        };
        if architecture_ok == 0 || native_machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(LauncherError::new(
                "NATIVE_AMD64_REQUIRED",
                "仅支持原生 AMD64 Windows；Windows on Arm 仿真不属于 V1 支持范围。",
            ));
        }
        if !crate::is_supported_host_signature(
            version.major,
            version.build,
            version.product_type,
            native_machine,
        ) {
            return Err(LauncherError::new(
                "WINDOWS_HOST_UNSUPPORTED",
                "当前 Windows 宿主不属于 V1 支持范围。",
            ));
        }
        Ok(())
    }

    pub fn ensure_hardware_prerequisites(data_path: &Path) -> Result<(), LauncherError> {
        // SAFETY: IsProcessorFeaturePresent has no pointer preconditions.
        let virtualization = unsafe {
            IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) != 0
                && IsProcessorFeaturePresent(PF_SECOND_LEVEL_ADDRESS_TRANSLATION) != 0
        };
        if !virtualization {
            return Err(LauncherError::new(
                "HARDWARE_VIRTUALIZATION_REQUIRED",
                "硬件虚拟化或二级地址转换不可用。Launcher 不会修改固件或 Windows 功能。",
            ));
        }

        let mut memory = MemoryStatusEx {
            length: size_of::<MemoryStatusEx>() as u32,
            memory_load: 0,
            total_physical: 0,
            available_physical: 0,
            total_page_file: 0,
            available_page_file: 0,
            total_virtual: 0,
            available_virtual: 0,
            available_extended_virtual: 0,
        };
        // SAFETY: memory points to a correctly sized writable MEMORYSTATUSEX value.
        if unsafe { GlobalMemoryStatusEx(&mut memory) } == 0
            || memory.total_physical < MIN_TOTAL_MEMORY_BYTES
            || memory.available_physical < MIN_AVAILABLE_MEMORY_BYTES
        {
            return Err(LauncherError::new(
                "HOST_MEMORY_INSUFFICIENT",
                "需要至少 16 GiB 物理内存且当前至少 4 GiB 可用。",
            ));
        }

        ensure_local_disk_path(data_path)?;
        let path = wide(data_path.as_os_str());
        let mut available = 0_u64;
        let mut total = 0_u64;
        let mut free = 0_u64;
        // SAFETY: path is NUL terminated and output pointers are valid.
        if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut available, &mut total, &mut free) } == 0
            || available < MIN_FREE_DISK_BYTES
        {
            return Err(LauncherError::new(
                "HOST_DISK_INSUFFICIENT",
                "产品数据所在本地卷需要至少 40 GiB 当前可用空间。",
            ));
        }
        Ok(())
    }

    pub fn system32_executable(name: &str) -> Result<PathBuf, LauncherError> {
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(LauncherError::new(
                "INVALID_SYSTEM_TOOL",
                "系统工具名称无效。",
            ));
        }
        let executable = system32_directory()?.join(name);
        ensure_regular_file(&executable)?;
        Ok(executable)
    }

    pub fn windows_powershell_executable() -> Result<PathBuf, LauncherError> {
        let system32 = system32_directory()?;
        let executable = system32
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        ensure_trusted_descendant(&system32, &executable)?;
        ensure_regular_file(&executable)?;
        Ok(executable)
    }

    fn system32_directory() -> Result<PathBuf, LauncherError> {
        let mut buffer = vec![0_u16; 32_768];
        // SAFETY: buffer is writable and its capacity is passed accurately.
        let written =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len().try_into().unwrap()) };
        if written == 0 || written as usize >= buffer.len() {
            return Err(LauncherError::new(
                "SYSTEM_DIRECTORY_UNAVAILABLE",
                "无法解析 Windows System32 目录。",
            ));
        }
        buffer.truncate(written as usize);
        let directory = PathBuf::from(String::from_utf16_lossy(&buffer));
        ensure_directory(&directory)?;
        Ok(directory)
    }

    pub fn program_files_directory() -> Result<PathBuf, LauncherError> {
        let mut raw_path: *mut u16 = null_mut();
        // SAFETY: FOLDER_ID_PROGRAM_FILES is valid and raw_path is writable.
        let result =
            unsafe { SHGetKnownFolderPath(&FOLDER_ID_PROGRAM_FILES, 0, null_mut(), &mut raw_path) };
        if result < 0 || raw_path.is_null() {
            return Err(LauncherError::new(
                "PROGRAM_FILES_UNAVAILABLE",
                "无法解析受信 Program Files 目录。",
            ));
        }
        let mut length = 0_usize;
        // SAFETY: SHGetKnownFolderPath returns a NUL-terminated allocation on success.
        unsafe {
            while length < 32_768 && *raw_path.add(length) != 0 {
                length += 1;
            }
        }
        if length == 32_768 {
            // SAFETY: raw_path was allocated by SHGetKnownFolderPath.
            unsafe {
                CoTaskMemFree(raw_path.cast());
            }
            return Err(LauncherError::new(
                "PROGRAM_FILES_UNAVAILABLE",
                "Program Files 路径超过安全上限。",
            ));
        }
        // SAFETY: raw_path contains at least length initialized UTF-16 code units.
        let value =
            unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(raw_path, length)) };
        // SAFETY: raw_path was allocated by SHGetKnownFolderPath.
        unsafe {
            CoTaskMemFree(raw_path.cast());
        }
        let path = PathBuf::from(value);
        ensure_directory(&path)?;
        ensure_directory_not_writable(&path)?;
        Ok(path)
    }

    pub fn local_app_data_directory() -> Result<PathBuf, LauncherError> {
        let mut raw_path: *mut u16 = null_mut();
        // SAFETY: FOLDER_ID_LOCAL_APP_DATA is valid and raw_path is writable.
        let result = unsafe {
            SHGetKnownFolderPath(&FOLDER_ID_LOCAL_APP_DATA, 0, null_mut(), &mut raw_path)
        };
        if result < 0 || raw_path.is_null() {
            return Err(LauncherError::new(
                "LOCALAPPDATA_UNAVAILABLE",
                "无法通过 Windows Known Folder 解析 LOCALAPPDATA。",
            ));
        }
        let mut length = 0_usize;
        // SAFETY: SHGetKnownFolderPath returns a NUL-terminated allocation on success.
        unsafe {
            while length < 32_768 && *raw_path.add(length) != 0 {
                length += 1;
            }
        }
        if length == 32_768 {
            // SAFETY: raw_path was allocated by SHGetKnownFolderPath.
            unsafe {
                CoTaskMemFree(raw_path.cast());
            }
            return Err(LauncherError::new(
                "LOCALAPPDATA_UNAVAILABLE",
                "Windows LOCALAPPDATA 路径超过安全上限。",
            ));
        }
        // SAFETY: raw_path contains at least length initialized UTF-16 code units.
        let value =
            unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(raw_path, length)) };
        // SAFETY: raw_path was allocated by SHGetKnownFolderPath.
        unsafe {
            CoTaskMemFree(raw_path.cast());
        }
        let path = PathBuf::from(value);
        ensure_local_disk_path(&path)?;
        ensure_tree_no_reparse(&path)?;
        Ok(path)
    }

    pub fn ensure_local_disk_path(path: &Path) -> Result<(), LauncherError> {
        match path.components().next() {
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
            _ => {
                return Err(LauncherError::new(
                    "LOCAL_PATH_REQUIRED",
                    "受控路径必须位于本地盘符；UNC、网络盘和设备路径均被拒绝。",
                ));
            }
        }
        Ok(())
    }

    pub fn ensure_tree_no_reparse(path: &Path) -> Result<(), LauncherError> {
        ensure_local_disk_path(path)?;
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            if matches!(component, Component::Prefix(_) | Component::RootDir) {
                continue;
            }
            ensure_directory(&current)?;
        }
        Ok(())
    }

    pub fn ensure_trusted_descendant(root: &Path, candidate: &Path) -> Result<(), LauncherError> {
        ensure_local_disk_path(root)?;
        ensure_local_disk_path(candidate)?;
        ensure_tree_no_reparse(root)?;
        ensure_directory_not_writable(root)?;
        if !candidate.starts_with(root) {
            return Err(LauncherError::new(
                "TRUSTED_PATH_REQUIRED",
                "可执行文件不在受信 Program Files/System32 根目录内。",
            ));
        }

        let mut current = root.to_path_buf();
        let relative = candidate.strip_prefix(root).map_err(|_| {
            LauncherError::new("TRUSTED_PATH_REQUIRED", "无法验证可执行文件受信根目录。")
        })?;
        let components: Vec<_> = relative.components().collect();
        for (index, component) in components.iter().enumerate() {
            current.push(component.as_os_str());
            if index + 1 == components.len() {
                ensure_regular_file(&current)?;
            } else {
                ensure_directory(&current)?;
                ensure_directory_not_writable(&current)?;
            }
        }

        let canonical_root = fs::canonicalize(root)
            .map_err(|_| LauncherError::new("TRUSTED_PATH_REQUIRED", "无法规范化受信根目录。"))?;
        let canonical_candidate = fs::canonicalize(candidate).map_err(|_| {
            LauncherError::new("TRUSTED_PATH_REQUIRED", "无法规范化可执行文件路径。")
        })?;
        if !canonical_candidate.starts_with(&canonical_root) {
            return Err(LauncherError::new(
                "TRUSTED_PATH_REQUIRED",
                "可执行文件规范路径逃逸受信根目录。",
            ));
        }
        Ok(())
    }

    fn ensure_directory_not_writable(path: &Path) -> Result<(), LauncherError> {
        let path = wide(path.as_os_str());
        for desired_access in [
            FILE_ADD_FILE,
            FILE_ADD_SUBDIRECTORY,
            DELETE_ACCESS,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            // SAFETY: path is NUL terminated; no handle is retained on failed access.
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    desired_access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    null_mut(),
                )
            };
            if !is_invalid_handle(handle) {
                // SAFETY: handle is valid and owned by this function.
                unsafe {
                    CloseHandle(handle);
                }
                return Err(LauncherError::new(
                    "TRUSTED_DIRECTORY_WRITABLE",
                    "Docker Desktop 可执行目录可被当前非提升进程写入，已拒绝信任。",
                ));
            }
            // SAFETY: GetLastError is called immediately after failed CreateFileW.
            if unsafe { GetLastError() } != ERROR_ACCESS_DENIED {
                return Err(LauncherError::new(
                    "TRUSTED_DIRECTORY_ACCESS_UNKNOWN",
                    "无法证明 Docker Desktop 可执行目录不可写。",
                ));
            }
        }
        Ok(())
    }

    pub fn ensure_directory(path: &Path) -> Result<(), LauncherError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            LauncherError::new(
                "LOCAL_DIRECTORY_UNAVAILABLE",
                format!("无法访问受控本机目录：{}", path.display()),
            )
        })?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LauncherError::new(
                "LOCAL_DIRECTORY_UNSAFE",
                format!(
                    "受控本机目录不是普通目录或包含 reparse point：{}",
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    pub fn ensure_regular_file(path: &Path) -> Result<(), LauncherError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            LauncherError::new(
                "LOCAL_FILE_UNAVAILABLE",
                format!("无法访问所需文件：{}", path.display()),
            )
        })?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LauncherError::new(
                "LOCAL_FILE_UNSAFE",
                format!(
                    "所需文件不是普通文件或包含 reparse point：{}",
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    pub fn ensure_authenticode_trusted(path: &Path) -> Result<(), LauncherError> {
        ensure_regular_file(path)?;
        let path = wide(path.as_os_str());
        let mut file_info = WinTrustFileInfo {
            size: size_of::<WinTrustFileInfo>() as u32,
            file_path: path.as_ptr(),
            file: null_mut(),
            known_subject: null(),
        };
        let mut trust_data = WinTrustData {
            size: size_of::<WinTrustData>() as u32,
            policy_callback_data: null_mut(),
            sip_client_data: null_mut(),
            ui_choice: WTD_UI_NONE,
            revocation_checks: WTD_REVOKE_WHOLECHAIN,
            union_choice: WTD_CHOICE_FILE,
            file_info: &mut file_info,
            state_action: WTD_STATEACTION_VERIFY,
            state_data: null_mut(),
            url_reference: null_mut(),
            provider_flags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_CACHE_ONLY_URL_RETRIEVAL,
            ui_context: 0,
            signature_settings: null_mut(),
        };
        // SAFETY: trust_data and file_info remain alive and contain valid pointers for the call.
        let status = unsafe {
            WinVerifyTrust(
                null_mut(),
                &WINTRUST_ACTION_GENERIC_VERIFY_V2,
                (&mut trust_data as *mut WinTrustData).cast(),
            )
        };
        trust_data.state_action = WTD_STATEACTION_CLOSE;
        // SAFETY: closes any state created by the preceding verification call.
        unsafe {
            WinVerifyTrust(
                null_mut(),
                &WINTRUST_ACTION_GENERIC_VERIFY_V2,
                (&mut trust_data as *mut WinTrustData).cast(),
            );
        }
        if status != 0 {
            return Err(LauncherError::new(
                "AUTHENTICODE_INVALID",
                "可执行文件缺少有效、受信的 Authenticode 签名。",
            ));
        }
        Ok(())
    }

    pub fn ensure_authenticode_publisher(
        path: &Path,
        allowed_publishers: &[&str],
    ) -> Result<(), LauncherError> {
        ensure_authenticode_trusted(path)?;
        let publisher = authenticode_publisher(path)?;
        if !allowed_publishers
            .iter()
            .any(|allowed| publisher.eq_ignore_ascii_case(allowed))
        {
            return Err(LauncherError::new(
                "AUTHENTICODE_PUBLISHER_REJECTED",
                "Docker CLI 的 Authenticode 发布者不在固定允许列表内。",
            ));
        }
        Ok(())
    }

    pub fn ensure_authenticode_signer_sha256(
        path: &Path,
        allowed_signers: &[String],
    ) -> Result<String, LauncherError> {
        ensure_authenticode_trusted(path)?;
        let signer = authenticode_signer_certificate_sha256(path)?;
        if !signer_identity_allowed(&signer, allowed_signers) {
            return Err(LauncherError::new(
                "AUTHENTICODE_SIGNER_REJECTED",
                "可执行文件的 Authenticode 签名证书不在固定 SHA-256 允许集内。",
            ));
        }
        Ok(signer)
    }

    fn authenticode_signer_certificate_sha256(path: &Path) -> Result<String, LauncherError> {
        let path = wide(path.as_os_str());
        let mut encoding = 0_u32;
        let mut content = 0_u32;
        let mut format = 0_u32;
        let mut store: Handle = null_mut();
        let mut message: Handle = null_mut();
        let mut context: *const c_void = null();
        // SAFETY: all output pointers are valid and path is NUL terminated.
        let queried = unsafe {
            CryptQueryObject(
                1,
                path.as_ptr().cast(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                &mut encoding,
                &mut content,
                &mut format,
                &mut store,
                &mut message,
                &mut context,
            )
        };
        if queried == 0 || store.is_null() || message.is_null() {
            if !message.is_null() {
                // SAFETY: message was returned by CryptQueryObject and is owned here.
                unsafe {
                    CryptMsgClose(message);
                }
            }
            if !store.is_null() {
                // SAFETY: store was returned by CryptQueryObject and is owned here.
                unsafe {
                    CertCloseStore(store, 0);
                }
            }
            return Err(LauncherError::new(
                "AUTHENTICODE_SIGNER_IDENTITY_UNAVAILABLE",
                "无法读取 Authenticode 签名证书身份。",
            ));
        }

        let result = (|| {
            let mut signer_count = 0_u32;
            let mut signer_count_size = size_of::<u32>() as u32;
            // SAFETY: signer_count points to a u32-sized output buffer.
            if unsafe {
                CryptMsgGetParam(
                    message,
                    CMSG_SIGNER_COUNT_PARAM,
                    0,
                    (&mut signer_count as *mut u32).cast(),
                    &mut signer_count_size,
                )
            } == 0
                || signer_count_size != size_of::<u32>() as u32
                || signer_count != 1
            {
                return Err(LauncherError::new(
                    "AUTHENTICODE_SIGNER_IDENTITY_UNAVAILABLE",
                    "发布制品必须且只能包含一个主 Authenticode 签名者。",
                ));
            }

            let mut info_size = 0_u32;
            // SAFETY: first call requests the required CERT_INFO buffer size.
            if unsafe {
                CryptMsgGetParam(
                    message,
                    CMSG_SIGNER_CERT_INFO_PARAM,
                    0,
                    null_mut(),
                    &mut info_size,
                )
            } == 0
                || info_size == 0
                || info_size > 1024 * 1024
            {
                return Err(LauncherError::new(
                    "AUTHENTICODE_SIGNER_IDENTITY_UNAVAILABLE",
                    "签名证书信息无效。",
                ));
            }
            let mut info = vec![0_u8; info_size as usize];
            // SAFETY: info has exactly the size requested by CryptMsgGetParam.
            if unsafe {
                CryptMsgGetParam(
                    message,
                    CMSG_SIGNER_CERT_INFO_PARAM,
                    0,
                    info.as_mut_ptr().cast(),
                    &mut info_size,
                )
            } == 0
            {
                return Err(LauncherError::new(
                    "AUTHENTICODE_SIGNER_IDENTITY_UNAVAILABLE",
                    "无法读取签名证书信息。",
                ));
            }
            // SAFETY: info is a CERT_INFO returned by CryptMsgGetParam for this message.
            let cert = unsafe {
                CertFindCertificateInStore(
                    store,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    info.as_ptr().cast(),
                    null(),
                )
            };
            if cert.is_null() {
                return Err(LauncherError::new(
                    "AUTHENTICODE_SIGNER_IDENTITY_UNAVAILABLE",
                    "无法定位 Authenticode 签名证书。",
                ));
            }
            // SAFETY: cert is valid until CertFreeCertificateContext below.
            let encoded = unsafe {
                let context = &*cert;
                if context.encoded_cert.is_null()
                    || context.encoded_cert_size == 0
                    || context.encoded_cert_size > 1024 * 1024
                {
                    None
                } else {
                    Some(slice::from_raw_parts(
                        context.encoded_cert,
                        context.encoded_cert_size as usize,
                    ))
                }
            };
            let digest = encoded
                .map(Sha256::digest)
                .ok_or_else(|| {
                    LauncherError::new(
                        "AUTHENTICODE_SIGNER_IDENTITY_UNAVAILABLE",
                        "Authenticode 签名证书编码无效。",
                    )
                })
                .map(|bytes| hex_lower(&bytes));
            // SAFETY: cert is owned by this function and no longer needed.
            unsafe {
                CertFreeCertificateContext(cert);
            }
            digest
        })();

        // SAFETY: handles were returned by CryptQueryObject and are owned here.
        unsafe {
            CryptMsgClose(message);
            CertCloseStore(store, 0);
        }
        result
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            result.push(HEX[(byte >> 4) as usize] as char);
            result.push(HEX[(byte & 0x0f) as usize] as char);
        }
        result
    }

    fn authenticode_publisher(path: &Path) -> Result<String, LauncherError> {
        let path = wide(path.as_os_str());
        let mut encoding = 0_u32;
        let mut content = 0_u32;
        let mut format = 0_u32;
        let mut store: Handle = null_mut();
        let mut message: Handle = null_mut();
        let mut context: *const c_void = null();
        // SAFETY: all output pointers are valid and path is NUL terminated.
        let queried = unsafe {
            CryptQueryObject(
                1,
                path.as_ptr().cast(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                &mut encoding,
                &mut content,
                &mut format,
                &mut store,
                &mut message,
                &mut context,
            )
        };
        if queried == 0 || store.is_null() || message.is_null() {
            return Err(LauncherError::new(
                "AUTHENTICODE_PUBLISHER_UNAVAILABLE",
                "无法读取 Authenticode 发布者。",
            ));
        }

        let result = (|| {
            let mut info_size = 0_u32;
            // SAFETY: first call requests the required CERT_INFO buffer size.
            if unsafe {
                CryptMsgGetParam(
                    message,
                    CMSG_SIGNER_CERT_INFO_PARAM,
                    0,
                    null_mut(),
                    &mut info_size,
                )
            } == 0
                || info_size == 0
                || info_size > 1024 * 1024
            {
                return Err(LauncherError::new(
                    "AUTHENTICODE_PUBLISHER_UNAVAILABLE",
                    "签名证书信息无效。",
                ));
            }
            let mut info = vec![0_u8; info_size as usize];
            // SAFETY: info has exactly the size requested by CryptMsgGetParam.
            if unsafe {
                CryptMsgGetParam(
                    message,
                    CMSG_SIGNER_CERT_INFO_PARAM,
                    0,
                    info.as_mut_ptr().cast(),
                    &mut info_size,
                )
            } == 0
            {
                return Err(LauncherError::new(
                    "AUTHENTICODE_PUBLISHER_UNAVAILABLE",
                    "无法读取签名证书信息。",
                ));
            }
            // SAFETY: info is a CERT_INFO returned by CryptMsgGetParam for this message.
            let cert = unsafe {
                CertFindCertificateInStore(
                    store,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    info.as_ptr().cast(),
                    null(),
                )
            };
            if cert.is_null() {
                return Err(LauncherError::new(
                    "AUTHENTICODE_PUBLISHER_UNAVAILABLE",
                    "无法定位 Authenticode 签名证书。",
                ));
            }
            // SAFETY: cert is valid until CertFreeCertificateContext below.
            let name_length = unsafe {
                CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    null(),
                    null_mut(),
                    0,
                )
            };
            if name_length <= 1 || name_length > 4096 {
                // SAFETY: cert is owned by this function.
                unsafe {
                    CertFreeCertificateContext(cert);
                }
                return Err(LauncherError::new(
                    "AUTHENTICODE_PUBLISHER_UNAVAILABLE",
                    "Authenticode 发布者名称无效。",
                ));
            }
            let mut name = vec![0_u16; name_length as usize];
            // SAFETY: name has the length returned by the preceding call.
            let copied = unsafe {
                CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    null(),
                    name.as_mut_ptr(),
                    name_length,
                )
            };
            // SAFETY: cert is owned by this function and no longer needed.
            unsafe {
                CertFreeCertificateContext(cert);
            }
            if copied != name_length {
                return Err(LauncherError::new(
                    "AUTHENTICODE_PUBLISHER_UNAVAILABLE",
                    "无法稳定读取 Authenticode 发布者名称。",
                ));
            }
            name.truncate((copied - 1) as usize);
            Ok(String::from_utf16_lossy(&name))
        })();

        // SAFETY: handles were returned by CryptQueryObject and are owned here.
        unsafe {
            CryptMsgClose(message);
            CertCloseStore(store, 0);
        }
        result
    }

    pub fn prompt_bootstrap_admin() -> Result<Option<BootstrapInput>, LauncherError> {
        let instance = unsafe { GetModuleHandleW(null()) };
        if instance.is_null() {
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "无法取得 Launcher 模块句柄。",
            ));
        }
        let class_name = wide_text("DataXEnterpriseStudio.BootstrapAdmin.v1");
        let cursor = unsafe { LoadCursorW(null_mut(), IDC_ARROW as *const u16) };
        if cursor.is_null() {
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "无法加载 Windows 对话框光标。",
            ));
        }
        let window_class = WindowClassExW {
            size: size_of::<WindowClassExW>() as u32,
            style: 0,
            window_procedure: Some(bootstrap_window_procedure),
            class_extra: 0,
            window_extra: 0,
            instance,
            icon: null_mut(),
            cursor,
            background: (COLOR_BTNFACE + 1) as Handle,
            menu_name: null(),
            class_name: class_name.as_ptr(),
            small_icon: null_mut(),
        };
        let class = unsafe { RegisterClassExW(&window_class) };
        if class == 0 && unsafe { GetLastError() } != ERROR_CLASS_ALREADY_EXISTS {
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "无法注册首次管理员对话框。",
            ));
        }

        let width = 540;
        let height = 330;
        let screen_width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
        let screen_height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
        let x = (screen_width - width).max(0) / 2;
        let y = (screen_height - height).max(0) / 2;
        let title = wide_text("DataX Enterprise Studio - 创建首次管理员");
        let mut state = Box::new(BootstrapDialogState::new());
        let window = unsafe {
            CreateWindowExW(
                WS_EX_DLGMODALFRAME,
                class_name.as_ptr(),
                title.as_ptr(),
                WS_CAPTION | WS_SYSMENU,
                x,
                y,
                width,
                height,
                null_mut(),
                null_mut(),
                instance,
                (&mut *state as *mut BootstrapDialogState).cast(),
            )
        };
        if window.is_null() {
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "无法创建首次管理员对话框。",
            ));
        }

        let setup_result = setup_bootstrap_controls(window, instance, &mut state);
        if let Err(error) = setup_result {
            clear_bootstrap_password_controls(&state);
            unsafe {
                DestroyWindow(window);
            }
            return Err(error);
        }

        unsafe {
            ShowWindow(window, SW_SHOW);
            UpdateWindow(window);
            SetForegroundWindow(window);
            SetFocus(state.email);
        }

        let mut message = Message {
            window: null_mut(),
            message: 0,
            w_param: 0,
            l_param: 0,
            time: 0,
            point: Point { x: 0, y: 0 },
            private: 0,
        };
        let quit_code = loop {
            let status = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
            if status == -1 {
                clear_bootstrap_password_controls(&state);
                unsafe {
                    DestroyWindow(window);
                }
                return Err(LauncherError::new(
                    "BOOTSTRAP_DIALOG_FAILED",
                    "首次管理员对话框消息循环失败。",
                ));
            }
            if status == 0 {
                break message.w_param;
            }
            if unsafe { IsDialogMessageW(window, &mut message) } == 0 {
                unsafe {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
        };
        if quit_code != 0 {
            clear_bootstrap_password_controls(&state);
            unsafe {
                DestroyWindow(window);
            }
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "首次管理员对话框内部失败；未创建账号。",
            ));
        }
        Ok(state.result.take())
    }

    fn setup_bootstrap_controls(
        window: Handle,
        instance: Handle,
        state: &mut BootstrapDialogState,
    ) -> Result<(), LauncherError> {
        let font = unsafe { GetStockObject(DEFAULT_GUI_FONT) };
        if font.is_null() {
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "无法加载 Windows 默认界面字体。",
            ));
        }
        create_control(
            window,
            instance,
            "STATIC",
            "此引导仅在空用户库显示；临时密码不会保存到 Launcher。",
            WS_CHILD | WS_VISIBLE,
            24,
            20,
            480,
            24,
            0,
            font,
        )?;
        create_control(
            window,
            instance,
            "STATIC",
            "登录邮箱",
            WS_CHILD | WS_VISIBLE,
            24,
            64,
            112,
            24,
            0,
            font,
        )?;
        state.email = create_control(
            window,
            instance,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL,
            144,
            60,
            352,
            25,
            101,
            font,
        )?;
        create_control(
            window,
            instance,
            "STATIC",
            "显示名",
            WS_CHILD | WS_VISIBLE,
            24,
            104,
            112,
            24,
            0,
            font,
        )?;
        state.display_name = create_control(
            window,
            instance,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL,
            144,
            100,
            352,
            25,
            102,
            font,
        )?;
        create_control(
            window,
            instance,
            "STATIC",
            "临时密码",
            WS_CHILD | WS_VISIBLE,
            24,
            144,
            112,
            24,
            0,
            font,
        )?;
        state.password = create_control(
            window,
            instance,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD,
            144,
            140,
            352,
            25,
            103,
            font,
        )?;
        create_control(
            window,
            instance,
            "STATIC",
            "确认密码",
            WS_CHILD | WS_VISIBLE,
            24,
            184,
            112,
            24,
            0,
            font,
        )?;
        state.confirm_password = create_control(
            window,
            instance,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD,
            144,
            180,
            352,
            25,
            104,
            font,
        )?;
        create_control(
            window,
            instance,
            "STATIC",
            "密码需 12 至 256 个字符；首次登录后必须修改。",
            WS_CHILD | WS_VISIBLE,
            144,
            212,
            352,
            22,
            0,
            font,
        )?;
        create_control(
            window,
            instance,
            "BUTTON",
            "创建管理员",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            282,
            252,
            110,
            30,
            IDOK,
            font,
        )?;
        create_control(
            window,
            instance,
            "BUTTON",
            "取消",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            404,
            252,
            92,
            30,
            IDCANCEL,
            font,
        )?;
        unsafe {
            SendMessageW(state.email, EM_SETLIMITTEXT, 508, 0);
            SendMessageW(state.display_name, EM_SETLIMITTEXT, 256, 0);
            SendMessageW(state.password, EM_SETLIMITTEXT, 512, 0);
            SendMessageW(state.confirm_password, EM_SETLIMITTEXT, 512, 0);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn create_control(
        parent: Handle,
        instance: Handle,
        class: &str,
        text: &str,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        identifier: usize,
        font: Handle,
    ) -> Result<Handle, LauncherError> {
        let class = wide_text(class);
        let text = wide_text(text);
        let control = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                text.as_ptr(),
                style,
                x,
                y,
                width,
                height,
                parent,
                identifier as Handle,
                instance,
                null_mut(),
            )
        };
        if control.is_null() {
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "无法创建首次管理员对话框控件。",
            ));
        }
        unsafe {
            SendMessageW(control, WM_SETFONT, font as usize, 1);
        }
        Ok(control)
    }

    unsafe extern "system" fn bootstrap_window_procedure(
        window: Handle,
        message: u32,
        w_param: usize,
        l_param: isize,
    ) -> isize {
        catch_unwind(AssertUnwindSafe(|| {
            bootstrap_window_procedure_inner(window, message, w_param, l_param)
        }))
        .unwrap_or_else(|_| {
            unsafe {
                PostQuitMessage(1);
            }
            0
        })
    }

    fn bootstrap_window_procedure_inner(
        window: Handle,
        message: u32,
        w_param: usize,
        l_param: isize,
    ) -> isize {
        if message == WM_NCCREATE {
            let create = l_param as *const CreateStructW;
            if create.is_null() {
                return 0;
            }
            let state = unsafe { (*create).create_parameters };
            if state.is_null() {
                return 0;
            }
            unsafe {
                SetWindowLongPtrW(window, GWLP_USERDATA, state as isize);
            }
            return 1;
        }

        let state_pointer =
            unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) as *mut BootstrapDialogState };
        match message {
            WM_COMMAND if !state_pointer.is_null() => {
                let identifier = w_param & 0xffff;
                if identifier == IDOK {
                    let state = unsafe { &mut *state_pointer };
                    match collect_bootstrap_input(state) {
                        Ok(input) => {
                            state.result = Some(input);
                            clear_bootstrap_password_controls(state);
                            unsafe {
                                DestroyWindow(window);
                            }
                        }
                        Err(error) => {
                            clear_bootstrap_password_controls(state);
                            let title = wide_text("DataX Enterprise Studio");
                            let message = wide_text(error.message());
                            unsafe {
                                MessageBoxW(
                                    window,
                                    message.as_ptr(),
                                    title.as_ptr(),
                                    MB_OK | MB_ICONERROR,
                                );
                                SetFocus(state.password);
                            }
                        }
                    }
                    return 0;
                }
                if identifier == IDCANCEL {
                    let state = unsafe { &mut *state_pointer };
                    clear_bootstrap_password_controls(state);
                    unsafe {
                        DestroyWindow(window);
                    }
                    return 0;
                }
            }
            WM_CLOSE => {
                if !state_pointer.is_null() {
                    clear_bootstrap_password_controls(unsafe { &*state_pointer });
                }
                unsafe {
                    DestroyWindow(window);
                }
                return 0;
            }
            WM_DESTROY => {
                unsafe {
                    PostQuitMessage(0);
                }
                return 0;
            }
            WM_NCDESTROY => unsafe {
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            },
            _ => {}
        }
        unsafe { DefWindowProcW(window, message, w_param, l_param) }
    }

    fn collect_bootstrap_input(
        state: &BootstrapDialogState,
    ) -> Result<BootstrapInput, LauncherError> {
        let email_utf16 = get_control_text(state.email, 508)?;
        let display_utf16 = get_control_text(state.display_name, 256)?;
        let mut password = Zeroizing::new(get_control_text(state.password, 512)?);
        let mut confirmation = Zeroizing::new(get_control_text(state.confirm_password, 512)?);
        let passwords_match = constant_time_utf16_equal(&password, &confirmation);
        confirmation.zeroize();
        if !passwords_match {
            password.zeroize();
            return Err(LauncherError::new(
                "BOOTSTRAP_PASSWORD_MISMATCH",
                "两次输入的临时密码不一致，请重新输入。",
            ));
        }
        let email = String::from_utf16(&email_utf16).map_err(|_| {
            password.zeroize();
            LauncherError::new("BOOTSTRAP_EMAIL_INVALID", "登录邮箱包含无效 Unicode。")
        })?;
        let display_name = String::from_utf16(&display_utf16).map_err(|_| {
            password.zeroize();
            LauncherError::new("BOOTSTRAP_DISPLAY_NAME_INVALID", "显示名包含无效 Unicode。")
        })?;
        Ok(BootstrapInput {
            email,
            display_name,
            password_utf16: password,
        })
    }

    fn get_control_text(window: Handle, maximum: usize) -> Result<Vec<u16>, LauncherError> {
        if window.is_null() {
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "首次管理员对话框控件状态无效。",
            ));
        }
        let length = unsafe { GetWindowTextLengthW(window) };
        if length < 0 || length as usize > maximum {
            return Err(LauncherError::new(
                "BOOTSTRAP_INPUT_TOO_LONG",
                "首次管理员字段超过允许长度。",
            ));
        }
        let mut value = vec![0_u16; length as usize + 1];
        let copied = unsafe { GetWindowTextW(window, value.as_mut_ptr(), value.len() as i32) };
        if copied < 0 || copied as usize > length as usize {
            value.zeroize();
            return Err(LauncherError::new(
                "BOOTSTRAP_DIALOG_FAILED",
                "无法读取首次管理员对话框字段。",
            ));
        }
        value.truncate(copied as usize);
        Ok(value)
    }

    fn clear_bootstrap_password_controls(state: &BootstrapDialogState) {
        let empty = [0_u16];
        unsafe {
            if !state.password.is_null() {
                SetWindowTextW(state.password, empty.as_ptr());
            }
            if !state.confirm_password.is_null() {
                SetWindowTextW(state.confirm_password, empty.as_ptr());
            }
        }
    }

    fn constant_time_utf16_equal(left: &[u16], right: &[u16]) -> bool {
        if left.len() != right.len() {
            return false;
        }
        left.iter()
            .zip(right)
            .fold(0_u16, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    pub fn show_error(title: &str, message: &str) {
        let title = wide_text(title);
        let message = wide_text(message);
        // SAFETY: strings are NUL terminated and no window handle is required.
        unsafe {
            MessageBoxW(
                null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    pub fn show_info(title: &str, message: &str) {
        let title = wide_text(title);
        let message = wide_text(message);
        // SAFETY: strings are NUL terminated and no window handle is required.
        unsafe {
            MessageBoxW(
                null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONINFORMATION,
            );
        }
    }

    pub fn confirm_force_stop() -> bool {
        let title = wide_text("DataX Enterprise Studio");
        let message = wide_text(
            "强制停止会中断活动执行。下次启动时，不确定的执行将收敛为 LOST，目标会进入恢复门禁。\n\n确定继续吗？",
        );
        // SAFETY: strings are NUL terminated and no window handle is required.
        unsafe {
            MessageBoxW(
                null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
            ) == IDYES
        }
    }

    pub fn open_browser(url: &str) -> Result<(), LauncherError> {
        let operation = wide_text("open");
        let url = wide_text(url);
        // SAFETY: operation and URL are NUL terminated fixed launcher strings.
        let result = unsafe {
            ShellExecuteW(
                null_mut(),
                operation.as_ptr(),
                url.as_ptr(),
                null(),
                null(),
                SW_SHOWNORMAL,
            )
        };
        if result <= 32 {
            return Err(LauncherError::new(
                "BROWSER_OPEN_FAILED",
                "本机服务已就绪，但无法打开默认浏览器。请手动访问 http://127.0.0.1:17860。",
            ));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
mod imp {
    use super::{BootstrapInput, LauncherError, Path, PathBuf};

    pub struct InstanceGuard;

    pub fn acquire_single_instance() -> Result<InstanceGuard, LauncherError> {
        Ok(InstanceGuard)
    }

    pub fn ensure_supported_host() -> Result<(), LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "Launcher 只支持 Windows 11 x64；当前构建仅用于静态检查和单元测试。",
        ))
    }

    pub fn ensure_hardware_prerequisites(_data_path: &Path) -> Result<(), LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "Windows 硬件前置检查在当前主机不可用。",
        ))
    }

    pub fn system32_executable(_name: &str) -> Result<PathBuf, LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "Windows 系统工具在当前主机不可用。",
        ))
    }

    pub fn windows_powershell_executable() -> Result<PathBuf, LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "Windows PowerShell 在当前主机不可用。",
        ))
    }

    pub fn program_files_directory() -> Result<PathBuf, LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "Program Files 在当前主机不可用。",
        ))
    }

    pub fn local_app_data_directory() -> Result<PathBuf, LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "Windows LOCALAPPDATA Known Folder 在当前主机不可用。",
        ))
    }

    pub fn ensure_local_disk_path(_path: &Path) -> Result<(), LauncherError> {
        Ok(())
    }

    pub fn ensure_tree_no_reparse(path: &Path) -> Result<(), LauncherError> {
        ensure_directory(path)
    }

    pub fn ensure_trusted_descendant(_root: &Path, candidate: &Path) -> Result<(), LauncherError> {
        ensure_regular_file(candidate)
    }

    pub fn ensure_directory(path: &Path) -> Result<(), LauncherError> {
        if path.is_dir() {
            Ok(())
        } else {
            Err(LauncherError::new(
                "LOCAL_DIRECTORY_UNAVAILABLE",
                format!("目录不可用：{}", path.display()),
            ))
        }
    }

    pub fn ensure_regular_file(path: &Path) -> Result<(), LauncherError> {
        if path.is_file() {
            Ok(())
        } else {
            Err(LauncherError::new(
                "LOCAL_FILE_UNAVAILABLE",
                format!("文件不可用：{}", path.display()),
            ))
        }
    }

    pub fn ensure_authenticode_trusted(_path: &Path) -> Result<(), LauncherError> {
        Ok(())
    }

    pub fn ensure_authenticode_publisher(
        _path: &Path,
        _allowed_publishers: &[&str],
    ) -> Result<(), LauncherError> {
        Ok(())
    }

    pub fn ensure_authenticode_signer_sha256(
        _path: &Path,
        _allowed_signers: &[String],
    ) -> Result<String, LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "Authenticode 发布证书身份核验只支持 Windows 11 x64。",
        ))
    }

    pub fn show_error(_title: &str, message: &str) {
        eprintln!("{message}");
    }

    pub fn show_info(_title: &str, message: &str) {
        println!("{message}");
    }

    pub fn confirm_force_stop() -> bool {
        false
    }

    pub fn prompt_bootstrap_admin() -> Result<Option<BootstrapInput>, LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "首次管理员 Windows 原生对话框在当前主机不可用。",
        ))
    }

    pub fn open_browser(_url: &str) -> Result<(), LauncherError> {
        Err(LauncherError::new(
            "UNSUPPORTED_HOST",
            "默认浏览器启动仅支持 Windows 11 x64。",
        ))
    }
}

pub use imp::*;

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use std::ffi::c_void;

pub type NTSTATUS = i32;

pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004u32 as i32;
pub const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x80000005u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023u32 as i32;
pub const STATUS_INVALID_HANDLE: NTSTATUS = 0xC0000008u32 as i32;
pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022u32 as i32;

pub const SystemProcessInformation: u32 = 5;
pub const SystemProcessorPerformanceInformation: u32 = 8;
pub const SystemPagefileInformation: u32 = 18;
pub const SystemMemoryListInformation: u32 = 80;
pub const SystemExtendedHandleInformation: u32 = 64;

pub const ObjectNameInformation: u32 = 1;
pub const ObjectTypesInformation: u32 = 3;

pub const ThreadQuerySetWin32StartAddress: u32 = 9;

pub const ProcessBasicInformation: u32 = 0;
pub const ProcessCommandLineInformation: u32 = 60;
pub const ProcessProtectionInformation: u32 = 61;
pub const ProcessBreakOnTermination: u32 = 29;

pub fn protection_label(ps_protection: u8) -> String {
    let kind = match ps_protection & 0x7 {
        0 => return String::new(),
        1 => "PPL",
        2 => "PP",
        _ => "Protected",
    };
    let signer = match ps_protection >> 4 {
        1 => "Authenticode",
        2 => "CodeGen",
        3 => "Antimalware",
        4 => "Lsa",
        5 => "Windows",
        6 => "WinTcb",
        7 => "WinSystem",
        8 => "App",
        _ => "",
    };
    if signer.is_empty() {
        kind.to_string()
    } else {
        format!("{} {}", kind, signer)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

impl UNICODE_STRING {
    pub unsafe fn to_string(&self) -> String {
        if self.Buffer.is_null() || self.Length == 0 {
            return String::new();
        }
        let len = (self.Length / 2) as usize;
        let slice = unsafe { std::slice::from_raw_parts(self.Buffer, len) };
        String::from_utf16_lossy(slice)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
    pub IdleTime: i64,
    pub KernelTime: i64,
    pub UserTime: i64,
    pub DpcTime: i64,
    pub InterruptTime: i64,
    pub InterruptCount: u32,
}

#[repr(C)]
pub struct SYSTEM_PAGEFILE_INFORMATION {
    pub NextEntryOffset: u32,
    pub TotalSize: u32,
    pub TotalInUse: u32,
    pub PeakUsage: u32,
    pub PageFileName: UNICODE_STRING,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SYSTEM_MEMORY_LIST_INFORMATION {
    pub ZeroPageCount: usize,
    pub FreePageCount: usize,
    pub ModifiedPageCount: usize,
    pub ModifiedNoWritePageCount: usize,
    pub BadPageCount: usize,
    pub PageCountByPriority: [usize; 8],
    pub RepurposedPagesByPriority: [usize; 8],
    pub ModifiedPageCountPageFile: usize,
}

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: *mut c_void,
    pub UniqueThread: *mut c_void,
}

#[repr(C)]
pub struct SYSTEM_THREAD_INFORMATION {
    pub KernelTime: i64,
    pub UserTime: i64,
    pub CreateTime: i64,
    pub WaitTime: u32,
    pub StartAddress: *mut c_void,
    pub ClientId: CLIENT_ID,
    pub Priority: i32,
    pub BasePriority: i32,
    pub ContextSwitches: u32,
    pub ThreadState: u32,
    pub WaitReason: u32,
}

#[repr(C)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub WorkingSetPrivateSize: i64,
    pub HardFaultCount: u32,
    pub NumberOfThreadsHighWatermark: u32,
    pub CycleTime: u64,
    pub CreateTime: i64,
    pub UserTime: i64,
    pub KernelTime: i64,
    pub ImageName: UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: isize,
    pub InheritedFromUniqueProcessId: isize,
    pub HandleCount: u32,
    pub SessionId: u32,
    pub UniqueProcessKey: usize,
    pub PeakVirtualSize: usize,
    pub VirtualSize: usize,
    pub PageFaultCount: u32,
    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,
    pub QuotaPeakPagedPoolUsage: usize,
    pub QuotaPagedPoolUsage: usize,
    pub QuotaPeakNonPagedPoolUsage: usize,
    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub PrivatePageCount: usize,
    pub ReadOperationCount: i64,
    pub WriteOperationCount: i64,
    pub OtherOperationCount: i64,
    pub ReadTransferCount: i64,
    pub WriteTransferCount: i64,
    pub OtherTransferCount: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    pub Object: *mut c_void,
    pub UniqueProcessId: usize,
    pub HandleValue: usize,
    pub GrantedAccess: u32,
    pub CreatorBackTraceIndex: u16,
    pub ObjectTypeIndex: u16,
    pub HandleAttributes: u32,
    pub Reserved: u32,
}

#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION_EX {
    pub NumberOfHandles: usize,
    pub Reserved: usize,
    pub Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 1],
}

#[repr(C)]
pub struct GENERIC_MAPPING {
    pub GenericRead: u32,
    pub GenericWrite: u32,
    pub GenericExecute: u32,
    pub GenericAll: u32,
}

#[repr(C)]
pub struct OBJECT_TYPE_INFORMATION {
    pub TypeName: UNICODE_STRING,
    pub TotalNumberOfObjects: u32,
    pub TotalNumberOfHandles: u32,
    pub TotalPagedPoolUsage: u32,
    pub TotalNonPagedPoolUsage: u32,
    pub TotalNamePoolUsage: u32,
    pub TotalHandleTableUsage: u32,
    pub HighWaterNumberOfObjects: u32,
    pub HighWaterNumberOfHandles: u32,
    pub HighWaterPagedPoolUsage: u32,
    pub HighWaterNonPagedPoolUsage: u32,
    pub HighWaterNamePoolUsage: u32,
    pub HighWaterHandleTableUsage: u32,
    pub InvalidAttributes: u32,
    pub GenericMapping: GENERIC_MAPPING,
    pub ValidAccessMask: u32,
    pub SecurityRequired: u8,
    pub MaintainHandleCount: u8,
    pub TypeIndex: u8,
    pub ReservedByte: u8,
    pub PoolType: u32,
    pub DefaultPagedPoolCharge: u32,
    pub DefaultNonPagedPoolCharge: u32,
}

#[repr(C)]
pub struct OBJECT_TYPES_INFORMATION {
    pub NumberOfTypes: u32,
}

#[repr(C)]
pub struct OBJECT_NAME_INFORMATION {
    pub Name: UNICODE_STRING,
}

#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION {
    pub ExitStatus: NTSTATUS,
    pub PebBaseAddress: *mut c_void,
    pub AffinityMask: usize,
    pub BasePriority: i32,
    pub UniqueProcessId: usize,
    pub InheritedFromUniqueProcessId: usize,
}

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: *mut c_void,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: *mut c_void,
    pub ConsoleFlags: u32,
    pub StandardInput: *mut c_void,
    pub StandardOutput: *mut c_void,
    pub StandardError: *mut c_void,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: *mut c_void,
    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,
    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [u8; 32 * 24],
    pub EnvironmentSize: usize,
    pub EnvironmentVersion: usize,
}

pub const PEB_OFFSET_PROCESS_PARAMETERS: usize = 0x20;

pub const DIRECTORY_QUERY: u32 = 0x0001;
pub const SYMBOLIC_LINK_QUERY: u32 = 0x0001;

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: *mut c_void,
    pub ObjectName: *const UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *const c_void,
    pub SecurityQualityOfService: *const c_void,
}

#[repr(C)]
pub struct OBJECT_DIRECTORY_INFORMATION {
    pub Name: UNICODE_STRING,
    pub TypeName: UNICODE_STRING,
}

pub fn unicode(buf: &[u16]) -> UNICODE_STRING {
    let bytes = (buf.len().saturating_sub(1) * 2) as u16;
    UNICODE_STRING { Length: bytes, MaximumLength: bytes + 2, Buffer: buf.as_ptr() as *mut u16 }
}

pub fn attributes(name: &UNICODE_STRING, root: *mut c_void) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES { Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32, RootDirectory: root, ObjectName: name, Attributes: 0x40, SecurityDescriptor: std::ptr::null(), SecurityQualityOfService: std::ptr::null() }
}

unsafe extern "system" {
    pub fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut c_void,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;

    pub fn NtQueryObject(
        Handle: *mut c_void,
        ObjectInformationClass: u32,
        ObjectInformation: *mut c_void,
        ObjectInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;

    pub fn NtQueryInformationProcess(
        ProcessHandle: *mut c_void,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;

    pub fn NtQueryInformationThread(
        ThreadHandle: *mut c_void,
        ThreadInformationClass: u32,
        ThreadInformation: *mut c_void,
        ThreadInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;

    pub fn NtSuspendProcess(ProcessHandle: *mut c_void) -> NTSTATUS;

    pub fn NtResumeProcess(ProcessHandle: *mut c_void) -> NTSTATUS;

    pub fn NtOpenDirectoryObject(DirectoryHandle: *mut *mut c_void, DesiredAccess: u32, ObjectAttributes: *const OBJECT_ATTRIBUTES) -> NTSTATUS;

    pub fn NtQueryDirectoryObject(DirectoryHandle: *mut c_void, Buffer: *mut c_void, Length: u32, ReturnSingleEntry: u8, RestartScan: u8, Context: *mut u32, ReturnLength: *mut u32) -> NTSTATUS;

    pub fn NtOpenSymbolicLinkObject(LinkHandle: *mut *mut c_void, DesiredAccess: u32, ObjectAttributes: *const OBJECT_ATTRIBUTES) -> NTSTATUS;

    pub fn NtQuerySymbolicLinkObject(LinkHandle: *mut c_void, LinkTarget: *mut UNICODE_STRING, ReturnedLength: *mut u32) -> NTSTATUS;

    pub fn NtClose(Handle: *mut c_void) -> NTSTATUS;
}

pub fn nt_ok(status: NTSTATUS) -> bool {
    status >= 0
}

pub fn status_text(status: NTSTATUS) -> String {
    match status {
        STATUS_ACCESS_DENIED => "access denied".into(),
        STATUS_INVALID_HANDLE => "invalid handle".into(),
        _ => format!("NTSTATUS 0x{:08X}", status as u32),
    }
}

use clap::Parser;
use debugid::DebugId;
use eyre::{Context, OptionExt};
use object::{
    read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile32, PeFile64},
    Object as _,
};
use pdb::{FallibleIterator, Rva, PDB};
use std::{borrow::Cow, collections::HashMap, fmt, fs::File, path::PathBuf, rc::Rc, str::FromStr};
use symbolic_demangle::Demangle as _;
use symsrv::SymsrvDownloader;
use windows::{core::Owned, Win32::System::Registry::HKEY};

/// This program uses [Microsoft Symbol Server] to get debug symbols for
/// `twinui.pcshell.dll` and then searches those symbols for information related
/// to the Virtual Desktop COM interfaces.
///
/// Code was inspired by the python script at [GetVirtualDesktopAPI_DIA]
///
/// [GetVirtualDesktopAPI_DIA]: https://github.com/mzomparelli/GetVirtualDesktopAPI_DIA
///
/// [Microsoft Symbol Server]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols
#[derive(Debug, clap::Parser)]
struct Args {
    /// Show all interface ids and show info about all virtual function tables.
    /// If this is not specified then only info about COM interfaces that seem
    /// relevant will be shown.
    #[clap(long = "all", visible_alias = "unfiltered")]
    unfiltered: bool,

    /// Specify a PeCodeId for the `twinui.pcshell.dll` file in order to
    /// download a specific version of the dll file from a Microsoft Symbol
    /// Server.
    ///
    /// Note: if the specified version already exists then nothing will be
    /// downloaded.
    #[clap(long)]
    twinui_dll_id: Option<PeCodeId>,

    /// Specify a PeCodeId for the `actxprxy.dll` file in order to download a
    /// specific version of the dll file from a Microsoft Symbol Server.
    ///
    /// Note: if the specified version already exists then nothing will be
    /// downloaded.
    #[clap(long)]
    actxprxy_dll_id: Option<PeCodeId>,

    /// Don't use any information from `twinui.pcshell.dll`.
    #[clap(long, conflicts_with = "twinui_dll_id")]
    skip_twinui: bool,

    /// Don't use any information from `actxprxy.dll`.
    #[clap(long, conflicts_with = "actxprxy_dll_id")]
    skip_actxprxy: bool,

    /// Don't print the current Windows version. Implied if a DLL PeCodeId is specified.
    #[clap(long)]
    skip_windows_version: bool,

    /// Don't search for interface ids in the Windows registry. Implied if a DLL PeCodeId is specified.
    #[clap(long)]
    skip_windows_registry: bool,
}

fn system32() -> eyre::Result<PathBuf> {
    // https://learn.microsoft.com/en-us/windows/deployment/usmt/usmt-recognized-environment-variables
    if let Some(found) = std::env::var_os("CSIDL_SYSTEM") {
        Ok(found.into())
    } else if let Some(windows) =
        std::env::var_os("WINDIR").or_else(|| std::env::var_os("SYSTEMROOT"))
    {
        Ok(PathBuf::from(windows).join("System32"))
    } else {
        // Assume it on the C drive:
        Ok(PathBuf::from(r"C:\Windows\System32"))
    }
}

/// Contains virtual function tables (vftables).
fn twinui_pcshell_path() -> eyre::Result<PathBuf> {
    Ok(system32()?.join("twinui.pcshell.dll"))
}

/// Contains IID values for private virtual desktop interfaces.
fn actxprxy_path() -> eyre::Result<PathBuf> {
    Ok(system32()?.join("actxprxy.dll"))
}

/// Parts of known mangled names for vtables
const VIRTUAL_DESKTOP_V_TABLE_NAMES: &[&str] = &[
    "??_7CVirtualDesktop@@6BIVirtualDesktop@@@",
    "??_7CVirtualDesktop@@6B?$Chain",
    "??_7CVirtualDesktopManager@@6BIVirtualDesktopManagerInternal2@@@",
    "??_7CVirtualDesktopNotificationsDerived@@6BIVirtualDesktopNotification@@@",
    "??_7CVirtualDesktopNotificationsDerived@@6B@",
    "??_7CVirtualDesktopHotkeyHandler@@6B@",
    "??_7VirtualDesktopsApi@@6B@",
    "??_7VirtualPinnedAppsHandler@@6B?$Chain",
    "??_7ApplicationViewCollectionBase@@6B@",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct WindowsVersion {
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub patch_version: Option<u32>,
}
impl WindowsVersion {
    /// Get the Windows patch version (the last number in the full version).
    ///
    /// # References
    ///
    /// - This is how the C# VirtualDesktop library does it: [VirtualDesktop/src/VirtualDesktop/Utils/OS.cs at 7e37b9848aef681713224dae558d2e51960cf41e · mzomparelli/VirtualDesktop](https://github.com/mzomparelli/VirtualDesktop/blob/7e37b9848aef681713224dae558d2e51960cf41e/src/VirtualDesktop/Utils/OS.cs#L21)
    /// - We use this function: [RegGetValueW in windows::Win32::System::Registry - Rust](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegGetValueW.html)
    ///   - Function docs: [RegGetValueW function (winreg.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew)
    ///   - StackOverflow usage example: [windows - RegGetValueW(), how to do it right - Stack Overflow](https://stackoverflow.com/questions/78224404/reggetvaluew-how-to-do-it-right)
    /// - Info about the registry key: [.net - C# - How to show the full Windows 10 build number? - Stack Overflow](https://stackoverflow.com/questions/52041735/c-sharp-how-to-show-the-full-windows-10-build-number)
    fn read_patch_version_from_registry() -> Option<u32> {
        use windows::{
            core::w,
            Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD},
        };

        let mut buffer: [u8; 4] = [0; 4];
        let mut cb_data = buffer.len() as u32;
        let res = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                w!(r#"SOFTWARE\Microsoft\Windows NT\CurrentVersion"#),
                w!("UBR"),
                RRF_RT_REG_DWORD,
                Some(std::ptr::null_mut()),
                Some(buffer.as_mut_ptr() as _),
                Some(&mut cb_data as *mut u32),
            )
        };
        if res.is_err() {
            eprintln!(
                "Failed to read Windows patch version from the registry: {:?}",
                windows::core::Error::from(res.to_hresult())
            );
            return None;
        }

        // REG_DWORD is signed 32-bit, using little endian
        let patch_version = i32::from_le_bytes(buffer);
        if patch_version < 0 {
            eprintln!(
                "Windows patch version read from the registry was negative \
                ({patch_version}), ignoring read value"
            );
        }
        u32::try_from(patch_version).ok()
    }
    /// Get info about the current Windows version.
    ///
    /// # Determining Windows Version
    ///
    /// We could use the [`GetVersionExW` function
    /// (sysinfoapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw),
    /// but it is deprecated after Windows 8.1. It also changes behavior depending
    /// on what manifest is embedded in the executable.
    ///
    /// That pages links to [Version Helper functions - Win32
    /// apps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/version-helper-apis)
    /// where we are linked to the [`IsWindowsVersionOrGreater` function
    /// (versionhelpers.h)](https://learn.microsoft.com/en-us/windows/win32/api/VersionHelpers/nf-versionhelpers-iswindowsversionorgreater)
    /// and the [`VerifyVersionInfoA` function
    /// (winbase.h)](https://learn.microsoft.com/en-us/windows/win32/api/Winbase/nf-winbase-verifyversioninfoa)
    /// that it uses internally (though the later function is deprecated in Windows
    /// 10).
    ///
    /// We can use `RtlGetVersion` [RtlGetVersion function (wdm.h) - Windows
    /// drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion?redirectedfrom=MSDN)
    /// as mentioned at [c++ - Detecting Windows 10 version - Stack
    /// Overflow](https://stackoverflow.com/questions/36543301/detecting-windows-10-version/36545162#36545162).
    ///
    /// # `windows` API References
    ///
    /// - [GetVersionExW in windows::Win32::System::SystemInformation -
    ///   Rust](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/SystemInformation/fn.GetVersionExW.html)
    ///   - Affected by manifest.
    /// - [RtlGetVersion in windows::Wdk::System::SystemServices -
    ///   Rust](https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/System/SystemServices/fn.RtlGetVersion.html)
    ///   - Always returns the correct version.
    pub fn get() -> eyre::Result<Self> {
        let mut version: windows::Win32::System::SystemInformation::OSVERSIONINFOW =
            Default::default();
        version.dwOSVersionInfoSize = core::mem::size_of_val(&version) as u32;
        unsafe { windows::Wdk::System::SystemServices::RtlGetVersion(&mut version) }
            .ok()
            .context("Failed to get Windows version from RtlGetVersion")?;

        let patch_version = Self::read_patch_version_from_registry();
        Ok(Self {
            major_version: version.dwMajorVersion,
            minor_version: version.dwMinorVersion,
            build_number: version.dwBuildNumber,
            patch_version,
        })
    }
}
impl fmt::Display for WindowsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major_version,
            self.minor_version,
            self.build_number,
            match self.patch_version {
                Some(v) => v.to_string(),
                None => "N/A".to_owned(),
            }
        )
    }
}

/// Iterator over interface ids and interface names stored in the windows
/// registry.
#[derive(Debug, Clone)]
pub struct RegistryIIDs {
    interface_key: Rc<Owned<HKEY>>,
    index: u32,
}
impl RegistryIIDs {
    /// Opens the registry directory
    /// `HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface`.
    ///
    /// # References
    ///
    /// - [RegOpenKeyExW in windows::Win32::System::Registry - Rust](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegOpenKeyExW.html)
    ///   - [RegOpenKeyExW function (winreg.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw)
    ///   - [Registry Key Security and Access Rights - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
    pub fn open() -> eyre::Result<Self> {
        use windows::{
            core::w,
            Win32::System::Registry::{
                RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE,
            },
        };

        let mut result = HKEY::default();
        unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                w!(r#"SOFTWARE\Classes\Interface"#),
                0,
                KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                &mut result,
            )
        }
        .ok()?;

        Ok(RegistryIIDs {
            interface_key: Rc::new(unsafe { Owned::new(result) }),
            index: 0,
        })
    }
}
impl Iterator for RegistryIIDs {
    type Item = eyre::Result<(uuid::Uuid, Option<String>)>;

    /// Get a subkey of the interface key and interpret its name as an interface
    /// id and its default value as the interface name.
    ///
    /// # References
    ///
    /// - [RegEnumKeyW in windows::Win32::System::Registry - Rust](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegEnumKeyW.html)
    ///   - [RegEnumKeyW function (winreg.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyw)
    ///   - [Registry element size limits - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits)
    /// - [RegGetValueW in windows::Win32::System::Registry - Rust](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegGetValueW.html)
    ///   - [RegGetValueW function (winreg.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew)
    fn next(&mut self) -> Option<Self::Item> {
        use windows::{
            core::PCWSTR,
            Win32::{
                Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS},
                System::Registry::{RegEnumKeyW, RegGetValueW, RRF_RT_REG_SZ},
            },
        };

        // Key name can't be more than 255 characters long.
        // Buffer that receives the name of the subkey, including the terminating null character.
        // Only the name of the subkey, not the full key hierarchy.
        let mut key_name = [0; 1024];
        let result = unsafe { RegEnumKeyW(**self.interface_key, self.index, Some(&mut key_name)) };
        if result == ERROR_NO_MORE_ITEMS {
            return None;
        }
        self.index += 1;
        if let Err(e) = result.ok() {
            return Some(Err(eyre::eyre!(e)).context(
                "Failed to open subkey of registry key \
                    HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Interface",
            ));
        }

        let key_str = match String::from_utf16(
            &key_name[..key_name.iter().position(|&c| c == 0).unwrap_or_default()],
        ) {
            Ok(v) => v,
            Err(e) => {
                return Some(Err(e).context(
                    "Failed to convert name to utf16 for registry key in \
                        HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Interface",
                ))
            }
        };
        let iid = match uuid::Uuid::from_str(key_str.trim_matches(['{', '}'])) {
            Ok(v) => v,
            Err(e) => {
                return Some(Err(e).context(format!(
                    "Failed to parse key name as guid for registry key \
                        HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Interface\\{key_str}"
                )))
            }
        };

        let mut heap_buffer;
        let mut stack_buffer = [0_u16; 512];
        let mut value_buf = stack_buffer.as_mut_slice();
        let mut value_len: u32 = std::mem::size_of_val(value_buf) as u32;
        let mut result = unsafe {
            RegGetValueW(
                **self.interface_key,
                PCWSTR::from_raw(key_name.as_ptr()),
                PCWSTR::null(),
                RRF_RT_REG_SZ,
                None,
                Some(value_buf.as_mut_ptr() as *mut core::ffi::c_void),
                Some(&mut value_len),
            )
        };
        if result == ERROR_MORE_DATA {
            // Our stack buffer wasn't large enough, use a heap buffer with the required size:
            heap_buffer = vec![
                0_u16;
                value_len as usize / core::mem::size_of::<u16>()
                    + (value_len % 2) as usize
            ];
            value_buf = heap_buffer.as_mut_slice();
            result = unsafe {
                RegGetValueW(
                    **self.interface_key,
                    PCWSTR::from_raw(key_name.as_ptr()),
                    PCWSTR::null(),
                    RRF_RT_REG_SZ,
                    None,
                    Some(value_buf.as_mut_ptr() as *mut core::ffi::c_void),
                    Some(&mut value_len),
                )
            };
        }
        if result == ERROR_FILE_NOT_FOUND {
            // No value (interface name) for this key:
            return Some(Ok((iid, None)));
        }
        if let Err(e) = result.ok() {
            return Some(Err(eyre::eyre!(e)).context(format!(
                "Failed to read value for subkey of registry key \
                    HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Interface\\{key_str}",
            )));
        }
        let value_len = value_len as usize / core::mem::size_of::<u16>() - 1;

        let value = String::from_utf16_lossy(&value_buf[..value_len]);

        Some(Ok((iid, Some(value))))
    }
}

/// The code ID for a Windows PE file.
///
/// When combined with the binary name, the `PeCodeId` lets you obtain binaries from
/// symbol servers. It is not useful on its own, it has to be paired with the binary name.
///
/// A Windows binary's `PeCodeId` is distinct from its debug ID (= pdb GUID + age).
/// If you have a binary file, you can get both the `PeCodeId` and the debug ID
/// from it. If you only have a PDB file, you usually *cannot* get the `PeCodeId` of
/// the corresponding binary from it.
///
/// Note: copied from the [`wholesym`] crate.
///
/// [`wholesym`]: https://docs.rs/samply-symbols/0.23.0/src/samply_symbols/shared.rs.html#227
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeCodeId {
    pub timestamp: u32,
    pub image_size: u32,
}
impl PeCodeId {
    /// Code from `make_library_info` function in "samply-symbols-0.23.0\src\binary_image.rs".
    pub fn for_file_data(data: &[u8]) -> eyre::Result<Self> {
        if let Ok(file) = PeFile64::parse(data) {
            Self::from_pe_file(file)
        } else {
            Self::from_pe_file(PeFile32::parse(data)?)
        }
    }
    /// Code from pe_info function in "samply-symbols-0.23.0\src\binary_image.rs"
    fn from_pe_file<'buf, Pe: ImageNtHeaders>(
        pe: object::read::pe::PeFile<'buf, Pe, &'buf [u8]>,
    ) -> eyre::Result<Self> {
        // The code identifier consists of the `time_date_stamp` field id the COFF header, followed by
        // the `size_of_image` field in the optional header. If the optional PE header is not present,
        // this identifier is `None`.
        let header = pe.nt_headers();
        let timestamp = header
            .file_header()
            .time_date_stamp
            .get(object::LittleEndian);
        let image_size = header.optional_header().size_of_image();
        Ok(PeCodeId {
            timestamp,
            image_size,
        })
    }
}
impl FromStr for PeCodeId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 9 || s.len() > 16 {
            return Err("invalid length");
        }
        let timestamp = u32::from_str_radix(&s[..8], 16).map_err(|_| "invalid timestamp")?;
        let image_size = u32::from_str_radix(&s[8..], 16).map_err(|_| "invalid image size")?;
        Ok(Self {
            timestamp,
            image_size,
        })
    }
}
impl std::fmt::Display for PeCodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:08X}{:x}", self.timestamp, self.image_size))
    }
}

/// The Portable Executable (PE) format is a file format for executables, object
/// code, DLLs.
pub struct PeFile {
    /// Path where the dll file can be found.
    dll_path: PathBuf,
    /// Path where debug info can be found.
    pdb_path: Option<PathBuf>,
}
impl PeFile {
    pub fn new(dll_path: impl Into<PathBuf>) -> Self {
        Self {
            dll_path: dll_path.into(),
            pdb_path: None,
        }
    }
    /// Dll file name without file extension.
    pub fn file_stem(&self) -> eyre::Result<&str> {
        self.dll_path
            .file_stem()
            .ok_or_eyre("dll paths have file names")?
            .to_str()
            .ok_or_eyre("dll files have UTF8 file names")
    }
    /// Get a debug id that can be used to download a `.pdb` file. Use the
    /// [`DebugId::breakpad`] method and then [`ToString::to_string`] that.
    pub fn debug_id(&self) -> eyre::Result<DebugId> {
        let data = std::fs::read(&self.dll_path)
            .with_context(|| format!("Failed to read {}", self.dll_path.display()))?;

        let object = object::File::parse(data.as_slice())?;

        if let Ok(Some(pdb_info)) = object.pdb_info() {
            // Copied code from "samply-symbols-0.23.0\src\debugid_util.rs"
            Ok(DebugId::from_guid_age(&pdb_info.guid(), pdb_info.age())?)
        } else {
            Err(eyre::eyre!("No debug info available for object"))
        }
    }
    /// This id can be used to download the `.dll` file.
    pub fn pe_code_id(&self) -> eyre::Result<PeCodeId> {
        PeCodeId::for_file_data(self.read_dll()?.as_slice())
    }
    /// Ensures `dll_path` points to a DLL with the specified code id. If the
    /// current DLL doesn't match the id then a new DLL will be downloaded.
    ///
    /// Returns `true` if a new DLL had to be downloaded.
    pub async fn maybe_download_dll(
        &mut self,
        downloader: &SymsrvDownloader,
        wanted_pe_code_id: PeCodeId,
    ) -> eyre::Result<bool> {
        if self.pe_code_id()? == wanted_pe_code_id {
            return Ok(false);
        }
        let dll_name = self
            .dll_path
            .file_name()
            .ok_or_eyre("dll paths have file names")?
            .to_str()
            .ok_or_eyre("dll files have UTF8 file names")?;
        assert!(dll_name.to_ascii_lowercase().ends_with(".dll"));

        // Get hash:
        let hash = self.pe_code_id()?.to_string();

        // Download and cache a DLL file.
        let local_path = downloader.get_file(dll_name, &hash).await?;

        // At this point we don't want to use the DLL inside
        // C:/Windows/System32, instead we want to use the newly downloaded DLL
        // next to the executable:
        self.dll_path = local_path;

        Ok(true)
    }
    /// Download and cache `.pdb` debug symbol file.
    pub async fn download_pdb(&mut self, downloader: &SymsrvDownloader) -> eyre::Result<()> {
        let pdb_name = self.dll_path.with_extension("pdb");
        let pdb_name = pdb_name
            .file_name()
            .ok_or_eyre("dll paths have file names")?
            .to_str()
            .ok_or_eyre("dll files have UTF8 file names")?;
        assert!(pdb_name.to_ascii_lowercase().ends_with(".pdb"));

        // Get hash:
        let hash = self.debug_id()?.breakpad().to_string();

        // Download and cache a PDB file.
        let local_path = downloader.get_file(pdb_name, &hash).await?;
        self.pdb_path = Some(local_path);
        Ok(())
    }
    pub fn open_pdb(&self) -> eyre::Result<PDB<'static, File>> {
        let file = std::fs::File::open(
            self.pdb_path
                .as_deref()
                .ok_or_eyre("Haven't downloaded pdb file yet")?,
        )?;
        Ok(pdb::PDB::open(file)?)
    }
    pub fn read_dll(&self) -> eyre::Result<Vec<u8>> {
        std::fs::read(&self.dll_path)
            .with_context(|| format!("Failed to read DLL file at: {}", self.dll_path.display()))
    }
}

fn setup_download_next_to_exe() -> SymsrvDownloader {
    // Parse the _NT_SYMBOL_PATH environment variable.
    let symbol_path_env = symsrv::get_symbol_path_from_environment();
    let symbol_path = symbol_path_env
        .as_deref()
        .unwrap_or("srv**https://msdl.microsoft.com/download/symbols");
    let parsed_symbol_path = symsrv::parse_nt_symbol_path(symbol_path);

    // Create a downloader which follows the _NT_SYMBOL_PATH recipe.
    let mut downloader = SymsrvDownloader::new(parsed_symbol_path);
    downloader.set_default_downstream_store(
        // Download files next to the executable:
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|exe_dir| exe_dir.join("Symbols")))
            .or_else(symsrv::get_home_sym_dir),
    );
    downloader
}

#[derive(Debug, Default, Clone, Copy)]
struct AddressInfo {
    size: u32,
    rva: Rva,
}

type SymbolWithSize<'sym> = (Option<AddressInfo>, pdb::Symbol<'sym>);

/// Inspired by [`symbolic_debuginfo::SymbolMap::from_iter`], assumes that a
/// symbol occupies all space until the next symbol.
fn calculate_size_for_symbols(
    symbols: &mut [SymbolWithSize<'_>],
    address_map: &pdb::AddressMap<'_>,
) {
    let mut symbols = symbols
        .iter_mut()
        .filter_map(|(size, sym)| match sym.parse().ok()? {
            pdb::SymbolData::Public(public_symbol) => public_symbol
                .offset
                .to_rva(address_map)
                .map(|rva| (size, rva)),
            pdb::SymbolData::ProcedureReference(_proc_ref) => {
                // Ignore for now
                None
            }
            unexpected => todo!("didn't expect this kod of symbol: {unexpected:?}"),
        })
        .collect::<Vec<_>>();
    symbols.sort_by_key(|(_, start)| start.0);

    // symbols.dedup_by_key(|(_, start)| start.0); // We could do this but then some symbols won't get a size...

    for ix in 1..symbols.len() {
        let start = symbols[ix - 1].1;
        // There might be multiple "symbols" at the same offset, find the next one:
        let Some((_, end)) = symbols[ix..].iter().find(|(_, end)| *end != start) else {
            break;
        };
        let size = end
            .checked_sub(start)
            .expect("Since symbols are sorted the later once should have larger offsets");
        *symbols[ix - 1].0 = Some(AddressInfo { size, rva: start });
    }
}

struct DllRelated {
    symbols: pdb::SymbolTable<'static>,
    address_map: pdb::AddressMap<'static>,
    /// All data from the DLL file.
    dll_data: Vec<u8>,
}
impl DllRelated {
    /// Collect data about dll.
    fn collect(dll_info: &PeFile) -> eyre::Result<Self> {
        let mut pdb = dll_info.open_pdb()?;

        if !pdb.type_information()?.is_empty() {
            eprintln!(
                "Info: Type info isn't empty for {} as was expected, perhaps it could be useful",
                dll_info.file_stem()?
            );
        }
        if !pdb.frame_table()?.is_empty() {
            eprintln!(
                "Info: Frame table isn't empty for {} as was expected, perhaps it could be useful",
                dll_info.file_stem()?
            );
        }
        if !pdb.id_information()?.is_empty() {
            eprintln!(
                "Info: Id information isn't empty for {} as was expected, perhaps it could be useful",
                dll_info.file_stem()?
            );
        }

        let symbols = pdb.global_symbols()?;
        let address_map = pdb.address_map()?;

        let dll_data = dll_info.read_dll()?;

        Ok(Self {
            symbols,
            address_map,
            dll_data,
        })
    }
    /// Symbol together with its estimated size (from the
    /// [`calculate_size_for_symbols`]).
    fn estimate_symbol_sizes(&self) -> eyre::Result<DllRelatedSymbols<'_>> {
        let mut all_symbols = self
            .symbols
            .iter()
            .map(|sym| Ok((None, sym)))
            .collect::<Vec<_>>()?;
        calculate_size_for_symbols(all_symbols.as_mut_slice(), &self.address_map);
        Ok(DllRelatedSymbols {
            info: self,
            symbols: all_symbols,
        })
    }
}

pub struct DllRelatedSymbols<'a> {
    info: &'a DllRelated,
    symbols: Vec<SymbolWithSize<'a>>,
}
impl<'a> DllRelatedSymbols<'a> {
    fn interface_ids(&self) -> eyre::Result<Vec<IidInfo<'a>>> {
        let mut all_iid = Vec::new();

        for (size, symbol) in &self.symbols {
            let Ok(pdb::SymbolData::Public(data)) = symbol.parse() else {
                continue;
            };
            if !data.name.as_bytes().starts_with(b"IID_") {
                // Note an interface id.
                continue;
            }
            if size.unwrap_or_default().size < 16 {
                eyre::bail!(
                    "Expected symbol with IID to have a size that is 16 or larger but it was {}",
                    size.unwrap_or_default().size
                );
            }
            let Some(rva) = size
                // Used cached rva if possible:
                .map(|info| info.rva)
                // Otherwise compute it:
                .or_else(|| data.offset.to_rva(&self.info.address_map))
            else {
                continue;
            };
            let iid: &[u8] = &self.info.dll_data[rva.0 as usize..][..16];
            let iid = uuid::Uuid::from_slice_le(iid).context("Failed to parse IID as GUID")?;

            all_iid.push(IidInfo {
                iid,
                name: data.name.to_string(),
            });
            println!("{iid:X} for {}", data.name);
        }

        // We might keep the vector around for a while, so try to minimize memory usage:
        all_iid.shrink_to_fit();

        Ok(all_iid)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct IidInfo<'a> {
    iid: uuid::Uuid,
    name: Cow<'a, str>,
}
impl<'a> IidInfo<'a> {
    pub fn into_owned(self) -> IidInfo<'static> {
        IidInfo {
            iid: self.iid,
            name: Cow::Owned(self.name.into_owned()),
        }
    }
}
impl fmt::Display for IidInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { iid, name, .. } = self;
        write!(f, "{iid:X} for {name}")
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let Args {
        unfiltered,
        twinui_dll_id,
        actxprxy_dll_id,
        skip_twinui,
        skip_actxprxy,
        skip_windows_version,
        skip_windows_registry,
    } = Args::parse();

    if twinui_dll_id.is_none() && actxprxy_dll_id.is_none() {
        println!("\nAnalyzing COM interfaces for local Windows installation.\n");
        if !skip_windows_version {
            println!("Windows Version: {}\n\n", WindowsVersion::get()?);
        }

        if !skip_windows_registry {
            println!(
                r"Interface ids (IID) from Registry key HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface"
            );
            println!();
            let reg_iids = RegistryIIDs::open()?;
            for res in reg_iids {
                let (iid, name) = res?;
                let Some(name) = name else { continue };
                if unfiltered
                    || name.contains("VirtualDesktop")
                    || (name.contains("ApplicationView") && !name.contains("CViewManagement"))
                {
                    println!("{iid} for {name}");
                }
            }
            println!("\n");
        }
    } else {
        println!("\nAnalyzing COM interfaces for specific DLL files using PE code ids.\n")
    }

    let downloader = setup_download_next_to_exe();

    let mut twinui = PeFile::new(twinui_pcshell_path()?);
    let mut actxprxy = PeFile::new(actxprxy_path()?);
    let mut pe_files = [
        (&mut twinui, twinui_dll_id, skip_twinui),
        (&mut actxprxy, actxprxy_dll_id, skip_actxprxy),
    ];

    println!("DLL and PDB information:");
    eprintln!(
        "\nFetching PDB (and DLLs if PE code ids were specified) from Microsoft Symbol Server"
    );
    for (pe_file, dll_id, skip) in &mut pe_files {
        eprintln!();
        if *skip {
            eprintln!("Ignoring information from: {}", pe_file.file_stem()?);
            continue;
        }

        if let Some(dll_id) = dll_id {
            let did_download = pe_file
                .maybe_download_dll(&downloader, *dll_id)
                .await
                .with_context(|| {
                    format!(
                        "Failed to download DLL for {}",
                        pe_file.file_stem().unwrap()
                    )
                })?;
            if did_download {
                eprintln!(
                    "PeCodeId for {}.dll differed from the dll in local Windows installation, \
                    so it was downloaded from a Microsoft Symbol Server",
                    pe_file.file_stem()?
                );
            } else {
                eprintln!(
                    "PeCodeId for {}.dll matched with the dll in local Windows installation, \
                    so nothing was downloaded",
                    pe_file.file_stem()?
                );
            }
        }
        eprintln!("Using dll file at: {}", pe_file.dll_path.display());

        pe_file.download_pdb(&downloader).await?;
        eprintln!(
            "Using pdb debug file at: {}",
            pe_file.pdb_path.as_ref().unwrap().display()
        );

        println!(
            "\n{}.dll with PeCodeId: {}",
            pe_file.file_stem()?,
            pe_file.pe_code_id()?
        );
        println!(
            "{}.pdb with breakpad id: {}",
            pe_file.file_stem()?,
            pe_file.debug_id()?.breakpad()
        );
    }

    println!("\n\nInterface ids (IID) read from the DLL files using PDB debug info:\n");

    // actxprxy related:
    let actxprxy_info = (!skip_actxprxy)
        .then(|| DllRelated::collect(&actxprxy))
        .transpose()?;
    let actxprxy_symbols = actxprxy_info
        .as_ref()
        .map(|info| info.estimate_symbol_sizes())
        .transpose()?;

    // twinui related:
    let twinui_info = (!skip_twinui)
        .then(|| DllRelated::collect(&twinui))
        .transpose()?;
    let twinui_symbols = twinui_info
        .as_ref()
        .map(|info| info.estimate_symbol_sizes())
        .transpose()?;

    // Search both dll files even though we are likely only interested in IID from actxprxy.dll:
    let all_symbols = [&actxprxy_symbols, &twinui_symbols]
        .into_iter()
        .filter_map(|sym| sym.as_ref());
    let mut all_iid = Vec::<IidInfo<'_>>::new();
    for symbols in all_symbols {
        for iid in symbols.interface_ids()? {
            if !unfiltered
                && !iid.name.contains("VirtualDesktop")
                // Note: IApplicationView iid is not in any of the dlls we are currently searching
                && !iid.name.contains("IApplicationView")
            {
                // Likely not an interface id we are interested in.
                continue;
            }
            all_iid.push(iid);
        }
    }
    all_iid.sort_by(|a, b| a.name.cmp(&b.name));
    all_iid.iter().for_each(|iid| println!("{iid}"));
    println!();

    let (Some(twinui_info), Some(twinui_all_symbols)) = (&twinui_info, twinui_symbols) else {
        eprintln!("\nSkipping virtual function tables because of --skip-twinui flag\n");
        return Ok(());
    };

    println!("\n\n\nVirtual function tables (vftable) for COM interfaces read from the DLL files using PDB debug info:");

    let mut symbol_lookup = HashMap::new();
    for (info, sym) in &twinui_all_symbols.symbols {
        let Some(info) = info else { continue };
        symbol_lookup.insert(info.rva, (info, sym));
    }

    let twinui_image_base =
        object::File::parse(twinui_info.dll_data.as_slice())?.relative_address_base();

    for (size, symbol) in &twinui_all_symbols.symbols {
        // Will be either SymbolData::ProcedureReference or
        // SymbolData::Public

        let Ok(pdb::SymbolData::Public(data)) = symbol.parse() else {
            continue;
        };
        let rva = data
            .offset
            .to_rva(&twinui_info.address_map)
            .unwrap_or_default();
        let name = data.name.to_string();

        // These filtering rules were ported from the Python script:
        if !(unfiltered
            || (VIRTUAL_DESKTOP_V_TABLE_NAMES
                .iter()
                .any(|part| name.contains(part))
                || (name.contains("_7CWin32ApplicationView")
                    && name.contains("IApplicationView")
                    && !name.contains("Microsoft")
                    && !name.contains("IApplicationViewBase"))))
        {
            // This symbol likely isn't relevant.
            continue;
        }

        let name_info = symbolic_common::Name::new(
            data.name.to_string(),
            symbolic_common::NameMangling::Unknown,
            symbolic_common::Language::Unknown,
        );
        let _lang = name_info.detect_language();
        let demangled = name_info.demangle(symbolic_demangle::DemangleOptions::complete());

        if !matches!(&demangled, Some(demangled) if demangled.contains("vftable")) {
            // Not a vtable definition!
            continue;
        }
        if let Some(demangled) = &demangled {
            println!("\n\nDumping vftable: {} ({})", demangled, data.name);
        } else {
            println!("\n\nDumping vftable: ({})", data.name);
        }
        if let Some(size) = size {
            println!("\tVftable estimated size: {} bytes", size.size);
        }

        let vft_data =
            &twinui_info.dll_data[rva.0 as usize..][..size.unwrap_or_default().size as usize];
        let vft_ptrs = vft_data
            .chunks_exact(8)
            .map(|bytes| {
                u64::from_le_bytes(bytes.try_into().expect("slices should be 8 bytes long"))
            })
            .map(|ptr| ptr.saturating_sub(twinui_image_base));
        for (method_index, method_ptr) in vft_ptrs.enumerate() {
            let Ok(method_ptr) = u32::try_from(method_ptr) else {
                eprintln!(
                    "Warning: a method address in the DLL didn't fit in 32bit and was ignored"
                );
                println!("\tMethod {method_index:02}: Unknown ({:x})", method_ptr);
                continue;
            };
            let method_ptr = Rva(method_ptr);

            let Some((_info, sym)) = symbol_lookup.get(&method_ptr) else {
                println!("\tMethod {method_index:02}: Unknown ({:x})", method_ptr.0);
                continue;
            };

            let Ok(pdb::SymbolData::Public(sym)) = sym.parse() else {
                unreachable!("previously parsed symbol when gathering address info");
            };

            let name_info = symbolic_common::Name::new(
                sym.name.to_string(),
                symbolic_common::NameMangling::Unknown,
                symbolic_common::Language::Unknown,
            );
            let _lang = name_info.detect_language();
            let demangled = name_info.demangle(symbolic_demangle::DemangleOptions::complete());

            println!(
                "\tMethod {method_index:02}: {} ({})",
                demangled.unwrap_or_default(),
                sym.name
            )
        }
    }
    eprintln!();

    Ok(())
}

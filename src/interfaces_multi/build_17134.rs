//! Windows 10 Version 1803 (April 2018 Update)
//!
//! From [Wikipedia](https://en.wikipedia.org/wiki/Windows_10,_version_1803):
//! > Windows 10 April 2018 Update (also known as version 1803 and codenamed
//! > "Redstone 4") is the fifth major update to Windows 10 and the fourth in a
//! > series of updates under the Redstone codenames. It carries the build
//! > number 10.0.17134.

use super::*;
use build_10240 as prev_build;

prev_build::IApplicationView!("871F602A-2B58-42B4-8C4B-6C43D642C06F");
prev_build::IApplicationViewCollection!("2C08ADF0-A386-4B35-9250-0FE183476FCC");
prev_build::IVirtualDesktop!("FF72FFDD-BE7E-43FC-9C03-AD81681E88E4");
prev_build::IVirtualDesktopManagerInternal!("F31574D6-B682-4CDC-BD56-1827860ABEC6");
prev_build::IVirtualDesktopNotification!("C179334C-4295-40D3-BEA1-C654D965605A");
prev_build::IVirtualDesktopNotificationService!("0CD45E71-D927-4F15-8B0A-8FEF525337BF");
prev_build::IVirtualDesktopPinnedApps!("4CE81583-1E4C-4632-A621-07A53543148F");

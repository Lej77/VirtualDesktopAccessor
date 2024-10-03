//! Windows 10 Version 1709 (Fall Creators Update)
//!
//! From [Wikipedia](https://en.wikipedia.org/wiki/Windows_10,_version_1709):
//! > Windows 10 Fall Creators Update (also known as version 1709 and codenamed
//! > "Redstone 3") is the fourth major update to Windows 10 and the third in a
//! > series of updates under the Redstone codenames. It carries the build
//! > number 10.0.16299.

use super::*;
use build_10240 as prev_build;

prev_build::IApplicationView!("9AC0B5C8-1484-4C5B-9533-4134A0F97CEA");
prev_build::IApplicationViewCollection!("2C08ADF0-A386-4B35-9250-0FE183476FCC");
prev_build::IVirtualDesktop!("FF72FFDD-BE7E-43FC-9C03-AD81681E88E4");
prev_build::IVirtualDesktopManagerInternal!("F31574D6-B682-4CDC-BD56-1827860ABEC6");
prev_build::IVirtualDesktopNotification!("C179334C-4295-40D3-BEA1-C654D965605A");
prev_build::IVirtualDesktopNotificationService!("0CD45E71-D927-4F15-8B0A-8FEF525337BF");
prev_build::IVirtualDesktopPinnedApps!("4CE81583-1E4C-4632-A621-07A53543148F");

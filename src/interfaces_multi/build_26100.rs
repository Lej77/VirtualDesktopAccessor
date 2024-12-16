//! Windows 11, version 24H2
//!
//! From [Wikipedia](https://en.wikipedia.org/wiki/Windows_11,_version_24H2):
//!
//! > The Windows 11 2024 Update (also known as version 24H2) is the third and
//! > current major update to Windows 11. It carries the build number
//! > 10.0.26100.
//!
//! # Interface definitions
//!
//! Updated interface definitions were found at
//! [MScholtes/VirtualDesktop/VirtualDesktop11-24H2.cs](https://github.com/MScholtes/VirtualDesktop/blob/c601d38796e947d7647c9124a5087fb4b595cbd9/VirtualDesktop11-24H2.cs).
//!
//! All the interface ids seem to have remained the same as in the previous
//! version but a `switch_desktop_and_move_foreground_view` method were added to
//! the `IVirtualDesktopManagerInternal` interface.
//!
//! `winvd` was updated to support this Windows release with [commit
//! `873cd38729d9c6e881e5ab5f1d04de6f035421d9`](https://github.com/Ciantic/VirtualDesktopAccessor/commit/873cd38729d9c6e881e5ab5f1d04de6f035421d9).

use super::*;
use build_22631_3155 as build_prev;

// These interfaces haven't changed since the previous version:
build_prev::IApplicationView!("372E1D3B-38D3-42E4-A15B-8AB2B178F513"); // Same IID
build_prev::IApplicationViewCollection!("1841C6D7-4F9D-42C0-AF41-8747538F10E5"); // Same IID
build_prev::IVirtualDesktop!("3F07F4BE-B107-441A-AF0F-39D82529072C"); // Same IID
build_prev::IVirtualDesktopNotification!("B9E5E94D-233E-49AB-AF5C-2B4541C3AADE"); // Not used by MScholtes/VirtualDesktop, so don't know if had changes.
build_prev::IVirtualDesktopNotificationService!("0cd45e71-d927-4f15-8b0a-8fef525337bf"); // Not used by MScholtes/VirtualDesktop, so don't know if had changes.
build_prev::IVirtualDesktopPinnedApps!("4CE81583-1E4C-4632-A621-07A53543148F"); // Same IID

// But these interfaces have different methods:

reusable_com_interface!(
    MacroOptions {
        temp_macro_name: _IVirtualDesktopManagerInternal,
        iid: "53F5CA0B-158F-4124-900C-057158060B27", // Same as previous version
    },
    {
        pub unsafe trait IVirtualDesktopManagerInternal: IUnknown {
            pub unsafe fn get_desktop_count(&self, out_count: *mut UINT) -> HRESULT;

            pub unsafe fn move_view_to_desktop(
                &self,
                view: ComIn<IApplicationView>,
                desktop: ComIn<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn can_move_view_between_desktops(
                &self,
                view: ComIn<IApplicationView>,
                can_move: *mut i32,
            ) -> HRESULT;

            pub unsafe fn get_current_desktop(
                &self,
                out_desktop: *mut Option<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn get_desktops(&self, out_desktops: *mut Option<IObjectArray>) -> HRESULT;

            /// Get next or previous desktop
            ///
            /// Direction values:
            /// 3 = Left direction
            /// 4 = Right direction
            pub unsafe fn get_adjacent_desktop(
                &self,
                in_desktop: ComIn<IVirtualDesktop>,
                direction: UINT,
                out_pp_desktop: *mut Option<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn switch_desktop(&self, desktop: ComIn<IVirtualDesktop>) -> HRESULT;

            // This method is new for build 26100:
            pub unsafe fn switch_desktop_and_move_foreground_view(
                &self,
                desktop: ComIn<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn create_desktop(
                &self,
                out_desktop: *mut Option<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn move_desktop(
                &self,
                in_desktop: ComIn<IVirtualDesktop>,
                index: UINT,
            ) -> HRESULT;

            pub unsafe fn remove_desktop(
                &self,
                destroy_desktop: ComIn<IVirtualDesktop>,
                fallback_desktop: ComIn<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn find_desktop(
                &self,
                guid: *const GUID,
                out_desktop: *mut Option<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn get_desktop_switch_include_exclude_views(
                &self,
                desktop: ComIn<IVirtualDesktop>,
                out_pp_desktops1: *mut IObjectArray,
                out_pp_desktops2: *mut IObjectArray,
            ) -> HRESULT;

            pub unsafe fn set_name(
                &self,
                desktop: ComIn<IVirtualDesktop>,
                name: HSTRING,
            ) -> HRESULT;
            pub unsafe fn set_wallpaper(
                &self,
                desktop: ComIn<IVirtualDesktop>,
                name: HSTRING,
            ) -> HRESULT;
            pub unsafe fn update_wallpaper_for_all(&self, name: HSTRING) -> HRESULT;

            pub unsafe fn copy_desktop_state(
                &self,
                view0: ComIn<IApplicationView>,
                view1: ComIn<IApplicationView>,
            ) -> HRESULT;

            pub unsafe fn create_remote_desktop(
                &self,
                name: HSTRING,
                out_desktop: *mut Option<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn switch_remote_desktop(&self, desktop: ComIn<IVirtualDesktop>) -> HRESULT;

            pub unsafe fn switch_desktop_with_animation(
                &self,
                desktop: ComIn<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn get_last_active_desktop(
                &self,
                out_desktop: *mut Option<IVirtualDesktop>,
            ) -> HRESULT;

            pub unsafe fn wait_for_animation_to_complete(&self) -> HRESULT;
        }
    }
);

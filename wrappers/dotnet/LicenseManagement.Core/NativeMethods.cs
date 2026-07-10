using System;
using System.Runtime.InteropServices;

namespace LicenseManagement.Core
{
    /// <summary>Raw P/Invoke surface over hymmalm's flat FFI (hlm_ffi.h).</summary>
    internal static class NativeMethods
    {
        private const string Lib = "hymmalm";

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_create(
            [MarshalAs(UnmanagedType.LPStr)] string? baseUrl,
            [MarshalAs(UnmanagedType.LPStr)] string productId,
            [MarshalAs(UnmanagedType.LPStr)] string clientApiKey,
            [MarshalAs(UnmanagedType.LPStr)] string jwksJson,
            int format,
            uint validDays,
            [MarshalAs(UnmanagedType.LPStr)] string? machineId,
            [MarshalAs(UnmanagedType.LPStr)] string? machineName,
            [MarshalAs(UnmanagedType.LPStr)] string? licensePath);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void hlm_ffi_destroy(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_check(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_activate(IntPtr client,
            [MarshalAs(UnmanagedType.LPStr)] string receiptCode);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_deactivate(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_refresh(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_status(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_status_name(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_license_id(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_product_name(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_buyer_email(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long hlm_ffi_expires(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long hlm_ffi_trial_end(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long hlm_ffi_receipt_expires(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_live_mode(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_metadata(IntPtr client,
            [MarshalAs(UnmanagedType.LPStr)] string key);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_last_http_status(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_err_name(int err);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_machine_id(
            [Out] byte[] buffer, int capacity);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_machine_name(
            [Out] byte[] buffer, int capacity);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_verify(
            [MarshalAs(UnmanagedType.LPStr)] string jws,
            [MarshalAs(UnmanagedType.LPStr)] string jwksJson,
            [MarshalAs(UnmanagedType.LPStr)] string? expectedProductId,
            [MarshalAs(UnmanagedType.LPStr)] string? expectedMachineId,
            long now,
            out int status);

        internal static string Str(IntPtr p) =>
            p == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAnsi(p) ?? string.Empty;
    }
}

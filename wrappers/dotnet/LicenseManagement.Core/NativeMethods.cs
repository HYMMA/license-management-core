using System;
using System.Runtime.InteropServices;

namespace LicenseManagement.Core
{
    /// <summary>Raw P/Invoke surface over hymmalm's flat FFI (hlm_ffi.h).</summary>
    internal static class NativeMethods
    {
        private const string Lib = "hymmalm";

        // UnmanagedType.LPUTF8Str (48) is missing from the netstandard2.0
        // reference assembly, but every supported runtime (.NET Framework
        // 4.7+, .NET, Mono) implements the marshaller. The C ABI is UTF-8.
        private const UnmanagedType LPUTF8Str = (UnmanagedType)48;

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_create(
            [MarshalAs(LPUTF8Str)] string? baseUrl,
            [MarshalAs(LPUTF8Str)] string productId,
            [MarshalAs(LPUTF8Str)] string clientApiKey,
            [MarshalAs(LPUTF8Str)] string jwksJson,
            int format,
            uint validDays,
            [MarshalAs(LPUTF8Str)] string? machineId,
            [MarshalAs(LPUTF8Str)] string? machineName,
            [MarshalAs(LPUTF8Str)] string? licensePath);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void hlm_ffi_destroy(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_check(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_activate(IntPtr client,
            [MarshalAs(LPUTF8Str)] string receiptCode);

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
            [MarshalAs(LPUTF8Str)] string key);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hlm_ffi_last_http_status(IntPtr client);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hlm_ffi_last_error_detail(IntPtr client);

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
            [MarshalAs(LPUTF8Str)] string jws,
            [MarshalAs(LPUTF8Str)] string jwksJson,
            [MarshalAs(LPUTF8Str)] string? expectedProductId,
            [MarshalAs(LPUTF8Str)] string? expectedMachineId,
            long now,
            out int status);

        // The C ABI is UTF-8; PtrToStringAnsi would mojibake every non-ASCII
        // product name / buyer email / error detail. (netstandard2.0 has no
        // Marshal.PtrToStringUTF8, so read the bytes manually.)
        internal static string Str(IntPtr p)
        {
            if (p == IntPtr.Zero) return string.Empty;
            int len = 0;
            while (Marshal.ReadByte(p, len) != 0) len++;
            if (len == 0) return string.Empty;
            var bytes = new byte[len];
            Marshal.Copy(p, bytes, 0, len);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
    }
}

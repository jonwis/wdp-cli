using System.Security.Cryptography;
using System.Text;
using Windows.Win32;
using Windows.Win32.Security.Cryptography;
using Windows.Security.Cryptography.DataProtection;
using System.Runtime.InteropServices;
using System.Formats.Asn1;
using System.Runtime.InteropServices.WindowsRuntime;

public enum Action {
    Lock,
    Unlock,
}

public class Program
{
    static byte[] _cleartext = Encoding.UTF8.GetBytes("kittens and muffins");

    static unsafe byte[] Win32ProtectData(byte[] cleartext)
    {
        fixed(byte* cleartextRaw = cleartext)
        {
            CRYPTOAPI_BLOB blobIn;
            blobIn.pbData = cleartextRaw;
            blobIn.cbData = (uint)cleartext.Length;
            if (!PInvoke.CryptProtectData(blobIn, null, null, null, null, 0, out var blobOut))
            {
                throw new System.Exception($"Oops: {Marshal.GetLastPInvokeError()}");
            }

            var output = new byte[blobOut.cbData];
            Marshal.Copy(new IntPtr(blobOut.pbData), output, 0, (int)blobOut.cbData);
            return output;
        }
    }

    static unsafe byte[] Win32UnprotectData(byte[] ciphertext)
    {
        fixed (byte* ciphertextRaw = ciphertext)
        {
            CRYPTOAPI_BLOB blobIn;
            blobIn.pbData = ciphertextRaw;
            blobIn.cbData = (uint)ciphertext.Length;
            if (!PInvoke.CryptUnprotectData(blobIn, null, null, null, null, 0, out var blobOut))
            {
                throw new System.Exception($"Oops: {Marshal.GetLastPInvokeError()}");
            }

            var output = new byte[blobOut.cbData];
            Marshal.Copy(new IntPtr(blobOut.pbData), output, 0, (int)blobOut.cbData);
            return output;
        }
    }

    static void CompareAndPrintArrays(string title, byte[] left, byte[] right)
    {
        Console.WriteLine(title);
        if (left.Length != right.Length)
        {
            Console.WriteLine("<> Buffers are different lengths");
            return;
        }

        for (int i = 0; i < left.Length; ++i)
        {
            if (left[i] != right[i])
            {
                Console.WriteLine("<> Index {0,8:X} - {1,8:x} : {2,8:x}", i, left[i], right[i]);
            }
        }
    }

    public static void Main()
    {
        DataProtectionProvider winrt_provider = new DataProtectionProvider("LOCAL=user");

        // Encrypt some things

        var dotnet_protected = ProtectedData.Protect(_cleartext, null, DataProtectionScope.CurrentUser);
        var win32_protected = Win32ProtectData(_cleartext);
        var winrt_protected = winrt_provider.ProtectAsync(_cleartext.AsBuffer()).AsTask().Result.ToArray();
        CompareAndPrintArrays(".NET vs Win32 ciphertext", dotnet_protected, win32_protected);
        CompareAndPrintArrays(".NET vs WinRT ciphertext", dotnet_protected, winrt_protected);
        CompareAndPrintArrays("Win32 vs WinRT ciphertext", win32_protected, winrt_protected);

        // Baseline self-decryption
        CompareAndPrintArrays(".NET decrypted", ProtectedData.Unprotect(dotnet_protected, null, DataProtectionScope.CurrentUser), _cleartext);
        CompareAndPrintArrays("Win32 decrypted", Win32UnprotectData(win32_protected), _cleartext);
        CompareAndPrintArrays("WinRT decrypted", winrt_provider.UnprotectAsync(winrt_protected.AsBuffer()).AsTask().Result.ToArray(), _cleartext);

        // Cross-decryption
        CompareAndPrintArrays(".NET unprotected by Win32", Win32UnprotectData(dotnet_protected), _cleartext);
        CompareAndPrintArrays(".NET unprotected by WinRT", winrt_provider.UnprotectAsync(dotnet_protected.AsBuffer()).AsTask().Result.ToArray(), _cleartext);
        CompareAndPrintArrays("Win32 unprotected by .NET", ProtectedData.Unprotect(win32_protected, null, DataProtectionScope.CurrentUser), _cleartext);
        CompareAndPrintArrays("Win32 unprotected by WinRT", winrt_provider.UnprotectAsync(win32_protected.AsBuffer()).AsTask().Result.ToArray(), _cleartext);
        CompareAndPrintArrays("WinRT unprotected by Win32", Win32UnprotectData(winrt_protected), _cleartext);
        CompareAndPrintArrays("WinRT unprotected by .NET", ProtectedData.Unprotect(winrt_protected, null, DataProtectionScope.CurrentUser), _cleartext);
    }
}

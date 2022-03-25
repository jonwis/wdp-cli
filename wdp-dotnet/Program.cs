using System.Security.Cryptography;

public enum Action {
    Lock,
    Unlock,
}

public class Program {
    /// <param name="file">The file to operate on</param>
    /// <param name="action">The action to take</param>
    public static void Main(FileInfo file, Action action) {
        if (!file.Exists) {
            Console.Error.WriteLine($"{file} does not exist!");
            Environment.Exit(1);
        }

        if (action == Action.Lock)
        {
            var output_file = $"{file.FullName}.locked";
            var bytes = File.ReadAllBytes(file.FullName);
            var data = ProtectedData.Protect(bytes, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
            File.WriteAllBytes(output_file, data);
            Console.WriteLine($"Locked as {output_file}");
        }
        else if (action == Action.Unlock)
        {
            var output_file = $"{file.FullName}.unlocked";
            var bytes = File.ReadAllBytes(file.FullName);
            bytes = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(output_file, bytes);
            Console.WriteLine($"Unlocked as {output_file}");
        }
    }
}
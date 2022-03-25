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
            var output_file = $"{file.FullName}.dotnet.locked";
            var bytes = File.ReadAllBytes(file.FullName);
            
            Console.WriteLine("Unprotected bytes:");
            Console.WriteLine($"[{BitConverter.ToString(bytes).Replace("-", ", ")}]");

            var protected_data = ProtectedData.Protect(bytes, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);

            Console.WriteLine("Protected bytes:");
            Console.WriteLine($"[{BitConverter.ToString(protected_data).Replace("-", ", ")}]");

            File.WriteAllBytes(output_file, protected_data);
            Console.WriteLine($"Locked as {output_file}");
        }
        else if (action == Action.Unlock)
        {
            var output_file = $"{file.FullName}.dotnet.unlocked";
            var bytes = File.ReadAllBytes(file.FullName);
            var unprotected_bytes = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(output_file, unprotected_bytes);
            Console.WriteLine($"Unlocked as {output_file}");
        }
    }
}
using System.CommandLine;
using System.IO;

public enum Action {
    Lock,
    Unlock,
}

public class Program {
    /// <param name="file">The file to operate on</param>
    /// <param name="action">The action to take</param>
    public static void Main(FileInfo file, Action action) {
        Console.WriteLine($"file: {file}");
        Console.WriteLine($"action: {action}");
    }
}
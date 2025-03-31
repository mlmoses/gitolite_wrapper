using System.Runtime.InteropServices;

namespace GitoliteWrapper;

internal static partial class Posix
{
    public static (int, string) Exec(string path, params string[] args)
    {
        var realArgs = new string?[args.Length + 2];
        realArgs[0] = path;
        realArgs[^1] = null;
        args.CopyTo(realArgs, 1);
        execv(path, realArgs);
        return execv(path, realArgs) == -1 
            ? (Marshal.GetLastPInvokeError(), Marshal.GetLastPInvokeErrorMessage()) 
            : (0, string.Empty);
    }

    [LibraryImport("c", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    // ReSharper disable once IdentifierTypo
    // ReSharper disable once InconsistentNaming
    private static partial int execv(string path, [In] string?[] argv);
}
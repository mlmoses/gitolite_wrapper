using System;

namespace GitoliteWrapper;

/// <summary>
/// Extension methods for parsing OpenSSH data from spans of bytes.
/// </summary>
internal static class SshPublicKeyExtensions
{
    private enum CertType
    {
        None = -1,
        Rsa,
        Dsa,
        Ecdsa256,
        Ecdsa384,
        Ecdsa521,
        Ed25519
    }

    private static readonly byte[][] CertTypes =
    [
        "ssh-rsa-cert-v01@openssh.com"u8.ToArray(),
        "ssh-dss-cert-v01@openssh.com"u8.ToArray(),
        "ecdsa-sha2-nistp256-cert-v01@openssh.com"u8.ToArray(),
        "ecdsa-sha2-nistp384-cert-v01@openssh.com"u8.ToArray(),
        "ecdsa-sha2-nistp521-cert-v01@openssh.com"u8.ToArray(),
        "ssh-ed25519-cert-v01@openssh.com"u8.ToArray(),
    ];

    public static string FindGitoliteUser(this ReadOnlySpan<byte> publicKey)
    {
        var typeString = publicKey.ReadSshString(0);
        var offset = typeString.Length + 4;
        var principals = typeString.GetCertType() switch
        {
            CertType.None => throw new ArgumentException($"Key type {typeString.DecodeText()} not supported."),
            CertType.Dsa => publicKey.ReadPrincipalsFromDsa(offset),
            CertType.Ecdsa256 or CertType.Ecdsa384 or CertType.Ecdsa521 => publicKey.ReadPrincipalsFromEcdsa(offset),
            CertType.Ed25519 => publicKey.ReadPrincipalsFromEd25519(offset),
            CertType.Rsa => publicKey.ReadPrincipalsFromRsa(offset),
            _ => throw new NotSupportedException("Unknown certificate type value.")
        };

        if (principals.IsEmpty)
            return string.Empty;

        var principalPrefix = "gitolite:"u8;

        offset = 0;
        do
        {
            var p = principals.ReadSshString(offset);
            offset = offset + 4 + p.Length;

            if (p.StartsWith(principalPrefix) && p.Length > principalPrefix.Length)
                return p[principalPrefix.Length..].DecodeText();
        } while (offset < principals.Length);

        return string.Empty;
    }

    public static bool IsSupportedCertType(this ReadOnlySpan<byte> type) => type.GetCertType() != CertType.None;

    private static CertType GetCertType(this ReadOnlySpan<byte> typeString)
    {
        var l = CertTypes.Length;
        for (var i = 0; i < l; i++)
        {
            if (((ReadOnlySpan<byte>)CertTypes[i]).SequenceEqual(typeString))
                return (CertType)i;
        }

        return CertType.None;
    }

    private static ReadOnlySpan<byte> ReadPrincipalsFromDsa(this ReadOnlySpan<byte> publicKey, int offset)
    {
        /*
         * string    "ssh-dss-cert-v01@openssh.com"
         * string    nonce
         * mpint     p
         * mpint     q
         * mpint     g
         * mpint     y
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */

        // string nonce
        offset = publicKey.SkipSshString(offset);
        // mpint p
        offset = publicKey.SkipSshString(offset);
        // mpint q
        offset = publicKey.SkipSshString(offset);
        // mpint g
        offset = publicKey.SkipSshString(offset);
        // mpint y
        offset = publicKey.SkipSshString(offset);
        // uint64 serial
        // uint32 type
        offset += 12;
        // string key id
        offset = publicKey.SkipSshString(offset);

        // string valid principals
        return publicKey.ReadSshString(offset);
    }

    private static ReadOnlySpan<byte> ReadPrincipalsFromEcdsa(this ReadOnlySpan<byte> publicKey, int offset)
    {
        /*
         * string    "ecdsa-sha2-nistp256-cert-v01@openssh.com" |
         *           "ecdsa-sha2-nistp384-cert-v01@openssh.com" |
         *           "ecdsa-sha2-nistp521-cert-v01@openssh.com"
         * string    nonce
         * string    curve
         * string    public_key
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */

        // string nonce
        offset = publicKey.SkipSshString(offset);
        // string curve
        offset = publicKey.SkipSshString(offset);
        // string public_key
        offset = publicKey.SkipSshString(offset);
        // uint64 serial
        // uint32 type
        offset += 12;
        // string key id
        offset = publicKey.SkipSshString(offset);

        // string valid principals
        return publicKey.ReadSshString(offset);
    }

    private static ReadOnlySpan<byte> ReadPrincipalsFromEd25519(this ReadOnlySpan<byte> publicKey, int offset)
    {
        /*
         * string    "ssh-ed25519-cert-v01@openssh.com"
         * string    nonce
         * string    pk
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */
        
        // string nonce
        offset = publicKey.SkipSshString(offset);
        // string pk
        offset = publicKey.SkipSshString(offset);
        // uint64 serial
        // uint32 type
        offset += 12;
        // string key id
        offset = publicKey.SkipSshString(offset);

        // string valid principals
        return publicKey.ReadSshString(offset);
    }

    private static ReadOnlySpan<byte> ReadPrincipalsFromRsa(this ReadOnlySpan<byte> publicKey, int offset)
    {
        /*
         * string    "ssh-rsa-cert-v01@openssh.com"
         * string    nonce
         * mpint     e
         * mpint     n
         * uint64    serial
         * uint32    type
         * string    key id
         * string    valid principals
         * uint64    valid after
         * uint64    valid before
         * string    critical options
         * string    extensions
         * string    reserved
         * string    signature key
         * string    signature
         */

        // string nonce
        offset = publicKey.SkipSshString(offset);
        // mpint e
        offset = publicKey.SkipSshString(offset);
        // mpint n
        offset = publicKey.SkipSshString(offset);
        // uint64 serial
        // uint32 type
        offset += 12;
        // string key id
        offset = publicKey.SkipSshString(offset);

        // string valid principals
        return publicKey.ReadSshString(offset);
    }

    private static int ReadSshStringLength(this ReadOnlySpan<byte> publicKey, int offset) =>
        ((publicKey[offset] & 255) << 24)
        | ((publicKey[offset + 1] & 255) << 16)
        | ((publicKey[offset + 2] & 255) << 8)
        | (publicKey[offset + 3] & 255);

    private static ReadOnlySpan<byte> ReadSshString(this ReadOnlySpan<byte> publicKey, int offset) =>
        publicKey.Slice(offset + 4, publicKey.ReadSshStringLength(offset));

    private static int SkipSshString(this ReadOnlySpan<byte> publicKey, int offset) =>
        offset + publicKey.ReadSshStringLength(offset) + 4;
}

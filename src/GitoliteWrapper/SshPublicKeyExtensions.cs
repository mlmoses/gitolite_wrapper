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
        CertType type;
        if ("ssh-ed25519-cert-v01@openssh.com"u8.SequenceEqual(typeString))
            type = CertType.Ed25519;
        else if ("ssh-rsa-cert-v01@openssh.com"u8.SequenceEqual(typeString))
            type = CertType.Rsa;
        else if ("ecdsa-sha2-nistp256-cert-v01@openssh.com"u8.SequenceEqual(typeString))
            type = CertType.Ecdsa256;
        else if ("ecdsa-sha2-nistp384-cert-v01@openssh.com"u8.SequenceEqual(typeString))
            type = CertType.Ecdsa384;
        else if ("ecdsa-sha2-nistp521-cert-v01@openssh.com"u8.SequenceEqual(typeString))
            type = CertType.Ecdsa521;
        else if ("ssh-dss-cert-v01@openssh.com"u8.SequenceEqual(typeString))
            type = CertType.Dsa;
        else
            type = CertType.None;
        return type;
    }

    private static ReadOnlySpan<byte> ReadPrincipalsFromDsa(this ReadOnlySpan<byte> publicKey, int offset)
    {
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

    private static int ReadSshStringLength(this ReadOnlySpan<byte> publicKey, int offset)
    {
        var length = (((uint)publicKey[offset] & 255) << 24)
                     | (((uint)publicKey[offset + 1] & 255) << 16)
                     | (((uint)publicKey[offset + 2] & 255) << 8)
                     | ((uint)publicKey[offset + 3] & 255);

        // OpenSSH strings use 32-bit unsigned integers to represent the length of the string. However, Span<T> and
        // Memory<T> require 32-it signed integers for all operations. This means we can't work with OpenSSH strings
        // which are larger than int.MaxValue. Therefore, we use a checked cast here so that encountering such a large
        // OpenSSH string will result in an exception.
        return checked((int)length);
    }

    private static ReadOnlySpan<byte> ReadSshString(this ReadOnlySpan<byte> publicKey, int offset) =>
        publicKey.Slice(offset + 4, publicKey.ReadSshStringLength(offset));

    private static int SkipSshString(this ReadOnlySpan<byte> publicKey, int offset) =>
        offset + publicKey.ReadSshStringLength(offset) + 4;
}

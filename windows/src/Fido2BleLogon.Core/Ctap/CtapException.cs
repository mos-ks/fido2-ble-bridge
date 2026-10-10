namespace Fido2BleLogon.Ctap;

/// <summary>An error status returned by the authenticator.</summary>
public sealed class CtapException(byte status) : Exception($"The security key returned {Describe(status)}.")
{
    public byte Status { get; } = status;

    public const byte InvalidCredential = 0x22;
    public const byte OperationDenied = 0x27;
    public const byte NoCredentials = 0x2E;
    public const byte UserActionTimeout = 0x2F;
    public const byte PinBlocked = 0x32;
    public const byte PinAuthInvalid = 0x33;
    public const byte PinRequired = 0x36;
    public const byte UvBlocked = 0x3C;
    public const byte UvInvalid = 0x3F;

    /// <summary>Statuses keys use for "the built-in fingerprint check failed" (Chromium treats them alike;
    /// CTAP 2.1 keys with a PIN set report a failed match as 0x36).</summary>
    public bool IsFingerprintRejected => Status is OperationDenied or PinAuthInvalid or PinRequired or UvInvalid;

    /// <summary>The key refuses fingerprint (or PIN) checks until it is unblocked.</summary>
    public bool IsBlocked => Status is UvBlocked or PinBlocked;

    public static string Describe(byte status) =>
        Names.TryGetValue(status, out var name) ? $"{name} (0x{status:X2})" : $"error 0x{status:X2}";

    private static readonly Dictionary<byte, string> Names = new()
    {
        [0x01] = "CTAP1_ERR_INVALID_COMMAND",
        [0x02] = "CTAP1_ERR_INVALID_PARAMETER",
        [0x03] = "CTAP1_ERR_INVALID_LENGTH",
        [0x04] = "CTAP1_ERR_INVALID_SEQ",
        [0x05] = "CTAP1_ERR_TIMEOUT",
        [0x06] = "CTAP1_ERR_CHANNEL_BUSY",
        [0x11] = "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
        [0x12] = "CTAP2_ERR_INVALID_CBOR",
        [0x14] = "CTAP2_ERR_MISSING_PARAMETER",
        [0x15] = "CTAP2_ERR_LIMIT_EXCEEDED",
        [0x16] = "CTAP2_ERR_UNSUPPORTED_EXTENSION",
        [0x17] = "CTAP2_ERR_FP_DATABASE_FULL",
        [0x19] = "CTAP2_ERR_CREDENTIAL_EXCLUDED",
        [0x21] = "CTAP2_ERR_PROCESSING",
        [0x22] = "CTAP2_ERR_INVALID_CREDENTIAL",
        [0x23] = "CTAP2_ERR_USER_ACTION_PENDING",
        [0x24] = "CTAP2_ERR_OPERATION_PENDING",
        [0x25] = "CTAP2_ERR_NO_OPERATIONS",
        [0x26] = "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
        [0x27] = "CTAP2_ERR_OPERATION_DENIED",
        [0x28] = "CTAP2_ERR_KEY_STORE_FULL",
        [0x2A] = "CTAP2_ERR_NO_OPERATION_PENDING",
        [0x2B] = "CTAP2_ERR_UNSUPPORTED_OPTION",
        [0x2C] = "CTAP2_ERR_INVALID_OPTION",
        [0x2D] = "CTAP2_ERR_KEEPALIVE_CANCEL",
        [0x2E] = "CTAP2_ERR_NO_CREDENTIALS",
        [0x2F] = "CTAP2_ERR_USER_ACTION_TIMEOUT",
        [0x30] = "CTAP2_ERR_NOT_ALLOWED",
        [0x31] = "CTAP2_ERR_PIN_INVALID",
        [0x32] = "CTAP2_ERR_PIN_BLOCKED",
        [0x33] = "CTAP2_ERR_PIN_AUTH_INVALID",
        [0x34] = "CTAP2_ERR_PIN_AUTH_BLOCKED",
        [0x35] = "CTAP2_ERR_PIN_NOT_SET",
        [0x36] = "CTAP2_ERR_PIN_REQUIRED",
        [0x37] = "CTAP2_ERR_PIN_POLICY_VIOLATION",
        [0x39] = "CTAP2_ERR_REQUEST_TOO_LARGE",
        [0x3A] = "CTAP2_ERR_ACTION_TIMEOUT",
        [0x3B] = "CTAP2_ERR_UP_REQUIRED",
        [0x3C] = "CTAP2_ERR_UV_BLOCKED",
        [0x3D] = "CTAP2_ERR_INTEGRITY_FAILURE",
        [0x3E] = "CTAP2_ERR_INVALID_SUBCOMMAND",
        [0x3F] = "CTAP2_ERR_UV_INVALID",
        [0x40] = "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
        [0x7F] = "CTAP1_ERR_OTHER",
    };
}

/// <summary>The authenticator's response could not be understood.</summary>
public sealed class CtapProtocolException(string message) : Exception(message);

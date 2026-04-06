using Aes.Encryptor.Interfaces;

namespace Aes.Encryptor.Models.Responses;

/// <summary>
/// Represents encrypted output values returned by the AES service.
/// </summary>
public class EncryptedModel : IResponseModel
{
	/// <summary>
	/// Gets or sets the encrypted payload bytes.
	/// </summary>
	public byte[]? Cipher { get; set; }

	/// <summary>
	/// Gets the encrypted payload as a Base64-encoded string. Returns null if the cipher is null.
	/// </summary>
	public string? CipherBase64 => Cipher == null ? null : Convert.ToBase64String(Cipher);

	/// <summary>
	/// Gets or sets the initialization vector (IV) or nonce used during encryption.
	/// </summary>
	public byte[]? Iv { get; set; }

	/// <summary>
	/// Gets the initialization vector (IV) or nonce as a Base64-encoded string. Returns null if the IV is null.
	/// </summary>
	public string? IvBase64 => Iv == null ? null : Convert.ToBase64String(Iv);

	/// <summary>
	/// Gets or sets the authentication tag for authenticated encryption modes such as AES-GCM.
	/// </summary>
	public byte[]? Tag { get; set; }

	/// <summary>
	/// Gets the authentication tag as a Base64-encoded string. Returns null if the tag is null.
	/// </summary>
	public string? TagBase64 => Tag == null ? null : Convert.ToBase64String(Tag);
}

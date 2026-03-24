using Aes.Encryptor.Interfaces;

namespace Aes.Encryptor.Models.Responses;

/// <summary>
/// Represents encrypted output values returned by the AES service.
/// </summary>
public class EncryptedModel : IResponseModel
{
	/// <summary>
	/// Gets or sets the initialization vector (IV) or nonce used during encryption.
	/// </summary>
	public byte[]? Iv { get; set; }

	/// <summary>
	/// Gets or sets the encrypted payload bytes.
	/// </summary>
	public byte[]? CipherText { get; set; }

	/// <summary>
	/// Gets or sets the authentication tag for authenticated encryption modes such as AES-GCM.
	/// </summary>
	public byte[]? Tag { get; set; }
}

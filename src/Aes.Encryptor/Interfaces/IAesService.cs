using Aes.Encryptor.Enums;
using Aes.Encryptor.Models.Responses;

namespace Aes.Encryptor.Interfaces;

/// <summary>
/// Represents an interface for AES encryption and decryption operations.
/// </summary>
public interface IAesService
{
	/// <summary>
	/// Encrypts the specified plain text using AES encryption and returns an EncryptedModel containing the cipher, IV, and authentication tag (if applicable).
	/// </summary>
	/// <param name="plainText">The plain text to encrypt.</param>
	/// <param name="keyByte">The encryption key as a byte array.</param>
	/// <param name="ivByte">The initialization vector as a byte array (optional).</param>
	/// <param name="encryptorType">The type of AES encryptor to use (default is AES).</param>
	/// <returns>An EncryptedModel containing the cipher, IV, and authentication tag (if applicable).</returns>
	EncryptedModel Encrypt(
		string? plainText,
		byte[]? keyByte,
		byte[]? ivByte = null,
		EncryptorType encryptorType = EncryptorType.Aes
	);

	/// <summary>
	/// Decrypts the specified cipher text using AES decryption and returns the original plain text. The method validates the key and IV lengths and supports both AES and AES-GCM decryption based on the specified encryptor type.
	/// </summary>
	/// <param name="cipherByte">The cipher text to decrypt as a byte array.</param>
	/// <param name="keyByte">The decryption key as a byte array.</param>
	/// <param name="ivByte">The initialization vector as a byte array (optional).</param>
	/// <param name="tagByte">The authentication tag as a byte array (optional, applicable for AES-GCM).</param>
	/// <param name="encryptorType">The type of AES encryptor to use (default is AES).</param>
	/// <returns>The decrypted plain text.</returns>
	string Decrypt(
		byte[]? cipherByte,
		byte[]? keyByte,
		byte[]? ivByte = null,
		byte[]? tagByte = null,
		EncryptorType encryptorType = EncryptorType.Aes
	);
}

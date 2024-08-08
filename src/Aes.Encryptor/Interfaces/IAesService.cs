using Aes.Encryptor.Enums;

namespace Aes.Encryptor.Interfaces;

/// <summary>
/// Represents an interface for AES encryption and decryption operations.
/// </summary>
public interface IAesService
{
	/// <summary>
	/// Encrypts the specified plain text using AES encryption.
	/// </summary>
	/// <param name="plainText">The plain text to encrypt.</param>
	/// <param name="key">The encryption key.</param>
	/// <param name="iv">The initialization vector (optional).</param>
	/// <param name="encryptorType">The type of AES encryptor to use (default is AES).</param>
	/// <returns>The encrypted cipher text.</returns>
	string Encrypt(string? plainText, string? key, string? iv = null, EncryptorType encryptorType = EncryptorType.Aes);

	/// <summary>
	/// Decrypts the specified cipher text using AES decryption.
	/// </summary>
	/// <param name="cipherText">The cipher text to decrypt.</param>
	/// <param name="key">The decryption key.</param>
	/// <param name="iv">The initialization vector (optional).</param>
	/// <param name="encryptorType">The type of AES encryptor to use (default is AES).</param>
	/// <returns>The decrypted plain text.</returns>
	string Decrypt(string? cipherText, string? key, string? iv = null, EncryptorType encryptorType = EncryptorType.Aes);
}

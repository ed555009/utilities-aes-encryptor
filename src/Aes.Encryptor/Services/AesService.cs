using System.Security.Cryptography;
using System.Text;
using Aes.Encryptor.Enums;
using Aes.Encryptor.Interfaces;
using Aes.Encryptor.Models.Responses;
using Microsoft.Extensions.Logging;

namespace Aes.Encryptor.Services;

public class AesService(ILogger<AesService> logger) : IAesService
{
	private readonly ILogger<AesService> _logger = logger;

	public string Decrypt(
		string? cipherText,
		string? key,
		string? iv = null,
		EncryptorType encryptorType = EncryptorType.Aes
	)
	{
		ArgumentNullException.ThrowIfNull(cipherText);
		ArgumentNullException.ThrowIfNull(key);

		var cipherByte = Convert.FromBase64String(cipherText);
		var keyByte = Encoding.UTF8.GetBytes(key);
		var ivByte = iv == null ? null : Encoding.UTF8.GetBytes(iv);

		if (keyByte.Length != 32)
			throw new ArgumentException("Key length must be 32 bytes.");

		if (ivByte != null && ivByte.Length != 16)
			throw new ArgumentException("IV length must be 16 bytes.");

		return encryptorType switch
		{
			EncryptorType.Aes => AesDecrypt(cipherByte, keyByte, ivByte),
			EncryptorType.AesGcm => GcmDecrypt(cipherByte, keyByte),
			_ => throw new NotSupportedException(),
		};
	}

	public EncryptedModel Encrypt(
		string? plainText,
		byte[]? keyByte,
		byte[]? ivByte = null,
		EncryptorType encryptorType = EncryptorType.Aes
	)
	{
		ArgumentNullException.ThrowIfNull(plainText);
		ArgumentNullException.ThrowIfNull(keyByte);

		// var keyByte = Encoding.UTF8.GetBytes(key);
		// var ivByte = iv == null ? null : Encoding.UTF8.GetBytes(iv);

		if (keyByte.Length != 32)
			throw new ArgumentException("Key length must be 32 bytes.");

		if (ivByte != null && ivByte.Length != 16)
			throw new ArgumentException("IV length must be 16 bytes.");

		return encryptorType switch
		{
			EncryptorType.Aes => AesEncrypt(plainText, keyByte, ivByte),
			EncryptorType.AesGcm => GcmEncrypt(Encoding.UTF8.GetBytes(plainText), keyByte, ivByte),
			_ => throw new NotSupportedException(),
		};
	}

	EncryptedModel AesEncrypt(string plainText, byte[] keyByte, byte[]? ivByte = null)
	{
		_logger.LogDebug("Start encrypting using AES.");

		using var aes = System.Security.Cryptography.Aes.Create();
		aes.Key = keyByte;

		if (ivByte == null)
		{
			_logger.LogDebug("IV is not provided. Generating IV.");
			aes.GenerateIV();
		}
		else
			aes.IV = ivByte;

		_logger.LogTrace("Key: {Key}", Encoding.UTF8.GetString(aes.Key));
		_logger.LogTrace("IV: {IV}", Convert.ToBase64String(aes.IV));

		using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
		using var memoryStream = new MemoryStream();

		// if (ivByte == null)
		// {
		// 	_logger.LogDebug("IV is not provided. Writing IV to memory stream.");
		// 	memoryStream.Write(aes.IV, 0, aes.IV.Length);
		// }

		using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
		{
			using var streamWriter = new StreamWriter(cryptoStream);
			streamWriter.Write(plainText);
		}

		return new EncryptedModel { Cipher = memoryStream.ToArray(), Iv = aes.IV };
	}

	string AesDecrypt(byte[] cipherByte, byte[] keyByte, byte[]? ivByte = null)
	{
		_logger.LogDebug("Start decrypting using AES.");

		byte[] encryptedContentByte;

		if (ivByte == null)
		{
			_logger.LogDebug("IV is not provided. Try extracting IV from cipherByte.");
			ivByte = ExtractIvFromCipherByte(cipherByte);

			encryptedContentByte = new byte[cipherByte.Length - ivByte.Length];
			Buffer.BlockCopy(cipherByte, ivByte.Length, encryptedContentByte, 0, encryptedContentByte.Length);
		}
		else
			encryptedContentByte = cipherByte;

		using var aes = System.Security.Cryptography.Aes.Create();
		aes.Key = keyByte;
		aes.IV = ivByte;

		using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
		using var memoryStream = new MemoryStream(encryptedContentByte);
		using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
		using var streamReader = new StreamReader(cryptoStream);

		return streamReader.ReadToEnd();
	}

	EncryptedModel GcmEncrypt(byte[] plainByte, byte[] keyByte, byte[]? nonceByte = null)
	{
		_logger.LogDebug("Start encrypting using AESGCM.");

		using var aesgcm = new AesGcm(keyByte, AesGcm.TagByteSizes.MaxSize);
		// var nonceByte = new byte[AesGcm.NonceByteSizes.MaxSize];
		var cipherByte = new byte[plainByte.Length];
		var tagByte = new byte[AesGcm.TagByteSizes.MaxSize];

		if (nonceByte == null)
		{
			nonceByte = new byte[AesGcm.NonceByteSizes.MaxSize];
			RandomNumberGenerator.Fill(nonceByte);
		}

		LogBytes(keyByte, nonceByte, tagByte);

		aesgcm.Encrypt(nonceByte, plainByte, cipherByte, tagByte);

		// byte[] encryptedBytes = new byte[nonceByte.Length + cipherByte.Length + tagByte.Length];
		// Buffer.BlockCopy(nonceByte, 0, encryptedBytes, 0, nonceByte.Length);
		// Buffer.BlockCopy(cipherByte, 0, encryptedBytes, nonceByte.Length, cipherByte.Length);
		// Buffer.BlockCopy(tagByte, 0, encryptedBytes, nonceByte.Length + cipherByte.Length, tagByte.Length);

		return new EncryptedModel
		{
			Cipher = cipherByte,
			Iv = nonceByte,
			Tag = tagByte,
		};
	}

	string GcmDecrypt(byte[] cipherByte, byte[] keyByte)
	{
		_logger.LogDebug("Start decrypting using AESGCM.");

		var nonceByte = new byte[AesGcm.NonceByteSizes.MaxSize];
		var cipherTextByte = new byte[cipherByte.Length - nonceByte.Length - AesGcm.TagByteSizes.MaxSize];
		var tagByte = new byte[AesGcm.TagByteSizes.MaxSize];

		Buffer.BlockCopy(cipherByte, 0, nonceByte, 0, nonceByte.Length);
		Buffer.BlockCopy(cipherByte, nonceByte.Length, cipherTextByte, 0, cipherTextByte.Length);
		Buffer.BlockCopy(cipherByte, nonceByte.Length + cipherTextByte.Length, tagByte, 0, tagByte.Length);

		LogBytes(keyByte, nonceByte, tagByte);

		using var aesgcm = new AesGcm(keyByte, AesGcm.TagByteSizes.MaxSize);
		var decryptedByte = new byte[cipherTextByte.Length];
		aesgcm.Decrypt(nonceByte, cipherTextByte, tagByte, decryptedByte);

		return Encoding.UTF8.GetString(decryptedByte);
	}

	byte[] ExtractIvFromCipherByte(byte[] cipherByte, int ivByteSize = 16)
	{
		// check cipherByte length when IV is not provided
		ArgumentOutOfRangeException.ThrowIfGreaterThan(ivByteSize, cipherByte.Length);

		_logger.LogDebug("Extracting IV from cipherByte.");

		var ivByte = new byte[ivByteSize];
		Buffer.BlockCopy(cipherByte, 0, ivByte, 0, ivByte.Length);

		_logger.LogDebug("Extracted IV: {IV}", Encoding.UTF8.GetString(ivByte));

		return ivByte;
	}

	void LogBytes(byte[] keyByte, byte[] nonceByte, byte[] tagByte)
	{
		_logger.LogTrace("Key: {Key}", Encoding.UTF8.GetString(keyByte));
		_logger.LogTrace("Nonce: {Nonce}", Encoding.UTF8.GetString(nonceByte));
		_logger.LogTrace("Tag: {Tag}", Encoding.UTF8.GetString(tagByte));
	}
}

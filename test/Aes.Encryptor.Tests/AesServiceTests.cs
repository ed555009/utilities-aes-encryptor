using System.Text;
using Aes.Encryptor.Enums;
using Aes.Encryptor.Services;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit.Abstractions;

namespace Aes.Encryptor.Tests;

public class AesServiceTests(ITestOutputHelper testOutputHelper)
{
	private readonly ITestOutputHelper _testOutputHelper = testOutputHelper;
	private readonly string _plainText = "Hello, World!";

	[Theory]
	[InlineData("12345678901234567890123456789012", null, EncryptorType.Aes)]
	[InlineData("12345678901234567890123456789012", null, EncryptorType.AesGcm)]
	[InlineData("12345678901234567890123456789012", "1234567890123456", EncryptorType.Aes)]
	public void Encrypt_ShouldSucceed(string key, string? iv, EncryptorType encryptorType = EncryptorType.Aes)
	{
		// Given
		var service = new AesService(Mock.Of<ILogger<AesService>>());

		// When
		var result = service.Encrypt(
			_plainText,
			Encoding.UTF8.GetBytes(key),
			iv == null ? null : Encoding.UTF8.GetBytes(iv),
			encryptorType
		);

		_testOutputHelper.WriteLine("\nEncrypted: " + result.CipherBase64);

		// Then
		Assert.NotNull(result);
	}

	[Theory]
	[InlineData("12345678901234567890123456789012", null, EncryptorType.Aes)]
	[InlineData("12345678901234567890123456789012", null, EncryptorType.AesGcm)]
	[InlineData("12345678901234567890123456789012", "1234567890123456", EncryptorType.Aes)]
	public void Decrypt_ShouldSucceed(string key, string? iv, EncryptorType encryptorType = EncryptorType.Aes)
	{
		// Given
		var service = new AesService(Mock.Of<ILogger<AesService>>());
		var encrypted = service.Encrypt(
			_plainText,
			Encoding.UTF8.GetBytes(key),
			iv == null ? null : Encoding.UTF8.GetBytes(iv),
			encryptorType
		);
		_testOutputHelper.WriteLine(encrypted.CipherBase64);

		// When
		var result = service.Decrypt(encrypted.CipherBase64, key, iv, encryptorType);

		_testOutputHelper.WriteLine(result);

		// Then
		Assert.Equal(_plainText, result);
	}

	[Theory]
	[InlineData(EncryptorType.Aes)]
	[InlineData(EncryptorType.AesGcm)]
	public void Encrypt_WithNullContent_ShouldThrow(EncryptorType encryptorType)
	{
		// Given
		var service = new AesService(Mock.Of<ILogger<AesService>>());

		// When
		var ex = Assert.Throws<ArgumentNullException>(() =>
			service.Encrypt(
				null,
				Encoding.UTF8.GetBytes("12345678901234567890123456789012"),
				encryptorType: encryptorType
			)
		);

		// Then
		Assert.NotNull(ex);
	}

	[Theory]
	[InlineData(EncryptorType.Aes)]
	[InlineData(EncryptorType.AesGcm)]
	public void Decrypt_WithNullContent_ShouldThrow(EncryptorType encryptorType)
	{
		// Given
		var service = new AesService(Mock.Of<ILogger<AesService>>());

		// When
		var ex = Assert.Throws<ArgumentNullException>(() =>
			service.Decrypt(null, "12345678901234567890123456789012", encryptorType: encryptorType)
		);

		// Then
		Assert.NotNull(ex);
	}

	[Theory]
	[InlineData(EncryptorType.Aes)]
	[InlineData(EncryptorType.AesGcm)]
	public void Encrypt_WithNullKey_ShouldThrow(EncryptorType encryptorType)
	{
		// Given
		var service = new AesService(Mock.Of<ILogger<AesService>>());

		// When
		var ex = Assert.Throws<ArgumentNullException>(() =>
			service.Encrypt(_plainText, null, encryptorType: encryptorType)
		);

		// Then
		Assert.NotNull(ex);
	}

	[Theory]
	[InlineData(EncryptorType.Aes)]
	[InlineData(EncryptorType.AesGcm)]
	public void Decrypt_WithNullKey_ShouldThrow(EncryptorType encryptorType)
	{
		// Given
		var service = new AesService(Mock.Of<ILogger<AesService>>());

		// When
		var ex = Assert.Throws<ArgumentNullException>(() =>
			service.Decrypt(_plainText, null, encryptorType: encryptorType)
		);

		// Then
		Assert.NotNull(ex);
	}

	[Theory]
	[InlineData("1234567890123456789012345678901", "1234567890123456", EncryptorType.Aes)]
	[InlineData("12345678901234567890123456789012", "123456789012345", EncryptorType.Aes)]
	[InlineData("1234567890123456789012345678901", "1234567890123456", EncryptorType.AesGcm)]
	[InlineData("12345678901234567890123456789012", "123456789012345", EncryptorType.AesGcm)]
	public void Encrypt_WithWrongKeyOrIv_ShouldThrow(string key, string iv, EncryptorType encryptorType)
	{
		// Given
		var service = new AesService(Mock.Of<ILogger<AesService>>());

		// When
		var ex = Assert.Throws<ArgumentException>(() =>
			service.Encrypt(
				_plainText,
				Encoding.UTF8.GetBytes(key),
				iv == null ? null : Encoding.UTF8.GetBytes(iv),
				encryptorType
			)
		);

		// Then
		Assert.NotNull(ex);
	}

	[Theory]
	[InlineData("1234567890123456789012345678901", "1234567890123456", EncryptorType.Aes)]
	[InlineData("12345678901234567890123456789012", "123456789012345", EncryptorType.Aes)]
	[InlineData("1234567890123456789012345678901", "1234567890123456", EncryptorType.AesGcm)]
	[InlineData("12345678901234567890123456789012", "123456789012345", EncryptorType.AesGcm)]
	public void Decrypt_WithWrongKeyOrIv_ShouldThrow(string key, string iv, EncryptorType encryptorType)
	{
		// Given
		var service = new AesService(Mock.Of<ILogger<AesService>>());
		var encryptedText = service.Encrypt(
			_plainText,
			Encoding.UTF8.GetBytes("12345678901234567890123456789012"),
			encryptorType: encryptorType
		);

		// When
		var ex = Assert.Throws<ArgumentException>(() =>
			service.Decrypt(encryptedText.CipherBase64, key, iv, encryptorType)
		);

		// Then
		Assert.NotNull(ex);
	}
}

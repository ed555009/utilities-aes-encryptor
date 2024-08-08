# Utilities.AesEncryptor

[![GitHub](https://img.shields.io/github/license/ed555009/utilities-aes-encryptor)](LICENSE)
![Build Status](https://dev.azure.com/edwang/github/_apis/build/status/utilities-aes-encryptor?branchName=main)
[![Nuget](https://img.shields.io/nuget/v/Utilities.AesEncryptor)](https://www.nuget.org/packages/Utilities.AesEncryptor)

![Coverage](https://sonarcloud.io/api/project_badges/measure?project=utilities-aes-encryptor&metric=coverage)
![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=utilities-aes-encryptor&metric=alert_status)
![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=utilities-aes-encryptor&metric=reliability_rating)
![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=utilities-aes-encryptor&metric=security_rating)
![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=utilities-aes-encryptor&metric=vulnerabilities)

## Installation

```bash
dotnet add package Utilities.AesEncryptor
```

## Using service

### Register services

```csharp
using Utilities.AesEncryptor.Interfaces;
using Utilities.AesEncryptor.Services;

ConfigureServices(IServiceCollection services)
{
	// this injects as SINGLETON
	services.AddSingleton<IAesService, AesService>();
}
```

### Using service

By default, `AES-256` encryption/decryption will be used. You can specify the `Key` and `IV` (Initialization Vector) for encryption.

IV is optional, if you don't provide it, the service will generate a random IV.

With AES-256, the key size is 256 bits (32 bytes) and the IV size is 128 bits (16 bytes).

```csharp
using Utilities.AesEncryptor.Interfaces;

public class MyProcess
{
	private readonly IAesService _aesService;

	public MyProcess(IAesService aesService) =>
		_aesService = aesService;

	public string EncryptSomething() =>
		_aesService.Encrypt("PlainText", "Key", "IV");

	public string DecryptSomething() =>
		_aesService.Decrypt("CipherText", "Key", "IV");
}
```

### AES-256-GCM

You can use `AES-256-GCM` encryption/decryption by specifying the `EncryptorType` parameter.

`Nonce` (IV) and `Tag` is generated automatically, provided Nonce(IV) will be ignored.

```csharp
public string GcmEncryptSomething() =>
	_aesService.Encrypt("PlainText", "Key", encryptorType: EncryptorType.AesGcm);

public string GcmDecryptSomething() =>
	_aesService.Decrypt("CipherText", "Key",  encryptorType: EncryptorType.AesGcm);
```


# Java library for encryption for push notification payloads for the browser push API

## Getting Started

- Use `gradle build` to build
- Use `gradle writeClasspath` to write the classes to <root>/build/classpath.txt. Use this in your application (or
Scala REPL) for testing
- Requires Java8 and (dependencies)

## Usage

Sample code:

// TODO Verify with Firefox, add docs :-)

```

public GcmData generateEncryptedPayload(final String payload, final ChromeNotification notification)
    throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
           InvalidKeySpecException, InvalidKeyException, IOException, NoSuchPaddingException, BadPaddingException,
           IllegalBlockSizeException {
  GcmData data = new GcmData();
  KeyPair serverKeys = _ellipticCurveKeyUtil.generateServerKeyPair();
  final BrowserPushSubscriptionKeys keys = notification.getBrowserPushSubscriptionKeys();

  final ECPublicKey clientPublicKey = _ellipticCurveKeyUtil.loadP256Dh(keys.getP256dh());
  final byte[] clientAuth = Base64.getUrlDecoder().decode(keys.getAuth());
  final byte[] salt = generateSalt();
  final byte[] sharedSecret = _ellipticCurveKeyUtil.generateSharedSecret(serverKeys, clientPublicKey);
  final byte[] serverPublicKeyBytes = _ellipticCurveKeyUtil.publicKeyToBytes((ECPublicKey) serverKeys.getPublic());
  final byte[] clientPublicKeyBytes = _ellipticCurveKeyUtil.publicKeyToBytes(clientPublicKey);
  final byte[] nonceInfo = generateInfo(serverPublicKeyBytes, clientPublicKeyBytes, NONCE);
  final byte[] contentEncryptionKeyInfo = generateInfo(serverPublicKeyBytes, clientPublicKeyBytes, AESGCM128);

  data.cipherText = encryptPayload(payload, sharedSecret, salt, contentEncryptionKeyInfo, nonceInfo, clientAuth);
  data.encryptionHeader = createEncryptionHeader(salt);
  data.cryptoKeyHeader = createCryptoKeyHeader(serverPublicKeyBytes);

  return data;
}

class GcmData {
  String cipherText;
  String encryptionHeader;
  String cryptoKeyHeader;
}

```

To send the request to GCM, use

```

curl -X POST -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization: key=<key>" -H "Encryption: salt=eZULO4LdQPl_tpv79Ri3Ng==" -H "Crypto-Key: dh=BJ5xtRN5AkECsyoM3ljFkxrmlYjB-lsDIwUoOT5RlMV3AbDHcRg-MFFgLLfu5ef56pA5wtlz1noGLfNVPjRE_UA=" -H "Content-Encoding: aesgcm" -H "Cache-Control: no-cache" -d '{
    "registration_ids": ["d14qJGqcOI0:APA91bHwMJJegKCw1fX0IHJkicmUGlcWDHyOBEMHVgX6W5uMzUz9DqjJ1YDtqJ-rSzsb253LTcuKtlCKAXSRf5Dx16l9IE1C7XnKQY_IpLvfa7TuGT2ftKunJ4yR0XfFgQndRbu2gawu"],
    "raw_data": "RXFlOrxl7NC0QXoCJmQyZPIj/YjDveJucVhL0OQn"
}' "https://android.googleapis.com/gcm/send"

```

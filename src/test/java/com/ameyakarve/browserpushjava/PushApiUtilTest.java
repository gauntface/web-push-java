package com.ameyakarve.browserpushjava;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.DecoderException;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Created by akarve on 5/4/16.
 */

public class PushApiUtilTest extends BaseTestCase {

  public PushApiUtilTest()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
             InvalidKeySpecException {
    super();
  }

  @Test
  public void testGenerateInfo()
      throws IOException, DecoderException {
    byte[] info = PushApiUtil
        .generateInfo(_ellipticCurveKeyUtils.publicKeyToBytes((ECPublicKey) _serverKeyPair.getPublic()),
            _ellipticCurveKeyUtils.publicKeyToBytes(_clientPublicKey), "nonce".getBytes(StandardCharsets.UTF_8));
    final String expectedInfoBase64 =
        "Q29udGVudC1FbmNvZGluZzogbm9uY2UAUC0yNTYAAEEEIhaCyfJcO/VWSGovY/thEG9164OeXAA9PaC42F0ihbcg/saYeHVIwo8vFF/vHy8nLpkUreiXaiGCf/7TI/tBAABBBOg5KfYiBdDDRF12Ri17y3v+POPr8X0nVP2jDjowPVI/DMKU1aQ3OLdPH1iaakvR9/PHq6tNCzJH35v/JUz2crY=";
    Assert.assertEquals(expectedInfoBase64, Base64.getEncoder().encodeToString(info));
  }

  @Test
  public void testCreateEncryptionHeader() {
    final String encryptionHeader = PushApiUtil.createEncryptionHeader(Base64.getDecoder().decode(_exampleSalt));
    final String expectedEncryptionHeader = "salt=AAAAAAAAAAAAAAAAAAAAAA==";
    Assert.assertEquals(expectedEncryptionHeader, encryptionHeader);
  }

  @Test
  public void testCreateCryptoKeyHeader() throws DecoderException {
    final String cryptoHeader = PushApiUtil
        .createCryptoKeyHeader(_ellipticCurveKeyUtils.publicKeyToBytes((ECPublicKey) _serverKeyPair.getPublic()));
    final String expectedCryptoHeader =
        "dh=BOg5KfYiBdDDRF12Ri17y3v-POPr8X0nVP2jDjowPVI_DMKU1aQ3OLdPH1iaakvR9_PHq6tNCzJH35v_JUz2crY=";
    Assert.assertEquals(expectedCryptoHeader, cryptoHeader);
  }

  @Test
  public void testHkdfExtract()
      throws InvalidKeyException, NoSuchAlgorithmException {
    final byte[] salt = Base64.getUrlDecoder().decode(_clientAuthUrlBase64);
    final byte[] sharedSecret = Base64.getDecoder().decode("vgkL5otElJ7tB3jnxop9g7sGxuM4gGs5NL3qTCxe9JE=");
    final byte[] extract =
        PushApiUtil.hkdfExtract(sharedSecret, salt, "Content-Encoding: auth\0".getBytes(StandardCharsets.UTF_8), 32);
    final String expectedExtract = "9Ua+rfDdC4WzwO/W644ZISWGXpNp8bxDSICxjlr03xQ=";
    Assert.assertEquals(expectedExtract, Base64.getEncoder().encodeToString(extract));
  }

  @Test
  public void testEncryptWithAESGCM128()
      throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
             BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {

    final byte[] nonce = Base64.getDecoder().decode("6CkTryo+JSdq8TcG");
    final byte[] contentEncryptionKey = Base64.getDecoder().decode("0G5bnzk/43i9yMq0uSyd9A==");
    final byte[] plaintext = Base64.getDecoder().decode("AABIZWxsbywgV29ybGQu");
    final byte[] encrypted = PushApiUtil.encryptWithAESGCM128(nonce, contentEncryptionKey, plaintext);
    final String expectedEncrypted = "CE2OS6BxfXsC2YbTdfkeWLlt4AKWbHZ3Fe53n5/4Yg==";
    Assert.assertEquals(expectedEncrypted, Base64.getEncoder().encodeToString(encrypted));
  }

  @Test
  public void testEncryptPayload()
      throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException,
             IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
    final byte[] sharedSecret = Base64.getDecoder().decode("vgkL5otElJ7tB3jnxop9g7sGxuM4gGs5NL3qTCxe9JE=");
    final byte[] nonceInfo = Base64.getDecoder().decode(
        "Q29udGVudC1FbmNvZGluZzogbm9uY2UAUC0yNTYAAEEEIhaCyfJcO/VWSGovY/thEG9164OeXAA9PaC42F0ihbcg/saYeHVIwo8vFF/vHy8nLpkUreiXaiGCf/7TI/tBAABBBOg5KfYiBdDDRF12Ri17y3v+POPr8X0nVP2jDjowPVI/DMKU1aQ3OLdPH1iaakvR9/PHq6tNCzJH35v/JUz2crY=");
    final byte[] contentEncryptionKeyInfo = Base64.getDecoder().decode(
        "Q29udGVudC1FbmNvZGluZzogYWVzZ2NtAFAtMjU2AABBBCIWgsnyXDv1VkhqL2P7YRBvdeuDnlwAPT2guNhdIoW3IP7GmHh1SMKPLxRf7x8vJy6ZFK3ol2ohgn/+0yP7QQAAQQToOSn2IgXQw0RddkYte8t7/jzj6/F9J1T9ow46MD1SPwzClNWkNzi3Tx9YmmpL0ffzx6urTQsyR9+b/yVM9nK2");
    final byte[] clientAuth = Base64.getUrlDecoder().decode(_clientAuthUrlBase64);
    String encrypted = PushApiUtil
        .encryptPayload(messageToEncrypt, sharedSecret, Base64.getDecoder().decode(_exampleSalt),
            contentEncryptionKeyInfo, nonceInfo, clientAuth);
    final String expectedEncrypted = "CE2OS6BxfXsC2YbTdfkeWLlt4AKWbHZ3Fe53n5/4Yg==";

    Assert.assertEquals(expectedEncrypted, encrypted);
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void testEncryptPayloadWithBigPayload() throws Exception {
    final byte[] sharedSecret = Base64.getDecoder().decode("vgkL5otElJ7tB3jnxop9g7sGxuM4gGs5NL3qTCxe9JE=");
    final byte[] nonceInfo = Base64.getDecoder().decode(
        "Q29udGVudC1FbmNvZGluZzogbm9uY2UAUC0yNTYAAEEEIhaCyfJcO/VWSGovY/thEG9164OeXAA9PaC42F0ihbcg/saYeHVIwo8vFF/vHy8nLpkUreiXaiGCf/7TI/tBAABBBOg5KfYiBdDDRF12Ri17y3v+POPr8X0nVP2jDjowPVI/DMKU1aQ3OLdPH1iaakvR9/PHq6tNCzJH35v/JUz2crY=");
    final byte[] contentEncryptionKeyInfo = Base64.getDecoder().decode(
        "Q29udGVudC1FbmNvZGluZzogYWVzZ2NtAFAtMjU2AABBBCIWgsnyXDv1VkhqL2P7YRBvdeuDnlwAPT2guNhdIoW3IP7GmHh1SMKPLxRf7x8vJy6ZFK3ol2ohgn/+0yP7QQAAQQToOSn2IgXQw0RddkYte8t7/jzj6/F9J1T9ow46MD1SPwzClNWkNzi3Tx9YmmpL0ffzx6urTQsyR9+b/yVM9nK2");
    final byte[] clientAuth = Base64.getUrlDecoder().decode(_clientAuthUrlBase64);
    String encrypted = PushApiUtil
        .encryptPayload(bigMessageThatFails, sharedSecret, Base64.getDecoder().decode(_exampleSalt),
            contentEncryptionKeyInfo, nonceInfo, clientAuth);
  }
}
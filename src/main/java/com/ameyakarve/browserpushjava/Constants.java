package com.ameyakarve.browserpushjava;

import java.nio.charset.StandardCharsets;

/**
 * Created by akarve on 4/26/16.
 */

public final class Constants {

  private Constants() {
    // no op
  }

  public static final byte[] CONTENT_ENCODING = "Content-Encoding: ".getBytes(StandardCharsets.UTF_8);
  public static final byte[] AESGCM128 = "aesgcm".getBytes(StandardCharsets.UTF_8);
  public static final byte[] NONCE = "nonce".getBytes(StandardCharsets.UTF_8);
  public static final byte[] P256 = "P-256".getBytes(StandardCharsets.UTF_8);
  public static final int GCM_TAG_LENGTH = 16; // in bytes
  public static final String SECP256R1 = "secp256r1";
  public static final String HMAC_SHA256 = "HmacSHA256";
  public static final byte NULL_BYTE = (byte) 0;
  public static final byte KEY_LENGTH_BYTE = (byte) 65; // This is always 65 for our curve
  public static final int MAX_PAYLOAD_LENGTH = 4078;
}
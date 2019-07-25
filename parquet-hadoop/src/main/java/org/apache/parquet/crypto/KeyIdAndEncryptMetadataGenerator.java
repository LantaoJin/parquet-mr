package org.apache.parquet.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.parquet.crypto.AesEncryptor.Mode;

import static org.apache.parquet.crypto.AesEncryptor.*;

public class KeyIdAndEncryptMetadataGenerator {

  private final AesEncryptor encryptor;
  private final int encryptedKeyLength;

  public KeyIdAndEncryptMetadataGenerator(byte[] kek) throws IOException {
    this.encryptor = new AesEncryptor(Mode.GCM, kek, null);
    this.encryptedKeyLength = NONCE_LENGTH + GCM_TAG_LENGTH * 2 + SIZE_LENGTH;
  }

  public byte[] genKeyMetadata(String keyId, byte[] data) throws IOException {
    byte[] encryptedKey = encryptor.encrypt(data, null);
    byte[] keyIdBytes = keyId.getBytes(StandardCharsets.UTF_8);
    byte[] keyMetadata = new byte[encryptedKeyLength + keyIdBytes.length];
    System.arraycopy(encryptedKey, 0, keyMetadata, 0, encryptedKeyLength);
    System.arraycopy(keyIdBytes, 0, keyMetadata, encryptedKeyLength, keyIdBytes.length);
    return keyMetadata;
  }
}

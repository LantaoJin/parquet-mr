package org.apache.parquet.crypto;

import java.io.IOException;
import org.apache.parquet.crypto.AesEncryptor.Mode;

public class EncryptKeyMetadataGenerator implements KeyMetadataGenerator {

  private final AesEncryptor encryptor;

  public EncryptKeyMetadataGenerator(byte[] kek) throws IOException {
    this.encryptor = new AesEncryptor(Mode.GCM, kek, null);
  }

  @Override
  public byte[] genKeyMetadata(byte[] data) throws IOException {
    return encryptor.encrypt(data, null);
  }
}

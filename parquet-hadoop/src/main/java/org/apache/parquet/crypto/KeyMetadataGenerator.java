package org.apache.parquet.crypto;

import java.io.IOException;

public interface KeyMetadataGenerator {

  byte[] genKeyMetadata(byte[] data) throws IOException;

}

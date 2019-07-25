/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.parquet.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Hashtable;
import org.apache.parquet.crypto.AesEncryptor.Mode;

import static org.apache.parquet.crypto.AesEncryptor.GCM_TAG_LENGTH;
import static org.apache.parquet.crypto.AesEncryptor.NONCE_LENGTH;
import static org.apache.parquet.crypto.AesEncryptor.SIZE_LENGTH;

// KeyRetriever that will decrypt key from keyMetadata bytes
public class KeyIdAndDecryptKeyRetriever implements DecryptionKeyRetriever {

  private final Hashtable<String,byte[]> kekMap;
  private final int encryptedKeyLength;

  public KeyIdAndDecryptKeyRetriever() throws IOException {
    kekMap = new Hashtable<String,byte[]>();
    this.encryptedKeyLength = NONCE_LENGTH + GCM_TAG_LENGTH * 2 + SIZE_LENGTH;
  }

  public void putKey(String keyId, byte[] keyBytes) {
    kekMap.put(keyId, keyBytes);
  }

  @Override
  public byte[] getKey(byte[] keyMetaData) throws IOException {
    byte[] keyIdBytes = new byte[keyMetaData.length - encryptedKeyLength];
    System.arraycopy(keyMetaData, encryptedKeyLength, keyIdBytes, 0, keyIdBytes.length);
    String keyId = new String(keyIdBytes, StandardCharsets.UTF_8);
    byte[] kek = kekMap.get(keyId);
    AesDecryptor decryptor = new AesDecryptor(Mode.GCM, kek, null);
    byte[] encryptedKey = new byte[encryptedKeyLength];
    System.arraycopy(keyMetaData, 0, encryptedKey, 0, encryptedKeyLength);
    return decryptor.decrypt(encryptedKey, null);
  }
}

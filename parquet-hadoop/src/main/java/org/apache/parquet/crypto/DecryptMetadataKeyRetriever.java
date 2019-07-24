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
import org.apache.parquet.crypto.AesEncryptor.Mode;

// KeyRetriever that will decrypt key from keymetadata bytes
public class DecryptMetadataKeyRetriever implements DecryptionKeyRetriever {

  private final AesDecryptor decryptor;

  public DecryptMetadataKeyRetriever(byte[] kek) throws IOException {
    this.decryptor = new AesDecryptor(Mode.GCM, kek, null);
  }

  @Override
  public byte[] getKey(byte[] keyMetaData) throws IOException {
    return decryptor.decrypt(keyMetaData, null);
  }
}

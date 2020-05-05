/*
 * Copyright © 2020 Celeral.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.celeral.netconf.transport;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface Credentials {

  KeyPair getKeyPair()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
          InvalidAlgorithmParameterException;

  /**
   * Get the password to be used for authentication.
   *
   * @return the password or null if no password configured
   */
  String getPassword();

  /**
   * Get the principal name to authenticate as.
   *
   * @return principal or null if the default principle is to be used
   */
  String getUserName();
}

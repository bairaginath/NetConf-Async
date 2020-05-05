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
package com.celeral.netconf.ssh;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.session.ConnectionService;

import com.celeral.utils.Closeables;
import com.celeral.utils.Throwables;

import com.celeral.netconf.transport.Credentials;
import com.celeral.netconf.transport.SessionFactory;

public class SSHSessionFactory implements SessionFactory, AutoCloseable {
  public static final TimeUnit DEFAULT_TIMEUNIT = TimeUnit.SECONDS;
  public static final long DEFAULT_CONNECT_TIMEOUT = 30;
  public static final long DEFAULT_AUTH_TIMEOUT = 30;

  protected final SshClient client;
  protected TimeUnit timeUnit = DEFAULT_TIMEUNIT;
  protected long connectTimeout = DEFAULT_CONNECT_TIMEOUT;
  protected long authTimeout = DEFAULT_AUTH_TIMEOUT;

  public SSHSessionFactory() {
    client = SshClient.setUpDefaultClient();

    PropertyResolverUtils.updateProperty(client, FactoryManager.TCP_NODELAY, true);
    PropertyResolverUtils.updateProperty(client, FactoryManager.SOCKET_KEEPALIVE, true);

    client.setServerKeyVerifier(
        (session, remoteAddress, serverKey) -> {
          logger.debug(
              "Server {} presented unverified {} key: {} for session {}",
              remoteAddress,
              (serverKey == null) ? null : serverKey.getAlgorithm(),
              KeyUtils.getFingerPrint(serverKey),
              session);
          return true;
        });

    List<RequestHandler<ConnectionService>> oldGlobalRequestHandlers =
        client.getGlobalRequestHandlers();
    ArrayList<RequestHandler<ConnectionService>> newGlobalRequestHandlers =
        new ArrayList<>(oldGlobalRequestHandlers.size() + 1);
    newGlobalRequestHandlers.addAll(oldGlobalRequestHandlers);
    newGlobalRequestHandlers.add(new KeepAliveHandler<>());
    client.setGlobalRequestHandlers(newGlobalRequestHandlers);

    client.start();
  }

  @Override
  public SSHSession getSession(String host, int port, Credentials creds) throws IOException {
    ConnectFuture connect = client.connect(creds.getUserName(), host, port);
    if (connect.await(connectTimeout, timeUnit)) {
      ClientSession session = connect.getSession();
      try (Closeables closeables = new Closeables(session)) {
        session.setPasswordIdentityProvider(PasswordIdentityProvider.EMPTY_PASSWORDS_PROVIDER);
        session.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
        KeyPair keyPair = creds.getKeyPair();
        if (keyPair == null) {
          session.addPasswordIdentity(creds.getPassword());
        } else {
          session.addPublicKeyIdentity(keyPair);
        }
        session.auth().verify(authTimeout, timeUnit);

        closeables.protect();
      } catch (NoSuchAlgorithmException
          | InvalidKeySpecException
          | InvalidAlgorithmParameterException ex) {
        throw Throwables.throwFormatted(
            ex,
            IOException.class,
            "Unable to get the public key identity to connect to host {} at port {} as user {}!",
            host,
            port,
            creds.getUserName());
      }

      return new SSHSession(session);
    } else {
      connect.cancel();
      throw Throwables.throwFormatted(
          IOException.class,
          "Unable to connect to  {}:{} as user {} within {} {}!",
          host,
          port,
          creds.getUserName(),
          connectTimeout,
          timeUnit);
    }
  }

  @Override
  public void close() {
    client.stop();
  }

  private static final Logger logger = LogManager.getLogger();
}

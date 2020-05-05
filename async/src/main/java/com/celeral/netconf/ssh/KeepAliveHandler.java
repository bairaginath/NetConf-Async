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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.util.buffer.Buffer;

public class KeepAliveHandler<T> implements RequestHandler<T> {

  private long previousTimeMillis;
  private final long jitter;

  public KeepAliveHandler() {
    this(DEFAULT_JITTER);
  }

  public KeepAliveHandler(long jitter) {
    this.jitter = jitter;
  }

  @Override
  public Result process(T t, String request, boolean wantReply, Buffer buffer) throws Exception {
    if (request.startsWith("keepalive@")) {
      long currentTimeMillis = System.currentTimeMillis();
      if (currentTimeMillis - previousTimeMillis > jitter) {
        logger.trace(
            "{} received {}/{} after {} millis",
            t,
            request,
            wantReply,
            currentTimeMillis - previousTimeMillis);
        return Result.ReplyFailure;
      }

      return Result.Replied;
    }

    return Result.Unsupported;
  }

  private static final long DEFAULT_JITTER = 5;
  private static final Logger logger = LogManager.getLogger();
}

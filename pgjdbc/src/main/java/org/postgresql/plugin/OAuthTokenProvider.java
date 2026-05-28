/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.plugin;

import org.postgresql.util.PSQLException;

/**
 * Provides an OAuth 2.0 token for OAuth bearer authentication.
 */
public interface OAuthTokenProvider {

  /**
   * Returns a token for OAuth authentication.
   *
   * @return the token; must not be null
   * @throws PSQLException if the token cannot be obtained
   */
  String getToken() throws PSQLException;

}

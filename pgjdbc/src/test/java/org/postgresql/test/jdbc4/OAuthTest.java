/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.test.jdbc4;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.postgresql.PGProperty;
import org.postgresql.core.ServerVersion;
import org.postgresql.core.v3.OAuthAuthenticator;
import org.postgresql.plugin.OAuthTokenProvider;
import org.postgresql.test.OAuthTestTokenProvider;
import org.postgresql.test.TestUtil;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;
import org.postgresql.util.TestLogHandler;

import org.checkerframework.checker.nullness.qual.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Integration tests for OAuth Bearer (OAUTHBEARER SASL) authentication.
 * These tests require PostgreSQL 18+ with OAuth configured.
 */
public class OAuthTest {

  private static @Nullable Connection con;
  private static final String USERNAME = "testoauth";


  private static final OAuthTestTokenProvider provider = new OAuthTestTokenProvider();

  @BeforeAll
  static void setUp() throws Exception {
    TestUtil.assumeOAuthTestsEnabled();

    con = TestUtil.openPrivilegedDB();

    assumeTrue(
        TestUtil.haveMinimumServerVersion(con, ServerVersion.v18),
        "PostgreSQL 18+ required for OAuth tests");
  }

  @AfterAll
  static void tearDown() throws Exception {
    TestUtil.closeDB(con);
  }

  private @Nullable TestLogHandler logHandler;
  private @Nullable Logger oauthLogger;
  private @Nullable Level previousOauthLoggerLevel;

  @BeforeEach
  void installLogHandler() {
    logHandler = new TestLogHandler();
    oauthLogger = Logger.getLogger(OAuthAuthenticator.class.getName());
    previousOauthLoggerLevel = oauthLogger.getLevel();
    oauthLogger.addHandler(logHandler);
    oauthLogger.setLevel(Level.ALL);
  }

  @AfterEach
  void uninstallLogHandler() {
    if (oauthLogger != null && logHandler != null) {
      oauthLogger.removeHandler(logHandler);
      oauthLogger.setLevel(previousOauthLoggerLevel);
    }
    logHandler = null;
    oauthLogger = null;
  }

  /**
   * Static token authentication.
   */
  @Test
  void staticToken() throws Exception {
    Properties props = new Properties();
    PGProperty.USER.set(props, USERNAME);
    PGProperty.OAUTH_ALLOW_UNENCRYPTED.set(props, "true");
    PGProperty.OAUTH_TOKEN.set(props, new String(provider.getToken()));

    try (Connection c = TestUtil.openDB(props)) {
      assertCurrentUser(c, USERNAME);
    }
  }

  /**
   * Token provided by {@link OAuthTokenProvider} plugin class.
   */
  @Test
  void tokenProvider() throws SQLException {
    Properties props = new Properties();
    PGProperty.USER.set(props, USERNAME);
    PGProperty.OAUTH_ALLOW_UNENCRYPTED.set(props, "true");
    PGProperty.OAUTH_TOKEN_PROVIDER_CLASS_NAME.set(props, OAuthTestTokenProvider.class.getName());
    try (Connection c = TestUtil.openDB(props)) {
      assertCurrentUser(c, USERNAME);
    }
  }

  /**
   * An invalid bearer token causes the server to reject the connection.
   */
  @Test
  void invalidToken() throws Exception {
    Properties props = new Properties();
    PGProperty.USER.set(props, USERNAME);
    PGProperty.OAUTH_ALLOW_UNENCRYPTED.set(props, "true");
    PGProperty.OAUTH_TOKEN.set(props, "invalid-bearer-token");

    PSQLException ex = assertThrows(
        PSQLException.class,
        () -> TestUtil.openDB(props),
        "Server should reject an invalid bearer token");
    assertEquals(
        "FATAL: OAuth bearer authentication failed for user \"" + USERNAME + "\"",
        ex.getMessage());
  }

  @Test
  void requireAuthAllowsOAuth() throws Exception {
    Properties props = new Properties();
    PGProperty.USER.set(props, USERNAME);
    PGProperty.OAUTH_ALLOW_UNENCRYPTED.set(props, "true");
    PGProperty.OAUTH_TOKEN.set(props, new String(provider.getToken()));
    PGProperty.REQUIRE_AUTH.set(props, "oauth-bearer");

    try (Connection c = TestUtil.openDB(props)) {
      assertCurrentUser(c, USERNAME);
    }
  }

  @Test
  void requireAuthForbidsOAuth() throws Exception {
    Properties props = new Properties();
    PGProperty.USER.set(props, USERNAME);
    PGProperty.OAUTH_TOKEN.set(props, new String(provider.getToken()));
    PGProperty.REQUIRE_AUTH.set(props, "!oauth-bearer");

    PSQLException ex = assertThrows(
        PSQLException.class,
        () -> TestUtil.openDB(props),
        "Driver should reject the connection when requireAuth disallows OAuth Bearer");
    assertEquals(
        "The server requested SASL authentication with mechanisms [OAUTHBEARER], but non of them configured or supported by the driver.",
        ex.getMessage());
  }

  @Test
  void channelBindingIncompatibleWithOAuth() throws Exception {
    // channelBinding requires a TLS connection, so this scenario only applies when SSL is enabled.
    TestUtil.assumeSslTestsEnabled();

    Properties props = new Properties();
    PGProperty.USER.set(props, USERNAME);
    PGProperty.SSL_MODE.set(props, "require");
    PGProperty.OAUTH_TOKEN.set(props, new String(provider.getToken()));
    PGProperty.CHANNEL_BINDING.set(props, "require");

    PSQLException ex = assertThrows(
        PSQLException.class,
        () -> TestUtil.openDB(props),
        "Driver should reject OAuth when channelBinding=require");
    assertEquals(PSQLState.CONNECTION_REJECTED.getState(), ex.getSQLState());
    assertEquals(
        "Channel binding is not supported for OAuth authentication.",
        ex.getMessage());
  }



  /**
   * Verifies that the given connection is authenticated as the expected user.
   */
  private static void assertCurrentUser(Connection c, String expectedUser) throws SQLException {
    try (Statement stmt = c.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT current_user")) {
      assertTrue(rs.next(), "Expected at least one row from SELECT current_user");
      assertEquals(expectedUser, rs.getString(1), "current_user should match the expected user");
    }
  }


}

/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.test;

import org.postgresql.plugin.OAuthTokenProvider;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * OAuth token provider for the test suite.
 */
public class OAuthTestTokenProvider implements OAuthTokenProvider {

  private static final String USERNAME = "testoauth";
  private static final String KEYCLOAK_CLIENT_ID = "pgjdbc-test";
  private static final String KEYCLOAK_PASSWORD = "testoidc-password";
  private static final String KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/pgjdbc/protocol/openid-connect/token";
  private static final String KEYCLOAK_SCOPE = "pgjdbc";

  @Override
  public char[] getToken() throws PSQLException {
    String token = null;
    try {
      token = fetchToken(KEYCLOAK_TOKEN_URL, KEYCLOAK_SCOPE);
    } catch (Exception ex) {
      throw new PSQLException(
          "Failed to get OAuth token: " + ex.getMessage(),
          PSQLState.CONNECTION_REJECTED, ex);
    }
    if (token == null || token.isEmpty()) {
      throw new PSQLException(
          "oauthToken system property not set",
          PSQLState.INVALID_PARAMETER_VALUE);
    }
    return token.toCharArray();
  }

  private static String fetchToken(String url, String scope) throws Exception {
    String body = "grant_type=password"
        + "&client_id=" + URLEncoder.encode(KEYCLOAK_CLIENT_ID, "UTF-8")
        + "&password=" + URLEncoder.encode(KEYCLOAK_PASSWORD, "UTF-8")
        + "&username=" + URLEncoder.encode(USERNAME, "UTF-8")
        + "&scope=" + URLEncoder.encode(scope, "UTF-8");

    String response = httpPost(url, body);
    String key = "\"access_token\":\"";
    int start = response.indexOf(key);
    if (start < 0) {
      throw new PSQLException(
          "access_token not found in Keycloak response: " + response,
          PSQLState.CONNECTION_REJECTED);
    }
    start += key.length();
    int end = response.indexOf('"', start);
    return response.substring(start, end);
  }

  private static String httpPost(String url, String body) throws Exception {
    HttpURLConnection conn = open(url);
    conn.setRequestMethod("POST");
    conn.setDoOutput(true);
    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
    conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));
    try (DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {
      out.write(bodyBytes);
    }
    return readResponse(conn);
  }

  private static HttpURLConnection open(String urlStr) throws Exception {
    HttpURLConnection conn = (HttpURLConnection) URI.create(urlStr).toURL().openConnection();
    conn.setConnectTimeout(5000);
    conn.setReadTimeout(10000);
    return conn;
  }

  private static String readResponse(HttpURLConnection conn) throws Exception {
    try (BufferedReader reader = new BufferedReader(
        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
      return reader.lines().collect(Collectors.joining("\n"));
    }
  }
}

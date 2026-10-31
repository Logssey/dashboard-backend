package com.logssey.secret.testing;

import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.UUID;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Uses Testcontainers by default. An explicitly marked, isolated local PostgreSQL 18 cluster can
 * run the same integration tests when Docker is unavailable. Never connects to the application DB.
 */
public final class SecretTestPostgres extends PostgreSQLContainer {
  private final String adminUrl = System.getenv("SECRET_TEST_POSTGRES_URL");
  private final String localUser = System.getenv("SECRET_TEST_POSTGRES_USER");
  private final String localPassword = System.getenv("SECRET_TEST_POSTGRES_PASSWORD");
  private String localUrl;
  private String localDatabase;
  private boolean localRunning;

  public SecretTestPostgres() {
    super("postgres:18.6");
  }

  private boolean local() {
    return adminUrl != null && !adminUrl.isBlank();
  }

  @Override
  public synchronized void start() {
    if (!local()) {
      super.start();
      return;
    }
    if (localRunning) return;
    if (!adminUrl.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]{4,5}/secret_[a-z0-9_]+")
        || localUser == null
        || !localUser.startsWith("secret_")) {
      throw new IllegalStateException("Local tests require a dedicated loopback Secret test cluster");
    }
    try (var connection = DriverManager.getConnection(adminUrl, getUsername(), getPassword());
        var statement = connection.createStatement()) {
      try (var marker =
          statement.executeQuery(
              "SELECT current_setting('cluster_name'), current_setting('server_version_num')")) {
        marker.next();
        if (!marker.getString(1).matches("logssey-secret-[a-z0-9-]+-tests")
            || marker.getInt(2) < 180000
            || marker.getInt(2) >= 190000) {
          throw new IllegalStateException("Refusing an unmarked or incompatible PostgreSQL cluster");
        }
      }
      // Generated identifiers only; each fixture gets a fresh database and retains it for inspection.
      localDatabase = "secret_test_" + UUID.randomUUID().toString().replace("-", "");
      statement.execute("CREATE DATABASE " + localDatabase);
      localUrl = adminUrl.substring(0, adminUrl.lastIndexOf('/') + 1) + localDatabase;
      localRunning = true;
    } catch (SQLException error) {
      throw new IllegalStateException("Cannot initialize the isolated PostgreSQL test database", error);
    }
  }

  @Override
  public synchronized void stop() {
    if (!local()) super.stop();
    else localRunning = false;
  }

  @Override
  public boolean isRunning() {
    return local() ? localRunning : super.isRunning();
  }

  @Override
  public String getJdbcUrl() {
    if (!local()) return super.getJdbcUrl();
    if (!localRunning) throw new IllegalStateException("Start the isolated test database first");
    return localUrl;
  }

  @Override
  public String getDatabaseName() {
    return local() ? localDatabase : super.getDatabaseName();
  }

  @Override
  public String getUsername() {
    return local() ? localUser : super.getUsername();
  }

  @Override
  public String getPassword() {
    return local() ? (localPassword == null ? "" : localPassword) : super.getPassword();
  }
}

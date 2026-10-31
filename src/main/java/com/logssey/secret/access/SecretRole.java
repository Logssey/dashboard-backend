package com.logssey.secret.access;

/** Secret roles are explicit database grants, independent of the dashboard login role. */
public enum SecretRole {
    SECURITY, REMEDIATOR, OPERATIONS
}

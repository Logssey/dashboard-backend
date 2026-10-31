package com.logssey.secret.access;

/** Shared predicate for live location reads and rechecking a stored snapshot's visible memberships. */
public final class SecretOccurrenceAccessSql {
    private SecretOccurrenceAccessSql() {}
    public static String predicate(String occurrenceAlias,String userParameter) {
        if(!occurrenceAlias.matches("[a-z][a-z0-9_]*")||!userParameter.matches(":[A-Za-z][A-Za-z0-9]*"))
            throw new IllegalArgumentException("Invalid internal SQL alias");
        return """
            EXISTS (SELECT 1 FROM secret_role_grants acl_grant
              WHERE acl_grant.user_id=USER_ID AND acl_grant.revoked_at IS NULL
                AND (acl_grant.connection_id IS NULL OR acl_grant.connection_id=OCCURRENCE.connection_id)
                AND (acl_grant.role='SECURITY' OR (acl_grant.role='REMEDIATOR' AND EXISTS (
                    SELECT 1 FROM secret_case_occurrences acl_location
                    JOIN secret_response_cases acl_case ON acl_case.case_id=acl_location.case_id
                    WHERE acl_location.occurrence_id=OCCURRENCE.occurrence_id AND acl_case.is_current AND (
                      (CASE WHEN jsonb_exists(to_jsonb(acl_location),'assigned_user_id')
                         THEN (to_jsonb(acl_location)->>'assigned_user_id')::bigint ELSE acl_case.assigned_user_id END)=USER_ID
                      OR ((CASE WHEN jsonb_exists(to_jsonb(acl_location),'assigned_user_id')
                         THEN (to_jsonb(acl_location)->>'assigned_user_id')::bigint ELSE acl_case.assigned_user_id END) IS NULL
                        AND EXISTS (SELECT 1 FROM secret_team_memberships acl_team
                          WHERE acl_team.user_id=USER_ID AND acl_team.removed_at IS NULL
                            AND acl_team.team_name=CASE WHEN jsonb_exists(to_jsonb(acl_location),'assigned_team')
                                THEN to_jsonb(acl_location)->>'assigned_team' ELSE acl_case.assigned_team END))
                    )))))
            """.replace("OCCURRENCE",occurrenceAlias).replace("USER_ID",userParameter);
    }
}

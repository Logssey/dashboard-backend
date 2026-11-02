-- Run using a monitoring role with SELECT only on these tables. Aggregate metadata
-- only: no scope refs, names, key labels, HMAC values or provider error bodies.
BEGIN TRANSACTION READ ONLY;
SELECT clock_timestamp() AS observed_at, kind, purpose, status, count(*) AS jobs,
       max(attempt_no) AS max_attempt,
       max(extract(epoch FROM clock_timestamp()-available_at))
         FILTER (WHERE status='PENDING' AND available_at<=clock_timestamp()) AS oldest_due_seconds,
       count(*) FILTER (WHERE status='LEASED' AND lease_until<clock_timestamp()) AS expired_leases
FROM secret_jobs WHERE status IN ('PENDING','LEASED') GROUP BY kind,purpose,status;

SELECT result_status, count(*) AS runs
FROM secret_scan_runs WHERE requested_at>clock_timestamp()-interval '24 hours'
GROUP BY result_status ORDER BY result_status;

SELECT count(*) FILTER (WHERE status='ACTIVE') AS active_connections,
       count(*) FILTER (WHERE status='ACTIVE' AND next_due_at<clock_timestamp()-interval '2 minutes') AS overdue_connections,
       max(last_collection_success_at) AS latest_collection_success
FROM secret_connections;
COMMIT;

# S3 folder collection

`AWS_S3_OBJECT_CONTENT` accepts both existing exact-object approvals and explicit
folder approvals. Folder approval uses
`aws://ACCOUNT/REGION/s3/prefix/BUCKET/ENCODED_PREFIX`, with a nonempty prefix ending
in `/`, encoded as one URI path segment (for example `configs%2F`). Existing
`s3/object` approvals retain their exact-file behavior.

Every full scan calls paginated `ListObjectsV2` with that prefix, no delimiter,
and the expected bucket owner. New files and nested folders are discovered without
registering individual objects. Folder markers are ignored. Each file is read
with the existing size, owner, ETag and optional version checks. Plain UTF-8 text
is scanned in memory; content buffers are erased after processing.

Findings retain separate object coordinates, while credential identity still
deduplicates across files. Manual credential validation and location rechecks
resolve only the original object within the approved prefix. Storage-policy
scope matching also checks the prefix and originating scope.

## IAM

The collector needs `s3:ListBucket` on the bucket, restricted by `s3:prefix` to
the approved folder, and `s3:GetObject` on `BUCKET/PREFIX/*`. SSE-KMS objects may
additionally require decrypt permission for their key. Neither public access nor
whole-account content access is needed.

## Coverage limits

The existing per-file limit is 256 KiB. Prefix scans allow 10,000 listed entries,
100 pages and 16 MiB of processed text per scope. Unsupported object names (source
coordinate limit 500 characters), binary/non-UTF-8 files, oversized objects,
read failures, list failures and limit hits are reported as incomplete coverage;
they do not turn into a successful all-files-clean result. Empty folders can
complete successfully with zero objects. The prefix includes current objects,
not historical versions.

Current AWS target-management UI does not yet provide a folder editor. An approved
folder must be configured as a connection scope by the operator; after that,
normal manual and scheduled scans discover its files automatically.

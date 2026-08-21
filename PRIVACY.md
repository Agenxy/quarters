# Privacy

Quarters is local software. It has no account, network service, telemetry,
analytics, crash upload or usage log.

Space folders can contain credentials, histories and agent conversations. They
are created with mode `0700`; generated files use `0600`. Quarters does not
inspect or report their contents. `env` redacts every value passed through an
explicit `--inherit` flag.

Removing a space deletes its folder from the local filesystem after an atomic
rename. Filesystem snapshots, backups and storage recovery may retain earlier
blocks. Quarters does not claim secure erasure.


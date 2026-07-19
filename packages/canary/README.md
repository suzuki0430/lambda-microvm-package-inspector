# `@demo/canary`

A harmless npm lifecycle canary for demonstrating bounded behavioral inspection.
Its `postinstall` script writes one file under `/tmp`, starts `/usr/bin/true`,
reads a nonexistent demonstration environment variable, attempts to open a
nonexistent AWS credentials path, and contacts a reserved `.test` hostname.

It does not contain secrets, persistence, destructive behavior, or a public
network destination.

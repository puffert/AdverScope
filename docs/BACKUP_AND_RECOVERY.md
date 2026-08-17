# Backup, recovery, and project transfer

AdverScope `0.9.0` treats recovery as part of professional evidence custody. Backups and project transfers are versioned ZIP archives with a complete file inventory, byte sizes, and SHA-256 digests. Import verifies every declared file before the database or evidence store is changed.

These archives can contain customer prompts, target responses, screenshots, uploaded artifacts, findings, and recovered sensitive values. Keep them within the engagement's approved storage and transfer boundary.

## Automatic database migration protection

When AdverScope opens an existing database with an older supported schema, it performs this sequence:

1. Create an online SQLite backup under `<database directory>/backups/migrations/`.
2. Verify the backup with SQLite integrity and foreign-key checks.
3. Write an adjacent manifest containing the source and target schema, inventory, and database SHA-256.
4. Run the versioned migration inside an immediate transaction.
5. Record the migration and backup digest in `schema_migrations`.
6. Commit only after foreign-key verification succeeds.

If migration raises an error or is interrupted before commit, SQLite rolls back the transaction and AdverScope restores the verified pre-migration database before returning the startup error. Never delete a migration backup until the upgraded installation, projects, evidence, and reports have been reviewed.

## GUI data-custody workflow

Select **Local data** in the top-right header.

- **Export selected project** creates one portable project archive. It contains exactly one project database plus that project's evidence files.
- **Verify and import** checks the complete archive and imports it only when the project ID and evidence directory do not already exist.
- **Download verified local backup** captures every project, the database, retained evidence, artifacts, non-secret provider profiles, and non-secret configuration metadata.

The GUI requires a sensitive-data acknowledgement. Browser login sessions are excluded by default because they can contain reusable authentication state and are not finding evidence. Their separate checkbox should be used only when the rules of engagement and credential-handling policy explicitly permit it.

Replacement restore is intentionally unavailable while the web application is running. Stop AdverScope and use the CLI.

## CLI project transfer

Stop AdverScope first. Direct CLI storage commands acquire the same database/port lock as the server and refuse to run while another AdverScope process owns it.

```text
adverscope projects export PROJECT_ID project.advscope-project.zip --acknowledge-sensitive-data
adverscope projects verify project.advscope-project.zip
adverscope projects import project.advscope-project.zip --acknowledge-sensitive-data
```

Add `--include-browser-sessions` only when credential-bearing browser state is approved for transfer.

Project import is intentionally not a merge operation. Duplicate project IDs, an existing project evidence directory, incompatible database schemas, unsafe archive paths, symbolic links, undeclared files, changed hashes, and failed database integrity checks stop the import without changing the destination project records.

## Complete local backup

Stop AdverScope, then run:

```text
adverscope backup create adverscope-backup.zip --acknowledge-sensitive-data
adverscope backup verify adverscope-backup.zip
```

The backup includes:

- the complete SQLite project database;
- every retained project evidence file and uploaded artifact;
- model-provider profiles containing environment-variable references, never key values;
- non-secret runtime configuration metadata.

It excludes browser sessions unless separately requested. API keys held in environment variables or process memory are never part of the backup.

## Offline restore

Initialize the destination installation so its intended local paths and port are known. Stop AdverScope, verify the archive, then restore:

```text
adverscope backup verify adverscope-backup.zip
adverscope backup restore adverscope-backup.zip --acknowledge-sensitive-data --yes
adverscope doctor --skip-model
adverscope serve
```

Restore keeps the destination installation's storage paths. It replaces the assessment database, evidence tree, and non-secret provider profiles. Before replacement, it retains the current database, evidence, and provider state under `backups/restore-rollback/` and writes `backups/restore-in-progress.json`. Final database integrity and foreign-key checks must pass before rollback state is removed.

If the process or machine stops during restore, the next `adverscope serve` detects the journal and returns the previous state before opening the database. An unreadable or path-inconsistent journal blocks startup for manual review instead of guessing.

## Retention and deletion boundary

AdverScope uses recoverable archive, not destructive project deletion. Archiving a project keeps its database records, traffic, screenshots, artifacts, findings, reviews, reports, and audit history read-only until restored. Exporting or backing up never deletes source data.

AdverScope does not claim forensic secure erasure. SSD wear levelling, copy-on-write filesystems, cloud snapshots, endpoint backup agents, and virtual-disk snapshots can retain old blocks after normal deletion. When the approved retention period ends:

1. Stop AdverScope.
2. Confirm which project exports, local backups, migration backups, rollback directories, browser sessions, and external copies are in scope.
3. Delete the database, evidence directory, provider profile file, browser sessions, and all approved backup copies using the organization's managed disposal workflow.
4. Rely on full-disk encryption key destruction, managed media sanitization, or storage-provider deletion controls when verifiable secure disposal is required.
5. Record the disposal action outside the deleted store according to the engagement and legal retention policy.

Do not present ordinary filesystem deletion as guaranteed secure erasure.

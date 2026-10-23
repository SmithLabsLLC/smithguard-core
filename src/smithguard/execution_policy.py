"""Source-bound owner policy; not a caller-controlled validation bypass."""

# September 11 standing direction, explicitly reaffirmed September 13, 2026.
# This records excluded proof, not a successful backup or restore. Artifact and
# migration-journal validation bind this policy to the reviewed release bytes.
# The recovery entry points it once gated were deleted on September 18, 2026;
# backups are an ad hoc owner operation, never a packaged feature.
BACKUP_RESTORE_POLICY = "not_required_by_owner_20260911"

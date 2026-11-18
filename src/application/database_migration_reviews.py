"""Trusted composition: authorize before provider reads, persist exact output.

Only server-owned placements/readers enter this service. Public clients choose
registered IDs, never verifier instances, connection strings or proof documents.
Provider-bearing collection belongs in the worker/operator process. An API with
no cloud/SQL collector credentials must queue collection instead of calling it.
"""


class DatabaseMigrationReviewService:
    def __init__(self, preflight, reviews):
        self.preflight, self.reviews = preflight, reviews

    def review(self, principal, source, target, policy, *, source_revision):
        self.reviews.authorize(principal, source.application_id)
        if (
            source.organization_id != principal.organization_id
            or target.organization_id != principal.organization_id
        ):
            raise FileNotFoundError("Application not found")
        report = self.preflight.inspect(source, target, policy, source_revision=source_revision)
        return self.reviews.record(principal, report)

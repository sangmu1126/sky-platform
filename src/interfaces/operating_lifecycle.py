"""Compose the same owned operations flow into upload and DB intake APIs."""

import os
from datetime import UTC, datetime

from adapters.state.deployment_reads import PostgresDeploymentReads
from application.operating_lifecycle import OperatingLifecycle
from interfaces.http.operating_lifecycle import handler_for_operating_lifecycle
from interfaces.operating_review import OperatingReviewController, load_operating_policies


def compose_operating_lifecycle(
    app,
    base_handler,
    connection,
    operations,
    *,
    account_id,
    region,
    policy_path=None,
    pool_settings=None,
    recovery=None,
):
    policies = (
        load_operating_policies(policy_path, account_id=account_id, region=region)
        if (policy_path or "SKY_OPERATING_REVIEW_POLICIES_JSON" in os.environ)
        else {}
    )
    reviews = OperatingReviewController(operations.records, policies)
    preparation = cutover = None
    handler = base_handler
    if policies:
        from interfaces.http.operating_review import handler_for_operating_review

        handler = handler_for_operating_review(app, reviews, base_handler=handler)
    from interfaces.database_cutover import DatabaseCutoverController, load_cutover_api_configuration
    from interfaces.database_preparation import (
        DatabasePreparationController,
        load_preparation_api_configuration,
    )

    if os.environ.get("SKY_DEDICATED_PREPARATION_ENABLED", "false") != "false":
        if pool_settings is None:
            raise ValueError("Dedicated preparation requires the registered workload pool")
        settings = load_preparation_api_configuration(policies=policies, source=pool_settings)
        if settings is not None:
            app.database_preparation_page = "/database-preparation"
            from application.database_promotion_workflow import PromotionPreparationAdmission
            from interfaces.http.database_preparation import handler_for_database_preparation

            preparation = DatabasePreparationController(
                reviews,
                PromotionPreparationAdmission(
                    operations.records,
                    operations,
                    policies,
                    enabled=True,
                    clock=lambda: datetime.now(UTC).isoformat(),
                ),
                pool_settings.pool,
            )
            handler = handler_for_database_preparation(app, reviews, preparation, base_handler=handler)
    registrations = load_cutover_api_configuration(
        policies=policies, account_id=account_id, region=region, now=datetime.now(UTC).isoformat()
    )
    if registrations is not None:
        from application.database_cutover_workflow import PromotionCutoverAdmission
        from interfaces.http.database_cutover import handler_for_database_cutover

        cutover = DatabaseCutoverController(
            reviews,
            PromotionCutoverAdmission(
                operations.records,
                operations,
                policies,
                registrations,
                enabled=True,
                clock=lambda: datetime.now(UTC).isoformat(),
            ),
        )
        handler = handler_for_database_cutover(app, reviews, cutover, base_handler=handler)
    app.operating_lifecycle_page = "/operations"
    controller = OperatingLifecycle(
        PostgresDeploymentReads(connection, workspace=operations.workspace),
        reviews=reviews,
        operations=operations,
        preparation=preparation,
        cutover=cutover,
        recovery=recovery,
    )
    return handler_for_operating_lifecycle(app, controller, base_handler=handler)

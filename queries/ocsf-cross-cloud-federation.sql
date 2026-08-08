-- Portable OCSF-oriented detection pseudocode.
-- Adapt timestamp arithmetic, nested-field syntax, FILTER/CASE expressions,
-- and overlapping-window de-duplication to your analytics engine.
-- Expected input: one row per normalized OCSF event; time is epoch milliseconds.

WITH authentications AS (
    SELECT
        time,
        time_dt,
        cloud.provider AS provider,
        src_endpoint.ip AS source_ip,
        unmapped.federation_subject AS federation_subject,
        unmapped.token_issuer AS token_issuer,
        unmapped.token_audience AS token_audience,
        unmapped.target_role AS target_role,
        session.uid AS session_uid
    FROM ocsf_events
    WHERE class_uid = 3002
      AND status_id = 1
      AND unmapped.federation_subject IS NOT NULL
      AND src_endpoint.ip IS NOT NULL
),
privileged_activity AS (
    SELECT
        time,
        cloud.provider AS provider,
        src_endpoint.ip AS source_ip,
        unmapped.federation_subject AS federation_subject,
        unmapped.target_role AS target_role,
        session.uid AS session_uid,
        api.operation AS operation
    FROM ocsf_events
    WHERE class_uid = 6003
      AND status_id = 1
      AND api.operation IN (
          'SecretGet',
          'GetSecretValue',
          'SetIamPolicy',
          'AttachRolePolicy'
      )
),
-- Every authentication can anchor a rolling 15-minute event-time window.
auth_windows AS (
    SELECT
        anchor.federation_subject,
        anchor.source_ip,
        anchor.time AS first_seen,
        MIN(observed.time) FILTER (
            WHERE observed.provider <> anchor.provider
        ) AS multi_cloud_time,
        MAX(observed.time) AS last_auth_seen,
        COUNT(DISTINCT observed.provider) AS provider_count,
        COUNT(DISTINCT CASE
            WHEN observed.provider IN ('AWS', 'GCP') THEN observed.provider
        END) AS approved_release_provider_count,
        SUM(CASE
            WHEN observed.provider IS NULL OR observed.provider NOT IN ('AWS', 'GCP')
            THEN 1 ELSE 0
        END) AS unexpected_release_provider_count,
        COUNT(DISTINCT observed.target_role) AS auth_target_role_count,
        COUNT(DISTINCT CASE
            WHEN observed.target_role IN ('ReleaseDeployer', 'release-deployer')
            THEN observed.target_role
        END) AS approved_release_auth_role_count,
        SUM(CASE
            WHEN observed.target_role IS NULL
              OR observed.target_role NOT IN ('ReleaseDeployer', 'release-deployer')
            THEN 1 ELSE 0
        END) AS unexpected_release_auth_role_count,
        COUNT(DISTINCT CASE
            WHEN (observed.provider = 'AWS' AND observed.target_role = 'ReleaseDeployer')
              OR (observed.provider = 'GCP' AND observed.target_role = 'release-deployer')
            THEN CONCAT(observed.provider, ':', observed.target_role)
        END) AS approved_release_provider_role_pair_count,
        SUM(CASE
            WHEN (observed.provider = 'AWS' AND observed.target_role = 'ReleaseDeployer')
              OR (observed.provider = 'GCP' AND observed.target_role = 'release-deployer')
            THEN 0 ELSE 1
        END) AS unexpected_release_provider_role_pair_count,
        COUNT(DISTINCT observed.token_issuer) AS issuer_count,
        COUNT(DISTINCT CASE
            WHEN observed.token_issuer = 'https://token.actions.example.test'
            THEN observed.token_issuer
        END) AS approved_release_issuer_count,
        SUM(CASE
            WHEN observed.token_issuer IS NULL
              OR observed.token_issuer <> 'https://token.actions.example.test'
            THEN 1 ELSE 0
        END) AS unexpected_release_issuer_count,
        COUNT(DISTINCT observed.token_audience) AS audience_count,
        COUNT(DISTINCT CASE
            WHEN observed.token_audience IN (
                'sts.amazonaws.com',
                '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/ci/providers/actions'
            ) THEN observed.token_audience
        END) AS approved_release_audience_count,
        SUM(CASE
            WHEN observed.token_audience IS NULL
              OR observed.token_audience NOT IN (
                  'sts.amazonaws.com',
                  '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/ci/providers/actions'
              )
            THEN 1 ELSE 0
        END) AS unexpected_release_audience_count
    FROM authentications anchor
    JOIN authentications observed
      ON observed.federation_subject = anchor.federation_subject
     AND observed.source_ip = anchor.source_ip
     AND observed.time BETWEEN anchor.time AND anchor.time + (15 * 60 * 1000)
    GROUP BY anchor.federation_subject, anchor.source_ip, anchor.time
),
-- Privileged activity must occur after the second provider is observed.
candidate_alerts AS (
    SELECT
        window.*,
        COUNT(DISTINCT activity.operation) AS privileged_action_count,
        COUNT(DISTINCT CASE
            WHEN activity.operation = 'GetSecretValue' THEN activity.operation
        END) AS approved_release_operation_count,
        SUM(CASE
            WHEN activity.operation IS NULL OR activity.operation <> 'GetSecretValue'
            THEN 1 ELSE 0
        END) AS unexpected_release_operation_count,
        SUM(CASE
            WHEN (activity.provider = 'AWS' AND activity.target_role = 'ReleaseDeployer')
              OR (activity.provider = 'GCP' AND activity.target_role = 'release-deployer')
            THEN 0 ELSE 1
        END) AS unexpected_release_api_role_count
    FROM auth_windows window
    JOIN privileged_activity activity
      ON activity.federation_subject = window.federation_subject
     AND activity.source_ip = window.source_ip
     AND activity.time BETWEEN window.multi_cloud_time
                           AND window.first_seen + (15 * 60 * 1000)
    WHERE window.provider_count >= 2
      AND window.multi_cloud_time IS NOT NULL
    GROUP BY
        window.federation_subject,
        window.source_ip,
        window.first_seen,
        window.multi_cloud_time,
        window.last_auth_seen,
        window.provider_count,
        window.approved_release_provider_count,
        window.unexpected_release_provider_count,
        window.auth_target_role_count,
        window.approved_release_auth_role_count,
        window.unexpected_release_auth_role_count,
        window.approved_release_provider_role_pair_count,
        window.unexpected_release_provider_role_pair_count,
        window.issuer_count,
        window.approved_release_issuer_count,
        window.unexpected_release_issuer_count,
        window.audience_count,
        window.approved_release_audience_count,
        window.unexpected_release_audience_count
)
SELECT *
FROM candidate_alerts
WHERE privileged_action_count >= 1
  AND NOT (
      federation_subject = 'repo:northstar-robotics/agent-deploy:ref:refs/heads/main'
      AND source_ip = '192.0.2.25'
      AND provider_count = 2
      AND approved_release_provider_count = 2
      AND unexpected_release_provider_count = 0
      AND auth_target_role_count = 2
      AND approved_release_auth_role_count = 2
      AND unexpected_release_auth_role_count = 0
      AND approved_release_provider_role_pair_count = 2
      AND unexpected_release_provider_role_pair_count = 0
      AND issuer_count = 1
      AND approved_release_issuer_count = 1
      AND unexpected_release_issuer_count = 0
      AND audience_count = 2
      AND approved_release_audience_count = 2
      AND unexpected_release_audience_count = 0
      AND privileged_action_count = 1
      AND approved_release_operation_count = 1
      AND unexpected_release_operation_count = 0
      AND unexpected_release_api_role_count = 0
  )
ORDER BY first_seen;

-- Production tuning candidates:
-- 1. De-duplicate overlapping anchor windows into one incident per subject/source.
-- 2. Materialize approved baselines in governed tables rather than hard-coding them.
-- 3. Compare exact observed sets, including NULL/missing-value handling and API actor roles.
-- 4. Add first-seen subject/provider and target-role rarity.
-- 5. Detect role-accepting API calls and their role parameters; iam:PassRole is
--    a permission check, not normally a standalone API event.
-- 6. Add an alternate path when source IP is missing or represents a shared proxy.

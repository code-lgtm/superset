# Security review — `superset/daos`

Scope: `superset/daos/**` on branch `master` of `code-lgtm/superset`, plus the direct
callers needed to establish reachability (REST APIs, commands, MCP list tools, DAO
`base_filter` classes, `superset/security/manager.py`). Reviewed against the role and
capability matrix in [`SECURITY.md`](SECURITY.md).

## Executive summary

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 1 |

- **1 medium** access-control finding: an embedded guest token's dashboard listing was
  widened by ordinary role/dataset-based access, so a guest could enumerate dashboards
  outside the token it was issued for. Fixed with a regression test.
- **1 low** parent-scoping defect inside the reviewed subtree
  (`DatasetDAO.find_dataset_metric`): a metric was fetched by id alone, without being
  constrained to its parent dataset. Not exploitable below the Admin role today, so it is
  reported as low/defence-in-depth and fixed with a regression test.
- No injection, deserialization, SSRF, path-traversal, weak-crypto or secret-handling
  issue was found in the DAO layer. No real credentials are committed.
- Dependency audit found 5 advisories in 4 pinned packages, none reachable from the
  reviewed subtree; no dependency change is made here.

Fix pull requests:

| Finding | PR |
| --- | --- |
| 1 — embedded guest dashboard scoping | https://github.com/code-lgtm/superset/pull/5 |
| 2 — dataset metric parent scoping | https://github.com/code-lgtm/superset/pull/6 |

---

## Findings

### 1. Embedded guest token could enumerate dashboards outside its token — Medium, high confidence

- **File/line:** `superset/dashboards/filters.py:123-197` (`DashboardAccessFilter`, the
  `base_filter` of `DashboardDAO` in `superset/daos/dashboard.py:84`).
- **Attacker principal:** Embedded guest token.
- **`SECURITY.md` capability row violated:** *Embedded guest token* — "data sources
  reachable through the embedded dashboards the token authorizes"; the in-scope example
  "an embedded guest token authorizes actions outside the dashboard it was issued for".
- **Attacker-controlled input source:** an embedded guest token (issued for dashboard set
  *S*) presented to any route whose query passes through `DashboardDAO`'s base filter,
  e.g. `GET /api/v1/dashboard/`.
- **Sink:** the `or_(...)` predicate list built in `DashboardAccessFilter._apply_viewers`.
- **Root cause:** the guest-token condition was appended to the same `or_()` as the
  editor, viewer and "no-viewer → dataset access" conditions. A guest carries the roles
  embedded in its token (commonly `Public`/`Gamma`-like with datasource grants), so branch
  (C) matched every *published* dashboard whose datasets those roles can access, and the
  union widened the guest's result set beyond *S*. `ChartFilter`
  (`superset/charts/filters.py:113`) already had the correct fail-closed shape, so the
  dashboard path had diverged.
- **Concrete impact:** dashboard metadata enumeration (ids, uuids, slugs, titles,
  published state, owner/creator names, thumbnails) for dashboards the token does not
  authorize. Fetching a specific non-authorized dashboard remains blocked by
  `security_manager.raise_for_access(dashboard=...)`
  (`superset/security/manager.py:4286-4293`), which is why this is medium and not high:
  the leak is metadata/enumeration, not dashboard contents or data.
- **Remediation (applied):** return the guest scoping as the *sole* predicate before any
  role-based widening, mirroring `ChartFilter`:

  ```python
  def apply(self, query: Query, value: Any) -> Query:
      if (guest_condition := guest_embedded_dashboard_filter()) is not None:
          return query.filter(guest_condition)
      if security_manager.is_admin():
          return query
      return self._apply_viewers(query)
  ```

  `guest_embedded_dashboard_filter()` returns a deny-all clause for a token with no
  dashboard resources, so the guest path fails closed. The same helper was hardened to
  route only numeric ids to the integer id column (`superset/utils/filters.py:81`); a
  non-uuid, non-numeric token id now denies instead of being bound to
  `dashboards.id`.
- **Validation:** validated by unit test — `pytest tests/unit_tests/subjects/test_filters.py -k
  guest_to_token` fails on the pre-fix code (the role path is taken) and passes after.
  Not validated end-to-end against a running instance with a signed guest token.

### 2. `DatasetDAO.find_dataset_metric` was not scoped to its parent dataset — Low, high confidence

- **File/line:** `superset/daos/dataset.py:627-639`.
- **Attacker principal:** none below Admin (see impact); reported as a scoping defect.
- **`SECURITY.md` row:** *Admin* is a trusted principal, so no matrix row is violated
  today — this is filed as defence-in-depth, not a vulnerability.
- **Input source / sink:** `DELETE /api/v1/dataset/<pk>/metric/<metric_id>`
  (`superset/datasets/metrics/api.py:48-93`, `@protect()` + `permission_name("delete")`) passes both
  path parameters to `DeleteDatasetMetricCommand`
  (`superset/commands/dataset/metrics/delete.py:50`), which resolved the metric with
  `db.session.query(SqlMetric).get(metric_id)` — the `pk` was only used to check that
  *some* dataset with that id is visible.
- **Why it is not exploitable below Admin:** the command then calls
  `security_manager.raise_for_editorship(metric)`. `SqlMetric` has no `editors`
  relationship (`superset/connectors/sqla/models.py:1197-1240`; only `SqlaTable` has one
  at line 1375), so for a non-Admin `is_editor()` resolves an empty editor set and the
  request is rejected. Only Admin (a trusted principal) or a deployment-configured
  `EXTRA_EDITORS_RESOLVER` (operator boundary) reaches the delete. The sibling
  `find_dataset_column` was already correctly scoped, which is what made the asymmetry
  worth fixing rather than dismissing.
- **Remediation (applied):** filter on `SqlMetric.table_id == dataset_id` as
  `find_dataset_column` does.
- **Validation:** unit test `tests/unit_tests/dao/dataset_test.py -k find_dataset_metric`
  fails before the fix, passes after.

---

## Dependency review

Resolved from `requirements/base.txt` (fully pinned; a lock file is present and no
floating version, `latest`, or unbounded `>=` pin was found). Audit run with `pip-audit`
against the pinned set (`--no-deps`, because the pinned `numpy` build is unavailable for
the interpreter used for resolution).

| Package | Resolved | Advisory | Severity | Fixed in | Direct? | Reachable from reviewed scope? |
| --- | --- | --- | --- | --- | --- | --- |
| flask | 2.3.3 | PYSEC-2026-2151 / CVE-2026-27205 / GHSA-68rp-wp8r-4726 | Low (CVSS 3.1 AV:N/UI:R, C:L) | 3.1.3 | direct | No. Missing `Vary: Cookie` on some session-touching responses; a caching concern at the framework/deployment layer, not the DAO layer. |
| cryptography | 49.0.0 | PYSEC-2026-3552 / CVE-2026-69247 | Medium (CVSS 4.0 AC:H/AT:P) | 50.0.0 | direct | No. Bleichenbacher oracle in PKCS#7 `EnvelopedData` decryption; Superset does not decrypt attacker-supplied PKCS#7 EnvelopedData in the reviewed paths. |
| paramiko | 3.5.1 | PYSEC-2026-2858 / CVE-2026-44405 | Low (CVSS 3.1 AV:A/AC:H) | no fixed release listed | direct | No. SHA-1 permitted in `rsakey.py`; only relevant to SSH-tunnel connections, adjacent-network attacker. |
| setuptools | 80.9.0 | PYSEC-2026-3447 / CVE-2026-59890 | Medium (CVSS 3.1 AV:L/UI:R) | 83.0.0 | build-time | No. `MANIFEST.in` exclusion bypass on APFS/HFS+ during packaging; build-time only. |

No advisory is reachable from `superset/daos`, so per the playbook no dependency bump is
included with these code fixes. Recommended separately, in their own PRs: `flask` →
3.1.3, `cryptography` → 50.0.0, `setuptools` → 83.0.0 (build).

**Discouraged/obsolete libraries:** none newly introduced in the reviewed subtree. No
typosquat-looking names or packages with install scripts were added recently in the
manifests covering this scope.

## Secret scan

`gitleaks` (no-git, redacted) over the working tree: 55 matches
(`generic-api-key` 30, `curl-auth-header` 13, `private-key` 12). All were inspected and
classified; **no real credential is committed**:

- Test fixtures and unit tests (e.g. `tests/unit_tests/databases/api_test.py`,
  `tests/unit_tests/db_engine_specs/test_snowflake.py`,
  `tests/integration_tests/fixtures/importexport.py`) — synthetic passwords/keys.
- Documentation and example config (`superset/mcp_service/PRODUCTION.md`, `docs/**`,
  `superset/db_engine_specs/README.md`) — placeholder tokens in `curl` examples.
- Public client-side config (`docs/docusaurus.config.ts`) — search API key intended to be
  public.
- Redacted/sample values echoed in MCP tool docstrings
  (`superset/mcp_service/**/get_*_info.py`).
- A few hits are in untracked `__pycache__/*.pyc` byte-compiled copies of the above.

Git history was not scanned (out of scope for this review). No rotation is required and no
secret is reproduced here.

## Attack surface map (reviewed scope)

- **DAO files reviewed:** `base.py`, `annotation_layer.py`, `chart.py`, `css.py`,
  `dashboard.py`, `database.py`, `dataset.py`, `datasource.py`, `group.py`, `key_value.py`,
  `log.py`, `query.py`, `report.py`, `role.py`, `security.py`, `semantic_layer.py`,
  `subject.py`, `tag.py`, `tasks.py`, `theme.py`, `user.py`, `version.py`.
- **Entry points reaching them:** FAB REST APIs (`@protect()`), legacy views
  (`@has_access`/`@has_access_api`), command classes under `superset/commands/**`, MCP
  tools under `superset/mcp_service/**`, and async/celery report + task paths.
- **Sensitive sinks in scope:** SQLAlchemy query construction (no raw SQL, no string
  interpolation into SQL anywhere under `superset/daos`), `setattr`-based generic
  create/update (mass assignment), `base_filter`/`raise_for_access`/`raise_for_editorship`
  authorization gates, key-value codec decode, JSON dashboard-metadata mutation.
- **Not present in the subtree:** shell execution, outbound HTTP, filesystem/archive
  handling, template rendering, `pickle`/`yaml.load`, XML parsing.

## Considered and dismissed

| Candidate | Why dismissed |
| --- | --- |
| `BaseDAO.apply_column_operators` accepts any model attribute as a filter column, including `Database.password`, `sqlalchemy_uri`, `encrypted_extra`, `server_cert` (`superset/daos/base.py:594-642`) | Not reachable with an attacker-chosen column. Every list caller constrains `col` with a Pydantic `Literal` allowlist (e.g. `DatabaseFilter` allows only `database_name`, `expose_in_sqllab`, `allow_file_upload`), and the JSON-string form is coerced through the same models by `parse_json_or_model_list` (`superset/mcp_service/common/pagination_schemas.py:113-122`), so the `Literal` still applies. `list_databases` additionally requires `user_can_view_data_model_metadata()`. FAB REST APIs use their own `search_columns` allowlists and never call this method. |
| Generic `setattr` loop in DAO `create`/`update` (mass assignment) | Attribute sets originate from Marshmallow/Pydantic schemas at the route boundary, not from raw request bodies. |
| `TagDAO.delete_tagged_object` checks the truthiness of a `Query` object instead of a row (`superset/daos/tag.py`) | Real defect, no security impact: `.one()` raises for a missing row, and tag authorization is route-level plus base filters, which `SECURITY.md`/`AGENTS.md` state is the intended pattern for tags. Not an authorization bypass. |
| `KeyValueDAO.get_value` decodes stored values with a caller-supplied codec | The codec is chosen by Superset code per resource, not by the request; codec selection is an operator/deployment concern per `SECURITY.md`. No path found where an unprivileged principal both picks a dangerous codec and controls the stored bytes. |
| `DashboardDAO.set_dash_metadata` uses `skip_visibility_filter` when resolving charts | Used only to resolve/assign soft-deleted charts inside an already-authorized dashboard edit; the dashboard itself passed `base_filter` + `raise_for_editorship`. |
| `LogDAO.get_recent_activity` (`superset/daos/log.py`) | Always constrained to `get_user_id()`; pagination clamped; ORM-composed, no injection. |
| `DatasetDAO.get_rls_filters_for_datasets` returns RLS clauses/roles | Reached only from `@protect()`ed dataset endpoints; RLS is in the "route-level authorization plus base filters" class per `AGENTS.md`. |
| `LIKE` filters in `BaseDAO` | `_escape_like` escapes `\`, `%`, `_` and passes `escape="\\"`; parameterized throughout — no injection or unbounded wildcard abuse. |
| Missing `raise_for_access` on tags, reports, CSS templates, annotation layers, RLS DAOs | By design for these resource classes per `SECURITY.md`/`AGENTS.md`; not a finding. |
| Admin-only capabilities encountered (e.g. `raise_for_editorship` admin bypass) | Admin is a trusted principal per trust boundary 1. |

## Out of scope / not validated

- Git history secret scanning, frontend code (`superset-frontend/**`), and the npm
  dependency tree were not reviewed.
- No runtime/HTTP reproduction was performed: no Superset instance, metadata database, or
  signed guest token was available in this environment. Both findings are validated at the
  unit level (each test fails before its fix and passes after).
- `pip-audit` could not resolve the full transitive graph in this environment (the pinned
  `numpy` has no distribution for the interpreter used for resolution); the audit above is
  over the pinned direct set only, so transitive-only advisories may be missed.
- Non-DAO areas were read only as far as needed to judge reachability; no claim is made
  about their overall security posture.

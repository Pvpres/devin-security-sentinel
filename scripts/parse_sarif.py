"""
SARIF v2.1.0 Parser and Batching Engine for Security Sentinel.

This module provides utilities for processing raw SARIF (Static Analysis Results
Interchange Format) data fetched from the GitHub /analyses endpoint. It extracts
essential vulnerability information and groups high-severity issues for remediation.

Data Flow Simplification:
-------------------------
Raw SARIF files contain extensive metadata, intermediate analysis steps, and verbose
location information. This parser simplifies the data flow by:

1. Extracting only actionable fields (ruleId, severity, file location, source/sink)
2. Collapsing codeFlows to just source and sink locations, removing intermediate steps
3. Filtering out low-severity issues (severity < 7.0) to focus remediation efforts
4. Grouping issues by rule type for batch processing by LLM remediation agents

The output is optimized for LLM context windows, minimizing token usage while
preserving all information necessary for automated code fixes.

SARIF v2.1.0 Compatibility:
---------------------------
This parser handles SARIF files from different CodeQL versions by:
- Using safe dictionary access with fallbacks for optional fields
- Supporting both single-run and multi-run SARIF files
- Handling variations in property naming conventions across versions
"""

from typing import Any


def _extract_physical_location(location: dict[str, Any]) -> dict[str, Any] | None:
    """
    Extract file path and line number from a SARIF location object.

    Args:
        location: A SARIF location object containing physicalLocation data.

    Returns:
        A dictionary with 'file' and 'line' keys, or None if extraction fails.
    """
    physical = location.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})

    file_path = artifact.get("uri")
    line_number = region.get("startLine")

    if file_path is None:
        return None

    return {
        "file": file_path,
        "line": line_number
    }


def _extract_code_flow_endpoints(code_flows: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Extract source and sink from codeFlows, ignoring intermediate steps.

    SARIF codeFlows contain detailed taint tracking information showing how data
    flows from a source (e.g., user input) through various transformations to a
    sink (e.g., SQL query execution). This function extracts only the endpoints
    to minimize token usage while preserving the essential vulnerability context.

    Args:
        code_flows: List of SARIF codeFlow objects.

    Returns:
        A dictionary with 'source' and 'sink' keys containing location strings
        in the format "file:line", or None values if extraction fails.
    """
    source = None
    sink = None

    if not code_flows:
        return {"source": None, "sink": None}

    for code_flow in code_flows:
        thread_flows = code_flow.get("threadFlows", [])
        for thread_flow in thread_flows:
            locations = thread_flow.get("locations", [])
            if not locations:
                continue

            first_location = locations[0].get("location", {})
            first_physical = _extract_physical_location(first_location)
            if first_physical and source is None:
                source = f"{first_physical['file']}:{first_physical['line']}"

            last_location = locations[-1].get("location", {})
            last_physical = _extract_physical_location(last_location)
            if last_physical:
                sink = f"{last_physical['file']}:{last_physical['line']}"

    return {"source": source, "sink": sink}


def _extract_severity(result: dict[str, Any], rules_map: dict[str, dict[str, Any]]) -> float | None:
    """
    Extract security-severity score from result properties or rule metadata.

    The security-severity score can be found in multiple locations within SARIF:
    1. Directly in the result's properties
    2. In the rule definition's properties (via rules_map lookup)
    3. In the rule's defaultConfiguration

    Args:
        result: A SARIF result object.
        rules_map: A dictionary mapping ruleId to rule definitions.

    Returns:
        The security-severity score as a float, or None if not found.
    """
    result_props = result.get("properties", {})
    severity = result_props.get("security-severity")
    if severity is not None:
        try:
            return float(severity)
        except (ValueError, TypeError):
            pass

    rule_id = result.get("ruleId")
    if rule_id and rule_id in rules_map:
        rule = rules_map[rule_id]
        rule_props = rule.get("properties", {})
        severity = rule_props.get("security-severity")
        if severity is not None:
            try:
                return float(severity)
            except (ValueError, TypeError):
                pass

        default_config = rule.get("defaultConfiguration", {})
        level = default_config.get("level")
        if level == "error":
            return 8.0
        elif level == "warning":
            return 5.0
        elif level == "note":
            return 3.0

    return None


def _build_rules_map(runs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Build a mapping from ruleId to rule definition across all runs.

    Args:
        runs: List of SARIF run objects.

    Returns:
        A dictionary mapping ruleId strings to their full rule definitions.
    """
    rules_map: dict[str, dict[str, Any]] = {}

    for run in runs:
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        rules = driver.get("rules", [])

        for rule in rules:
            rule_id = rule.get("id")
            if rule_id:
                rules_map[rule_id] = rule

        extensions = tool.get("extensions", [])
        for extension in extensions:
            ext_rules = extension.get("rules", [])
            for rule in ext_rules:
                rule_id = rule.get("id")
                if rule_id:
                    rules_map[rule_id] = rule

    return rules_map


def minify_sarif(raw_data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract essential fields from raw SARIF v2.1.0 data for LLM processing.

    This function transforms verbose SARIF output into a minimal representation
    containing only the fields necessary for vulnerability remediation:

    - Rule Metadata: ruleId and message text for identifying the vulnerability type
    - Severity: The security-severity score for prioritization
    - Target: The physical location (file path and line) of the vulnerability sink
    - Code Flow: Source and sink locations showing data flow endpoints

    The output is optimized for LLM context windows by removing all intermediate
    analysis steps, verbose descriptions, and non-essential metadata.

    Args:
        raw_data: Raw SARIF v2.1.0 data as a dictionary. Expected to contain
                  a 'runs' array with results from static analysis.

    Returns:
        A list of minified result dictionaries, each containing:
        - ruleId: The identifier of the triggered rule (e.g., "js/sql-injection")
        - message: The human-readable vulnerability description
        - severity: The security-severity score (0.0-10.0 scale)
        - target: Dict with 'file' and 'line' of the vulnerability location
        - source: Location string of the taint source (format: "file:line")
        - sink: Location string of the taint sink (format: "file:line")

    Example:
        >>> raw = {"runs": [{"results": [...], "tool": {...}}]}
        >>> minified = minify_sarif(raw)
        >>> print(minified[0])
        {
            "ruleId": "js/sql-injection",
            "message": "Query built from user input",
            "severity": 9.8,
            "target": {"file": "db.js", "line": 42},
            "source": "api.js:10",
            "sink": "db.js:42"
        }
    """
    minified_results: list[dict[str, Any]] = []

    runs = raw_data.get("runs", [])
    if not runs:
        return minified_results

    rules_map = _build_rules_map(runs)

    for run in runs:
        results = run.get("results", [])

        for result in results:
            rule_id = result.get("ruleId")
            message = result.get("message", {})
            message_text = message.get("text", "")

            severity = _extract_severity(result, rules_map)

            target = None
            locations = result.get("locations", [])
            if locations:
                target = _extract_physical_location(locations[0])

            code_flows = result.get("codeFlows", [])
            flow_endpoints = _extract_code_flow_endpoints(code_flows)

            minified_result = {
                "ruleId": rule_id,
                "message": message_text,
                "severity": severity,
                "target": target,
                "source": flow_endpoints["source"],
                "sink": flow_endpoints["sink"]
            }

            minified_results.append(minified_result)

    return minified_results


def _normalize_path(path: str | None) -> str:
    """
    Normalize file path for consistent matching between alerts and SARIF results.

    Removes leading './' or '/' characters to ensure paths from different sources
    can be compared reliably.

    Args:
        path: A file path string, or None.

    Returns:
        Normalized path string, or empty string if path is None.
    """
    if path is None:
        return ""
    return path.lstrip("./").lstrip("/")


def build_active_alert_index(
    alerts: list[dict[str, Any]]
) -> dict[tuple[str, str, int], int]:
    """
    Build an index mapping (rule_id, file, line) to alert_number.

    This function creates a lookup table from GitHub Code Scanning alerts that
    enables efficient filtering of SARIF results to only those matching active
    alerts. The composite key (rule_id, normalized_file, line) uniquely identifies
    each vulnerability location.

    Args:
        alerts: List of alerts from GitHubClient.get_active_alerts(). Each alert
                should contain 'number', 'rule.id', and 'most_recent_instance.location'.

    Returns:
        A dictionary mapping (rule_id, normalized_file, line) tuples to alert numbers.
        This index can be passed to minify_sarif_state_aware() for filtering.

    Example:
        >>> alerts = [{"number": 1, "rule": {"id": "py/sql-injection"},
        ...            "most_recent_instance": {"location": {"path": "app.py", "start_line": 42}}}]
        >>> index = build_active_alert_index(alerts)
        >>> print(index)
        {('py/sql-injection', 'app.py', 42): 1}
    """
    index: dict[tuple[str, str, int], int] = {}

    for alert in alerts:
        alert_number = alert.get("number")
        rule_id = alert.get("rule", {}).get("id")
        instance = alert.get("most_recent_instance", {})
        location = instance.get("location", {})
        file_path = _normalize_path(location.get("path"))
        line = location.get("start_line")

        if all([alert_number is not None, rule_id, file_path, line is not None]):
            key = (rule_id, file_path, line)
            index[key] = alert_number

    return index


def minify_sarif_state_aware(
    raw_data: dict[str, Any],
    active_alert_index: dict[tuple[str, str, int], int]
) -> list[dict[str, Any]]:
    """
    Extract essential fields from SARIF, filtering to only active alerts.

    This function extends minify_sarif() by:
    1. Only including results that match an active alert (via the index)
    2. Adding the alert_number to each result for tracking and post-remediation updates

    The state-aware approach ensures that only vulnerabilities that are:
    - Currently open (not fixed or dismissed)
    - Not assigned to another team member
    are processed for remediation.

    Args:
        raw_data: Raw SARIF v2.1.0 data as a dictionary.
        active_alert_index: Index from build_active_alert_index() mapping
                           (rule_id, file, line) tuples to alert numbers.

    Returns:
        A list of minified result dictionaries, each containing:
        - alert_number: The GitHub alert number for tracking
        - ruleId: The identifier of the triggered rule
        - message: The human-readable vulnerability description
        - severity: The security-severity score (0.0-10.0 scale)
        - target: Dict with 'file' and 'line' of the vulnerability location
        - source: Location string of the taint source (format: "file:line")
        - sink: Location string of the taint sink (format: "file:line")

    Example:
        >>> alerts = client.get_active_alerts()
        >>> index = build_active_alert_index(alerts)
        >>> sarif = client.get_sarif_data()
        >>> minified = minify_sarif_state_aware(sarif, index)
        >>> print(minified[0])
        {
            "alert_number": 1,
            "ruleId": "py/sql-injection",
            "message": "Query built from user input",
            "severity": 9.8,
            "target": {"file": "db.py", "line": 42},
            "source": "api.py:10",
            "sink": "db.py:42"
        }
    """
    minified_results: list[dict[str, Any]] = []

    runs = raw_data.get("runs", [])
    if not runs:
        return minified_results

    rules_map = _build_rules_map(runs)

    for run in runs:
        results = run.get("results", [])

        for result in results:
            rule_id = result.get("ruleId")

            target = None
            locations = result.get("locations", [])
            if locations:
                target = _extract_physical_location(locations[0])

            if target is None:
                continue

            file_path = _normalize_path(target.get("file"))
            line = target.get("line")
            key = (rule_id, file_path, line)

            if key not in active_alert_index:
                continue

            alert_number = active_alert_index[key]

            message = result.get("message", {})
            message_text = message.get("text", "")
            severity = _extract_severity(result, rules_map)
            code_flows = result.get("codeFlows", [])
            flow_endpoints = _extract_code_flow_endpoints(code_flows)

            minified_result = {
                "alert_number": alert_number,
                "ruleId": rule_id,
                "message": message_text,
                "severity": severity,
                "target": target,
                "source": flow_endpoints["source"],
                "sink": flow_endpoints["sink"]
            }

            minified_results.append(minified_result)

    return minified_results


def get_remediation_batches_state_aware(
    minified_data: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """
    Create remediation batches with alert tracking from state-aware minified data.

    This function processes minified SARIF data (from minify_sarif_state_aware)
    to create remediation batches that include alert numbers for each task.
    This enables post-remediation alert updates via the GitHub API.

    Args:
        minified_data: List of minified result dictionaries from minify_sarif_state_aware().
                       Each dict should contain 'alert_number', 'ruleId', 'severity',
                       'target', and 'source' fields.

    Returns:
        A dictionary where:
        - Keys are ruleId strings (e.g., "py/sql-injection")
        - Values are dictionaries containing:
          - severity: The highest severity score among instances of this rule
          - tasks: List of task dictionaries, each with:
            - alert_number: The GitHub alert number for tracking
            - file: Path to the vulnerable file
            - line: Line number of the vulnerability
            - source: Location string of the taint source

    Example:
        >>> minified = minify_sarif_state_aware(sarif, alert_index)
        >>> batches = get_remediation_batches_state_aware(minified)
        >>> print(batches)
        {
            "py/sql-injection": {
                "severity": 9.8,
                "tasks": [
                    {"alert_number": 1, "file": "db.py", "line": 42, "source": "api.py:10"}
                ]
            }
        }
    """
    SEVERITY_THRESHOLD = 7.0

    batches: dict[str, dict[str, Any]] = {}

    for item in minified_data:
        severity = item.get("severity")
        if severity is None or severity < SEVERITY_THRESHOLD:
            continue

        rule_id = item.get("ruleId")
        if rule_id is None:
            continue

        target = item.get("target")
        if target is None:
            continue

        task = {
            "alert_number": item.get("alert_number"),
            "file": target.get("file"),
            "line": target.get("line"),
            "source": item.get("source")
        }

        if rule_id not in batches:
            batches[rule_id] = {
                "severity": severity,
                "tasks": []
            }
        elif severity > batches[rule_id]["severity"]:
            batches[rule_id]["severity"] = severity

        batches[rule_id]["tasks"].append(task)

    return batches


def get_remediation_batches(minified_data: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Filter and batch high-severity vulnerabilities for remediation.

    This function processes minified SARIF data to create remediation batches
    optimized for LLM-driven code fixes. It performs two key operations:

    1. Filtering: Removes vulnerabilities with severity score < 7.0 to focus
       remediation efforts on critical and high-severity issues.

    2. Grouping: Organizes remaining issues by ruleId, allowing batch processing
       of similar vulnerability types. This improves LLM remediation efficiency
       by providing consistent context for each vulnerability category.

    The output structure is designed for minimal token usage while providing
    all necessary context for automated remediation.

    Args:
        minified_data: List of minified result dictionaries from minify_sarif().
                       Each dict should contain 'ruleId', 'severity', 'target',
                       and 'source' fields.

    Returns:
        A dictionary where:
        - Keys are ruleId strings (e.g., "js/sql-injection")
        - Values are dictionaries containing:
          - severity: The highest severity score among instances of this rule
          - tasks: List of task dictionaries, each with:
            - file: Path to the vulnerable file
            - line: Line number of the vulnerability
            - source: Location string of the taint source

    Example:
        >>> minified = [
        ...     {"ruleId": "js/sql-injection", "severity": 9.8,
        ...      "target": {"file": "db.js", "line": 42}, "source": "api.js:10"},
        ...     {"ruleId": "js/sql-injection", "severity": 9.8,
        ...      "target": {"file": "query.js", "line": 15}, "source": "routes.js:5"}
        ... ]
        >>> batches = get_remediation_batches(minified)
        >>> print(batches)
        {
            "js/sql-injection": {
                "severity": 9.8,
                "tasks": [
                    {"file": "db.js", "line": 42, "source": "api.js:10"},
                    {"file": "query.js", "line": 15, "source": "routes.js:5"}
                ]
            }
        }
    """
    SEVERITY_THRESHOLD = 7.0

    batches: dict[str, dict[str, Any]] = {}

    for item in minified_data:
        severity = item.get("severity")
        if severity is None or severity < SEVERITY_THRESHOLD:
            continue

        rule_id = item.get("ruleId")
        if rule_id is None:
            continue

        target = item.get("target")
        if target is None:
            continue

        task = {
            "file": target.get("file"),
            "line": target.get("line"),
            "source": item.get("source")
        }

        if rule_id not in batches:
            batches[rule_id] = {
                "severity": severity,
                "tasks": []
            }
        else:
            if severity > batches[rule_id]["severity"]:
                batches[rule_id]["severity"] = severity

        batches[rule_id]["tasks"].append(task)

    return batches


def extract_dominant_ref(alerts: list[dict[str, Any]]) -> str | None:
    """
    Extract the most common branch ref from a list of alerts.

    When alerts come from multiple branches, this function identifies the dominant
    branch (the one with the most alerts) to ensure SARIF data is fetched from
    the correct analysis context.

    Args:
        alerts: List of alerts from GitHubClient.get_active_alerts(). Each alert
                should contain 'most_recent_instance.ref' indicating its branch.

    Returns:
        The most common ref string (e.g., "refs/heads/main"), or None if no
        valid refs are found in the alerts.

    Example:
        >>> alerts = [
        ...     {"most_recent_instance": {"ref": "refs/heads/main"}},
        ...     {"most_recent_instance": {"ref": "refs/heads/main"}},
        ...     {"most_recent_instance": {"ref": "refs/heads/feature"}}
        ... ]
        >>> extract_dominant_ref(alerts)
        'refs/heads/main'
    """
    if not alerts:
        return None

    ref_counts: dict[str, int] = {}
    for alert in alerts:
        instance = alert.get("most_recent_instance", {})
        ref = instance.get("ref")
        if ref:
            ref_counts[ref] = ref_counts.get(ref, 0) + 1

    if not ref_counts:
        return None

    dominant_ref = max(ref_counts, key=ref_counts.get)
    return dominant_ref

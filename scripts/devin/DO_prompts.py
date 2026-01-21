from typing import Any

"""Module for generating high-density prompts for Sub-Devin workers to remediate GitHub code scanning alerts."""
"""Should be imported and used by the orchestrator script."""
def create_devin_prompt(
    task_description: str,
    batch_data: dict[str, Any],
    batch_id: str,
    owner: str,
    repo: str
) -> str:
    """
    Generate a high-density, XML-formatted prompt for Sub-Devin workers.
    
    The prompt includes:
    - Task description with clear remediation instructions
    - Minified batch data with file paths, line numbers, and code flows
    - Instructions to fix vulnerabilities, run tests, and open a PR
    
    Args:
        task_description: Human-readable description of the vulnerability batch
        batch_data: Minified batch data from get_remediation_batches_state_aware()
                    Format: {severity: float, tasks: [{alert_number, file, line, source}]}
        batch_id: Identifier for the vulnerability batch (typically the ruleId)
        owner: GitHub repository owner
        repo: GitHub repository name
    
    Returns:
        XML-formatted prompt string optimized for Devin AI processing
    """
    tasks = batch_data.get("tasks", [])
    severity = batch_data.get("severity", 0)
    
    vulnerabilities_xml = ""
    for task in tasks:
        vulnerabilities_xml += f"""
    <vulnerability>
      <rule>{batch_id}</rule>
      <file>{task.get('file', 'unknown')}</file>
      <line>{task.get('line', 'unknown')}</line>
      <source>{task.get('source', 'N/A')}</source>
      <alert_number>{task.get('alert_number', 'N/A')}</alert_number>
    </vulnerability>"""

    prompt = f"""<security_remediation_task>
  <metadata>
    <batch_id>{batch_id}</batch_id>
    <repository>{owner}/{repo}</repository>
    <task_type>vulnerability_remediation</task_type>
  </metadata>

  <description>
    {task_description}
  </description>

  <vulnerabilities>{vulnerabilities_xml}
  </vulnerabilities>

  <instructions>
    <step>1. Clone the repository {owner}/{repo} if not already available</step>
    <step>2. Analyze each vulnerability location listed above</step>
    <step>3. Implement secure fixes for all vulnerabilities in this batch</step>
    <step>4. Ensure fixes follow security best practices (input validation, parameterized queries, etc.)</step>
    <step>5. Run all existing tests to verify fixes don't break functionality</step>
    <step>6. Create a new branch named 'security-fix/{batch_id}'</step>
    <step>7. Commit all changes with descriptive commit messages</step>
    <step>8. Open a GitHub Pull Request with title: 'Security Fix: {batch_id}'</step>
    <step>9. Include a summary of all fixes in the PR description</step>
  </instructions>

  <requirements>
    <requirement>All vulnerabilities in this batch must be addressed</requirement>
    <requirement>Tests must pass after fixes are applied</requirement>
    <requirement>PR must be created and ready for review</requirement>
  </requirements>
</security_remediation_task>"""

    return prompt
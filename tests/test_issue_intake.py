from pathlib import Path
import unittest


CONFIG = Path(__file__).parents[1] / ".github" / "ISSUE_TEMPLATE" / "config.yml"


class IssueIntakeConfigTests(unittest.TestCase):
    def test_external_contributors_are_routed_to_the_structured_form(self) -> None:
        self.assertEqual(CONFIG.read_text(encoding="utf-8"), "blank_issues_enabled: false\n")


if __name__ == "__main__":
    unittest.main()

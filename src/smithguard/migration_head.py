"""The one Python home of the expected migration head.

Kept in a module with no dependencies so maintenance tools that must stay light
can import it without loading the ORM.
"""

EXPECTED_MIGRATION = "0035_bulletin_automation"

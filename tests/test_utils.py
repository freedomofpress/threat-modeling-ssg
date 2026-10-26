import pytest

from ratm.ssg.utils import requirement_parts


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("is_exposed", [("is exposed", "property_is_exposed.html")]),
        (
            "!loads_resources.deps",
            [("not loads resources.deps", "property_loads_resources.html")],
        ),
        (
            "!reads_input | is_exposed",
            [
                ("not reads input", "property_reads_input.html"),
                ("or", None),
                ("is exposed", "property_is_exposed.html"),
            ],
        ),
        (
            "requires_credentials != uses_strong_credentials",
            [
                ("requires credentials", "property_requires_credentials.html"),
                ("≠", None),
                ("uses strong credentials", "property_uses_strong_credentials.html"),
            ],
        ),
    ],
)
def test_requirement_parts_link_each_property(token, expected) -> None:
    assert requirement_parts(token) == expected

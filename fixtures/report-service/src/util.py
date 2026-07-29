"""Small helpers shared by the routes."""
import re

TAG_PATTERN = re.compile(r"\A[a-z][a-z0-9_]{0,31}\Z")


def normalise_term(term: str) -> str:
    """Trims a search term and collapses runs of whitespace."""
    return " ".join(term.split())


def known_tag(tag: str) -> str:
    """Returns the tag if it is one, and refuses anything else."""
    if not TAG_PATTERN.fullmatch(tag):
        raise ValueError("not a tag")
    return tag

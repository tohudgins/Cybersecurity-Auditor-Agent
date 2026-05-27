"""Tests for the compliance Q&A streaming path."""
from __future__ import annotations

from auditor.tools.compliance_qa import _NO_DOCS_MSG, stream_compliance_answer


def test_stream_compliance_answer_yields_no_docs_message():
    """With the conftest retrieve stub returning [], the streamer should emit the
    canonical 'no docs' message and stop without hitting the LLM."""
    chunks = list(stream_compliance_answer("What does NIST 800-53 say about AC-2?"))
    assert chunks == [_NO_DOCS_MSG]


def test_stream_compliance_answer_is_a_generator():
    """Ensure the return value is iterable (a generator) so st.write_stream can consume it."""
    result = stream_compliance_answer("anything")
    # Should expose generator semantics, not return a string directly.
    assert hasattr(result, "__iter__")
    assert hasattr(result, "__next__")

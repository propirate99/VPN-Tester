"""
Tests for PCAP parsing and bad PCAP graceful error handling.
"""

import os
import pytest
from analyzer.pcap_reader import read_pcap


def test_missing_pcap_file():
    """Verify that a missing PCAP file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        read_pcap("non_existent_file.pcap")


def test_bad_pcap_graceful_error(tmp_path):
    """Test 5: Bad/corrupt PCAP file raises graceful ValueError."""
    corrupt_file = tmp_path / "corrupt.pcap"
    corrupt_file.write_bytes(b"NOT_A_VALID_PCAP_HEADER_DATA_12345")

    with pytest.raises(ValueError):
        read_pcap(str(corrupt_file))

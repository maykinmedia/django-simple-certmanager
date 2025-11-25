import re

import pytest
from hypothesis import given, strategies as st

from simple_certmanager.utils import pretty_print_serial_number


@pytest.mark.parametrize(
    "serial_number,expected",
    [
        # Single byte, with padding
        (0x0, "00"),
        (0x1, "01"),
        (0xA, "0A"),
        (0xF, "0F"),
        # single byte, no padding
        (0x10, "10"),
        (0xFF, "FF"),
        # Multi-byte with values needing zero padding
        (0x0A0B1C0D0E0F, "0A:0B:1C:0D:0E:0F"),
        (0x010203, "01:02:03"),
        # Multi-byte without zero padding needed (all bytes >= 0x10)
        (0x102030, "10:20:30"),
        (0xABCDEF, "AB:CD:EF"),
        # Typical certificate size (128 bits)
        (
            0x70E229359BC842EBF88CEC05CD5526FEC426D6DF,
            "70:E2:29:35:9B:C8:42:EB:F8:8C:EC:05:CD:55:26:FE:C4:26:D6:DF",
        ),
    ],
)
def test_pretty_print_serial_number(serial_number, expected):
    result = pretty_print_serial_number(serial_number)
    assert result == expected


SERIAL_NUMBER_PATTERN = re.compile(r"[0-9A-F]{2}(?::[0-9A-F]{2})*")
"""Regex pattern for validating colon-separated hex byte pairs"""


@given(st.integers(min_value=0))
def test_pretty_print_result_is_well_formed_and_reversible(serial_number):
    result = pretty_print_serial_number(serial_number)

    reversed_serial_number = int("".join(result.split(":")), base=16)
    assert (
        reversed_serial_number == serial_number
    ), f"Reversed number {reversed_serial_number} does not match input {serial_number}"

    assert SERIAL_NUMBER_PATTERN.match(
        result
    ), f"{result} does not match expected format of colon-separated hex byte pairs"

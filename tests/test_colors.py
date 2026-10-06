import pytest

from pcap_labels import colors


def test_parse_color():
    assert colors.parse_color("pink") == (255, 105, 180)
    assert colors.parse_color("#FF69B4") == (255, 105, 180)
    assert colors.parse_color("ff69b4") == (255, 105, 180)
    with pytest.raises(ValueError):
        colors.parse_color("pinkish")


def test_wireshark_round_trip():
    text = colors.to_wireshark((255, 105, 180)) + colors.to_wireshark((0, 0, 0))
    assert text == "[65535,26985,46260][0,0,0]"
    assert colors.from_wireshark(text) == [(255, 105, 180), (0, 0, 0)]


def test_text_color_contrast():
    assert colors.text_color_for((255, 230, 60)) == (0, 0, 0)
    assert colors.text_color_for((70, 120, 240)) == (255, 255, 255)

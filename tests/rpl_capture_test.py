import unittest
from pathlib import Path

from web.main import (
    analyze_rpl_capture,
    count_inspectable_packets,
    inspect_rpl_capture,
    pcap_link_type,
)


ROOT = Path(__file__).resolve().parents[1]
RPL_CAPTURE = ROOT / "tests" / "fixtures" / "rpl-dio-mc-nsa-optional-tlv-dissector-sample.pcap"
ETHERNET_CAPTURE = ROOT / "test_dpi.pcap"


class RplCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rpl_bytes = RPL_CAPTURE.read_bytes()

    def test_decodes_ieee_802154_rpl_dio_frames(self):
        self.assertEqual(pcap_link_type(self.rpl_bytes), 195)
        self.assertEqual(count_inspectable_packets(self.rpl_bytes), 3)

        flows = inspect_rpl_capture(self.rpl_bytes)
        self.assertEqual(len(flows), 3)
        self.assertEqual([flow["rank"] for flow in flows], [1152, 384, 768])
        self.assertTrue(all(flow["application"] == "RPL DIO" for flow in flows))
        self.assertTrue(all(flow["instance"] == 30 for flow in flows))
        self.assertEqual(flows[0]["source"], "fe80::205:5:5:5")
        self.assertEqual(flows[0]["destination"], "ff02::1a")

    def test_reports_truncated_optional_rpl_options(self):
        report_event = analyze_rpl_capture(self.rpl_bytes)[-1]
        self.assertEqual(report_event["type"], "complete")
        self.assertIn("Truncated RPL Options: 3", report_event["report"])
        self.assertTrue(all(flow["truncated_options"] == 1 for flow in inspect_rpl_capture(self.rpl_bytes)))

    def test_keeps_ethernet_ipv4_tcp_udp_capture_counting(self):
        ethernet_bytes = ETHERNET_CAPTURE.read_bytes()
        self.assertEqual(pcap_link_type(ethernet_bytes), 1)
        self.assertEqual(count_inspectable_packets(ethernet_bytes), 77)


if __name__ == "__main__":
    unittest.main()

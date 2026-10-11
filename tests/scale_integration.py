#!/usr/bin/env python3
import pathlib
import re
import struct
import subprocess
import sys
import tempfile


PACKET_COUNT = 100_000
DOMAINS = (
    "www.youtube.com",
    "www.facebook.com",
    "www.instagram.com",
    "twitter.com",
    "www.netflix.com",
    "github.com",
)


def client_hello(domain):
    name = domain.encode("ascii")
    name_entry = b"\x00" + struct.pack(">H", len(name)) + name
    server_names = struct.pack(">H", len(name_entry)) + name_entry
    sni_extension = struct.pack(">HH", 0, len(server_names)) + server_names
    extensions = struct.pack(">H", len(sni_extension)) + sni_extension
    hello = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack(">H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def make_packet(flow_index, payload):
    source_ip = bytes((192, 168, 1, 10 + flow_index))
    destination_ip = bytes((203, 0, 113, 10 + flow_index))
    ethernet = bytes.fromhex("aabbccddeeff0011223344550800")
    tcp = struct.pack(
        ">HHIIHHHH",
        51000 + flow_index,
        443,
        1,
        0,
        (5 << 12) | 0x18,
        65535,
        0,
        0,
    )
    ip_length = 20 + len(tcp) + len(payload)
    ipv4 = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        ip_length,
        flow_index,
        0x4000,
        64,
        6,
        0,
        source_ip,
        destination_ip,
    )
    return ethernet + ipv4 + tcp + payload


def write_capture(path, packet_count=PACKET_COUNT):
    flows = [make_packet(index, client_hello(domain)) for index, domain in enumerate(DOMAINS)]
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for packet_index in range(packet_count):
            packet = flows[packet_index % len(flows)]
            capture.write(struct.pack("<IIII", 1, packet_index % 1_000_000, len(packet), len(packet)))
            capture.write(packet)


def count_capture_packets(path):
    count = 0
    with path.open("rb") as capture:
        capture.seek(24)
        while header := capture.read(16):
            if len(header) != 16:
                raise AssertionError("truncated PCAP packet header")
            included_length = struct.unpack("<IIII", header)[2]
            packet = capture.read(included_length)
            if len(packet) != included_length:
                raise AssertionError("truncated PCAP packet payload")
            count += 1
    return count


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    engine = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as temporary_directory:
        directory = pathlib.Path(temporary_directory)
        input_path = directory / "scale_input.pcap"
        output_path = directory / "scale_output.pcap"
        write_capture(input_path)

        result = subprocess.run(
            [str(engine), str(input_path), str(output_path), "--lbs", "3", "--fps", "5"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=240,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"engine exited with {result.returncode}\n"
                f"stdout:\n{result.stdout[-4000:]}\n"
                f"stderr:\n{result.stderr[-4000:]}"
            )

        benchmark = re.search(
            r"Benchmark: packets=(\d+) elapsed_seconds=([\d.]+) "
            r"packets_per_second=([\d.]+) fast_path_workers=(\d+)",
            result.stdout,
        )
        if not benchmark:
            raise AssertionError("engine did not emit its benchmark summary")
        packets, elapsed, rate, workers = benchmark.groups()
        require(int(packets) == PACKET_COUNT, benchmark.group(0))
        require(float(elapsed) > 0, "elapsed time must be positive")
        require(float(rate) > 0, "throughput must be positive")
        require(int(workers) == 15, benchmark.group(0))
        require(re.search(r"Classified:\s+6\s", result.stdout), "expected six classified flows")
        require(count_capture_packets(output_path) == PACKET_COUNT, "forwarded PCAP lost packets")

        print(benchmark.group(0))
        print("Scale integration passed: 100000 packets, 6 classified apps, 15 fast-path workers")

        rule_input = directory / "rule_input.pcap"
        write_capture(rule_input, len(DOMAINS))
        rule_cases = (
            (["--block-ip", "192.168.1.10"], "IP blocking"),
            (["--block-app", "YouTube"], "application blocking"),
            (["--block-domain", "*.facebook.com"], "domain wildcard blocking"),
        )
        for index, (rule, description) in enumerate(rule_cases):
            rule_output = directory / f"rule_output_{index}.pcap"
            rule_result = subprocess.run(
                [str(engine), str(rule_input), str(rule_output), "--lbs", "2", "--fps", "2", *rule],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
            require(
                rule_result.returncode == 0,
                f"{description} run failed: {rule_result.stderr[-2000:]}",
            )
            require(
                count_capture_packets(rule_output) == len(DOMAINS) - 1,
                f"{description} did not drop exactly one flow",
            )
        print("Rule integration passed: source IP, app, and wildcard domain blocking")


if __name__ == "__main__":
    main()
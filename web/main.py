import asyncio
import json
import re
import struct
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import LongTable, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

app = FastAPI()
UPLOAD_DIR = Path(tempfile.gettempdir()) / "dpi_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_SIZE_MB = 5
DPI_WORKER_COUNT = 4
PROGRESS_PATTERN = re.compile(r"DPI_PROGRESS completed=(\d+)")


class FlowNote(BaseModel):
    source: str = Field(min_length=1, max_length=128)
    destination: str = Field(min_length=1, max_length=128)
    protocol: str = Field(min_length=1, max_length=8)
    application: str = Field(min_length=1, max_length=64)
    domain: str = Field(default="", max_length=253)
    action: str = Field(min_length=1, max_length=10)
    packets: int = Field(ge=0)
    bytes: int = Field(ge=0)


class ExportNotesRequest(BaseModel):
    capture_name: str = Field(default="Capture", max_length=255)
    report: str = Field(min_length=1, max_length=2_000_000)
    flows: list[FlowNote] = Field(default_factory=list)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def home():
    return Path("web/static/index.html").read_text(encoding="utf-8")


def count_inspectable_packets(capture):
    if len(capture) < 24:
        raise ValueError("Capture is shorter than a PCAP global header.")

    if capture[:4] == b"\xd4\xc3\xb2\xa1":
        byte_order = "<"
    elif capture[:4] == b"\xa1\xb2\xc3\xd4":
        byte_order = ">"
    else:
        raise ValueError("Not a supported classic PCAP file.")

    snaplen = struct.unpack_from(byte_order + "I", capture, 16)[0]
    offset = 24
    count = 0
    while offset < len(capture):
        if len(capture) - offset < 16:
            raise ValueError("Capture contains a truncated packet header.")
        included_length = struct.unpack_from(byte_order + "I", capture, offset + 8)[0]
        if included_length > snaplen or included_length > 65535:
            raise ValueError("Capture contains an invalid packet length.")

        packet_start = offset + 16
        packet_end = packet_start + included_length
        if packet_end > len(capture):
            raise ValueError("Capture contains a truncated packet payload.")
        packet = capture[packet_start:packet_end]

        if len(packet) >= 34 and packet[12:14] == b"\x08\x00":
            ip_start = 14
            ip_header_length = (packet[ip_start] & 0x0F) * 4
            if (packet[ip_start] >> 4) == 4 and ip_header_length >= 20:
                transport_start = ip_start + ip_header_length
                if packet[23] == 6 and len(packet) >= transport_start + 20:
                    tcp_header_length = (packet[transport_start + 12] >> 4) * 4
                    if tcp_header_length >= 20 and len(packet) >= transport_start + tcp_header_length:
                        count += 1
                elif packet[23] == 17 and len(packet) >= transport_start + 8:
                    count += 1

        offset = packet_end

    return count


def sse_event(payload):
    return f"data: {json.dumps(payload, ensure_ascii=True)}\n\n"


def stream_engine(input_path, output_path, total_packets, cleanup_input):
    async def generate_events():
        process = None
        lines = []
        flow_records = []
        started_at = time.perf_counter()
        try:
            engine_candidates = (
                Path("./dpi_engine.exe"),
                Path("./build/Debug/dpi_engine.exe"),
                Path("./build/Release/dpi_engine.exe"),
                Path("./dpi_engine"),
            )
            engine_path = next(
                (candidate for candidate in engine_candidates if candidate.is_file()),
                None,
            )
            if engine_path is None:
                raise FileNotFoundError("DPI engine executable was not found.")

            process = subprocess.Popen(
                [str(engine_path.resolve()), str(input_path), str(output_path)],
                stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
            if process.stdout is None:
                raise RuntimeError("DPI process stdout pipe was not created.")
            started_at = time.perf_counter()
            yield sse_event({
                "type": "start",
                "total_packets": total_packets,
                "workers": DPI_WORKER_COUNT,
            })

            while line := await asyncio.to_thread(process.stdout.readline):
                text = line.decode("utf-8", errors="replace").rstrip()
                if text.startswith("DPI_FLOW\t"):
                    fields = text.split("\t")
                    if len(fields) != 11:
                        raise ValueError("The DPI engine returned a malformed flow record.")
                    flow = {
                        "source": f"{fields[1]}:{int(fields[2])}",
                        "destination": f"{fields[3]}:{int(fields[4])}",
                        "protocol": fields[5],
                        "application": fields[6],
                        "domain": fields[7],
                        "action": fields[8],
                        "packets": int(fields[9]),
                        "bytes": int(fields[10]),
                    }
                    flow_records.append(flow)
                    yield sse_event({"type": "flow", "flow": flow})
                    continue

                lines.append(text)
                yield sse_event({"type": "log", "line": text})

                progress = PROGRESS_PATTERN.search(text)
                if progress:
                    completed = int(progress.group(1))
                    elapsed = max(time.perf_counter() - started_at, 0.000001)
                    yield sse_event({
                        "type": "progress",
                        "completed_packets": completed,
                        "total_packets": total_packets,
                        "elapsed_seconds": elapsed,
                        "packets_per_second": completed / elapsed,
                    })
                elif "All threads started" in text:
                    yield sse_event({"type": "stage", "stage": "workers", "message": "Worker pool online"})
                elif "Starting packet processing" in text:
                    yield sse_event({"type": "stage", "stage": "inspection", "message": "Reading and inspecting packets"})
                elif "Finished reading" in text:
                    yield sse_event({"type": "stage", "stage": "draining", "message": "Capture read complete; draining worker queues"})

            return_code = await asyncio.to_thread(process.wait)
            report = "\n".join(lines)
            if return_code != 0:
                details = next((line for line in reversed(lines) if line.strip()), "Engine exited without a report.")
                yield sse_event({"type": "error", "message": details})
                return

            benchmark = re.search(r"Benchmark: packets=(\d+).*?elapsed_seconds=([\d.]+).*?packets_per_second=([\d.]+).*?fast_path_workers=(\d+)", report)
            yield sse_event({
                "type": "complete",
                "report": report,
                "packets": int(benchmark.group(1)) if benchmark else total_packets,
                "elapsed_seconds": float(benchmark.group(2)) if benchmark else time.perf_counter() - started_at,
                "packets_per_second": float(benchmark.group(3)) if benchmark else 0,
                "workers": int(benchmark.group(4)) if benchmark else DPI_WORKER_COUNT,
                "flow_count": len(flow_records),
            })
        except OSError as error:
            details = str(error).strip() or type(error).__name__
            yield sse_event({
                "type": "error",
                "message": f"The DPI process could not launch: {details}. Build the Windows CMake target or run the Docker/Linux demo.",
            })
        except Exception as error:
            details = str(error).strip() or type(error).__name__
            yield sse_event({"type": "error", "message": details})
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                await asyncio.to_thread(process.wait)
            if cleanup_input:
                input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)

    return StreamingResponse(
        generate_events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/analyze-stream")
async def analyze_stream(file: UploadFile = File(...)):
    contents = await file.read()
    if len(contents) > MAX_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {MAX_SIZE_MB}MB limit")
    try:
        total_packets = count_inspectable_packets(contents)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    if total_packets == 0:
        raise HTTPException(400, "Capture has no supported IPv4 TCP/UDP packets.")

    job_id = str(uuid.uuid4())
    input_path = UPLOAD_DIR / f"{job_id}_in.pcap"
    output_path = UPLOAD_DIR / f"{job_id}_out.pcap"
    input_path.write_bytes(contents)
    return stream_engine(input_path, output_path, total_packets, cleanup_input=True)


@app.post("/analyze-sample-stream")
async def analyze_sample_stream():
    input_path = Path("test_dpi.pcap").resolve()
    if not input_path.is_file():
        raise HTTPException(404, "Bundled sample capture is missing.")
    try:
        total_packets = count_inspectable_packets(input_path.read_bytes())
    except ValueError as error:
        raise HTTPException(400, str(error)) from error

    output_path = UPLOAD_DIR / f"{uuid.uuid4()}_sample_out.pcap"
    return stream_engine(input_path, output_path, total_packets, cleanup_input=False)


@app.post("/export-pdf")
def export_pdf(payload: ExportNotesRequest):
    if len(payload.flows) > 100_000:
        raise HTTPException(413, "Flow count exceeds the PDF export limit.")

    palette = {
        "forest": colors.HexColor("#143a31"),
        "green": colors.HexColor("#286b59"),
        "muted": colors.HexColor("#61756a"),
        "line": colors.HexColor("#d8e0d8"),
        "paper": colors.HexColor("#f3f5ef"),
        "drop": colors.HexColor("#bb5539"),
    }
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "NorthlineTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=22, leading=26, textColor=palette["forest"], alignment=0,
        spaceAfter=3,
    )
    eyebrow_style = ParagraphStyle(
        "NorthlineEyebrow", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=8, leading=11, textColor=palette["green"], spaceAfter=5,
    )
    meta_style = ParagraphStyle(
        "NorthlineMeta", parent=styles["Normal"], fontName="Helvetica",
        fontSize=8, leading=11, textColor=palette["muted"],
    )
    section_style = ParagraphStyle(
        "NorthlineSection", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=12, leading=15, textColor=palette["forest"], spaceBefore=14,
        spaceAfter=6,
    )
    summary_style = ParagraphStyle(
        "NorthlineSummary", parent=styles["Normal"], fontName="Helvetica",
        fontSize=8, leading=11, textColor=palette["muted"],
    )
    header_style = ParagraphStyle(
        "NorthlineTableHeader", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=7, leading=9, textColor=colors.white,
    )
    cell_style = ParagraphStyle(
        "NorthlineTableCell", parent=styles["Normal"], fontName="Helvetica",
        fontSize=7, leading=9, textColor=palette["forest"],
    )
    report_style = ParagraphStyle(
        "NorthlineReport", parent=styles["Code"], fontName="Courier",
        fontSize=6.5, leading=8, textColor=palette["forest"],
    )

    def report_value(pattern, fallback="Not reported"):
        match = re.search(pattern, payload.report, re.IGNORECASE)
        return match.group(1) if match else fallback

    metric_values = [
        ("Packets inspected", report_value(r"Total Packets\s*:\s*([\d,]+)")),
        ("Tracked flows", f"{len(payload.flows):,}"),
        ("Classified flows", report_value(r"Classified\s*:\s*([\d,]+)")),
        ("Forwarded", report_value(r"Forwarded\s*:\s*([\d,]+)")),
        ("Dropped", report_value(r"Dropped(?:/Blocked)?\s*:\s*([\d,]+)")),
        ("Processing rate", report_value(r"packets_per_second=([\d.]+)") + " packets/sec"),
    ]

    def metric_card(label, value):
        return Paragraph(
            f'<font size="7" color="{palette["muted"].hexval()}">{escape(label.upper())}</font>'
            f'<br/><font size="14" color="{palette["forest"].hexval()}"><b>{escape(value)}</b></font>',
            summary_style,
        )

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=landscape(A4), rightMargin=14 * mm, leftMargin=14 * mm,
        topMargin=17 * mm, bottomMargin=15 * mm,
        title="Northline Traffic Inspection Notes",
        author="Northline Networks",
    )
    story = [
        Paragraph("NORTHLINE NETWORK SYSTEMS / TRAFFIC INTELLIGENCE", eyebrow_style),
        Paragraph("Inspection notes", title_style),
        Paragraph(
            f"Capture: {escape(payload.capture_name)} &nbsp;&nbsp; / &nbsp;&nbsp; "
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            meta_style,
        ),
        Spacer(1, 10),
    ]

    summary_data = [
        [metric_card(label, value) for label, value in metric_values[:3]],
        [metric_card(label, value) for label, value in metric_values[3:]],
    ]
    summary_table = Table(summary_data, colWidths=[document.width / 3] * 3)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), palette["paper"]),
        ("BOX", (0, 0), (-1, -1), 0.5, palette["line"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, palette["line"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([summary_table, Paragraph("Flow ledger", section_style)])

    flow_data = [[
        Paragraph(label, header_style)
        for label in ("Source", "Destination", "Protocol", "Application", "Domain", "Outcome", "Packets", "Bytes")
    ]]
    for flow in payload.flows:
        outcome_style = ParagraphStyle(
            "FlowOutcome", parent=cell_style,
            textColor=palette["drop"] if flow.action == "DROP" else palette["green"],
        )
        flow_data.append([
            Paragraph(escape(flow.source), cell_style),
            Paragraph(escape(flow.destination), cell_style),
            Paragraph(escape(flow.protocol), cell_style),
            Paragraph(escape(flow.application), cell_style),
            Paragraph(escape(flow.domain or "No host metadata"), cell_style),
            Paragraph(escape(flow.action), outcome_style),
            Paragraph(f"{flow.packets:,}", cell_style),
            Paragraph(f"{flow.bytes:,}", cell_style),
        ])
    if not payload.flows:
        flow_data.append([Paragraph("No flow records were reported.", cell_style)] + [""] * 7)

    flow_table = LongTable(
        flow_data,
        colWidths=[118, 118, 48, 92, 170, 58, 65, document.width - 669],
        repeatRows=1,
        hAlign="LEFT",
    )
    flow_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), palette["forest"]),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, palette["paper"]]),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, palette["green"]),
        ("LINEBELOW", (0, 1), (-1, -1), 0.35, palette["line"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(flow_table)

    report_translation = str.maketrans({
        "╔": "+", "╗": "+", "╚": "+", "╝": "+", "╠": "+", "╣": "+",
        "╦": "+", "╩": "+", "═": "-", "║": "|", "┌": "+", "┐": "+",
        "└": "+", "┘": "+", "─": "-", "│": "|", "├": "+", "┤": "+",
        "┬": "+", "┴": "+", "┼": "+", "×": "x",
    })
    safe_report = payload.report.translate(report_translation).encode("ascii", "replace").decode("ascii")
    story.extend([
        Spacer(1, 8),
        Paragraph("Full engine output", section_style),
        Preformatted(safe_report, report_style),
    ])

    def draw_page(canvas, doc):
        canvas.saveState()
        page_width, _ = landscape(A4)
        canvas.setStrokeColor(palette["line"])
        canvas.line(14 * mm, 11 * mm, page_width - 14 * mm, 11 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(palette["muted"])
        canvas.drawString(14 * mm, 7 * mm, "NORTHLINE / DPI INSPECTION NOTES")
        canvas.drawRightString(page_width - 14 * mm, 7 * mm, f"PAGE {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", payload.capture_name).strip(".-") or "capture"
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}-dpi-notes.pdf"'},
    )


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    # Basic validation — reject anything that isn't a real pcap
    header = await file.read(4)
    if header != b"\xd4\xc3\xb2\xa1" and header != b"\xa1\xb2\xc3\xd4":
        raise HTTPException(400, "Not a valid PCAP file")
    await file.seek(0)

    contents = await file.read()
    if len(contents) > MAX_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {MAX_SIZE_MB}MB limit")

    job_id = str(uuid.uuid4())
    in_path = UPLOAD_DIR / f"{job_id}_in.pcap"
    out_path = UPLOAD_DIR / f"{job_id}_out.pcap"
    in_path.write_bytes(contents)

    try:
        result = subprocess.run(
            ["./dpi_engine", str(in_path), str(out_path)],
            capture_output=True, text=True, timeout=15
        )
    finally:
        in_path.unlink(missing_ok=True)
        out_path.unlink(missing_ok=True)

    return JSONResponse({"report": result.stdout or result.stderr})

@app.post("/analyze-sample")
def analyze_sample():
    result = subprocess.run(
        ["./dpi_engine", "test_dpi.pcap", "/tmp/sample_out.pcap"],
        capture_output=True, text=True, timeout=15
    )
    return JSONResponse({"report": result.stdout or result.stderr})

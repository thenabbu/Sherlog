"""Typer orchestration layer; all analytics remain importable pure functions."""
from __future__ import annotations

import json
import csv
import tempfile
import time
from collections import Counter
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Annotated

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import typer
import yaml
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from sat_sa.detectors import detect_critical_no_escalation, detect_fast_closure, detect_low_critical_asset_coverage_from_counts
from sat_sa.evidence import attach_evidence
from sat_sa.ingestion import FieldMapping, RawTable, normalize, normalize_table
from sat_sa.schema import Flag, SCHEMAS
from sat_sa.scoring import score_entities
from sat_sa.synth import write_synthetic
from sat_sa.runtime import AdaptiveController, RuntimeAdjustment, choose_runtime_settings, settings_dict

app = typer.Typer(help="SAT-SA: offline supervisory analytics for SOC assessments.", no_args_is_help=True)
console = Console()


def _mkdir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


class _ParquetAppender:
    """Write normalized chunks as parquet row groups, retaining no earlier chunks."""

    def __init__(self, path: Path):
        self.path = path
        self.writer: pq.ParquetWriter | None = None

    def write(self, frame: pd.DataFrame) -> None:
        if frame.empty:
            return
        # Optional fields can be entirely null in an early CSV chunk.  Declare
        # those as nullable strings so a later populated chunk keeps one schema.
        frame = frame.copy()
        for column in frame.columns:
            if frame[column].isna().all():
                frame[column] = frame[column].astype("string")
        table = pa.Table.from_pandas(frame, preserve_index=False)
        if self.writer is None:
            self.writer = pq.ParquetWriter(self.path, table.schema, compression="snappy")
        self.writer.write_table(table)

    def close(self) -> None:
        if self.writer:
            self.writer.close()


def _alert_batches(path: Path, batch_size_provider):
    """Yield parquet batches, re-reading the desired size for each row group."""
    source = pq.ParquetFile(path)
    for row_group in range(source.metadata.num_row_groups):
        # A generated row group is itself bounded; changing size here adapts all
        # subsequent row groups without ever accumulating prior alert data.
        for batch in source.iter_batches(batch_size=batch_size_provider(), row_groups=[row_group]):
            yield batch.to_pandas()


def _progress() -> Progress:
    # Rich progress uses Unicode blocks. Avoid failing an air-gapped Windows host
    # configured with a legacy non-UTF console; UTF terminals receive live bars.
    encoding = (getattr(console.file, "encoding", "") or "").lower().replace("-", "")
    return Progress(SpinnerColumn("line"), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), TimeElapsedColumn(), console=console, disable=encoding not in {"utf8", "utf_8"})


def _runtime_line(settings) -> str:
    profile = settings.profile
    return f"Runtime: {profile.logical_cpus} logical CPUs, {profile.available_memory_mb:,} MB RAM available => batch size {settings.batch_size:,}, workers {settings.workers}."


def _show_adjustment(adjustment: RuntimeAdjustment | None) -> None:
    if adjustment:
        cpu = "n/a" if adjustment.cpu_pct is None else f"{adjustment.cpu_pct:.0f}%"
        console.print(f"Adaptive health check: {adjustment.reason}; RAM {adjustment.available_memory_mb:,} MB, CPU {cpu}; batch {adjustment.old_batch_size:,}->{adjustment.new_batch_size:,}, workers {adjustment.old_workers}->{adjustment.new_workers}.")


def _normalize_chunk(chunk: pd.DataFrame, source: str, name: str) -> tuple[pd.DataFrame, list[dict]]:
    """Process-pool safe CSV chunk validation worker."""
    return normalize(RawTable(chunk, source, name), FieldMapping(name))


def _load_flags(path: Path) -> list[Flag]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload["flags"] if isinstance(payload, dict) and "flags" in payload else payload
    return [Flag.model_validate(row) for row in rows]


def _write_flags(path: Path, flags: list[Flag]) -> None:
    _mkdir(path.parent)
    path.write_text(json.dumps([flag.as_json() for flag in flags], indent=2), encoding="utf-8")


@app.command("generate-synth")
def generate_synth(
    entities: Annotated[int, typer.Option(min=4)] = 25,
    alerts_per_entity: Annotated[int, typer.Option(min=1)] = 400,
    seed: int = 42,
    anomaly_rate: Annotated[float, typer.Option(min=0.01, max=1.0)] = .15,
    batch_size: Annotated[int, typer.Option(help="Maximum alert records held per generated batch; 0 chooses from available RAM")] = 0,
    adaptive: Annotated[bool, typer.Option("--adaptive/--no-adaptive", help="Continuously tune batch size from health checks")] = True,
    healthcheck_interval: Annotated[int, typer.Option(min=1, help="Completed batches between adaptive health checks")] = 4,
    out: Path = Path("data/synth"),
) -> None:
    """Stream reproducible synthetic submissions in bounded batches to local files."""
    settings = choose_runtime_settings(batch_size)
    console.print(_runtime_line(settings))
    controller = AdaptiveController(settings, adaptive, healthcheck_interval)
    anomaly_count = max(1, round(entities * anomaly_rate))
    estimated_total = entities * alerts_per_entity + 2 * anomaly_count
    started = time.perf_counter()
    with _progress() as progress:
        task = progress.add_task("Generating alert batches", total=estimated_total)
        last_batch_time = time.perf_counter()
        def generated_batch(count: int) -> int:
            nonlocal last_batch_time
            now = time.perf_counter()
            progress.update(task, advance=count)
            _show_adjustment(controller.after_batch(count, now - last_batch_time))
            last_batch_time = now
            return controller.batch_size
        stats = write_synthetic(out, entities, alerts_per_entity, seed, anomaly_rate, settings.batch_size, generated_batch)
    console.print(f"Generated {stats['entities']} entities and {stats['alerts']:,} alerts in [bold]{out}[/bold] in {time.perf_counter() - started:.1f}s (final batch size {controller.batch_size:,}; adaptive={'on' if adaptive else 'off'}).")


@app.command()
def ingest(
    input: Path = typer.Option(..., exists=True, file_okay=True, dir_okay=True),
    format: Annotated[str, typer.Option(help="csv or json")] = "csv",
    batch_size: Annotated[int, typer.Option(help="CSV rows per batch; 0 chooses from available RAM")] = 0,
    workers: Annotated[int, typer.Option(help="Parallel validation workers; 0 chooses from CPU/RAM")] = 0,
    adaptive: Annotated[bool, typer.Option("--adaptive/--no-adaptive", help="Continuously tune batch admission from health checks")] = True,
    healthcheck_interval: Annotated[int, typer.Option(min=1, help="Completed batches between adaptive health checks")] = 4,
    out: Path = Path("data/normalized"),
) -> None:
    """Validate CSV/JSON submissions into normalized parquet and a reject audit log."""
    if format not in {"csv", "json"}:
        raise typer.BadParameter("format must be csv or json")
    files = [input] if input.is_file() else sorted(input.glob(f"*.{format}"))
    if not files:
        raise typer.BadParameter(f"No .{format} files found in {input}")
    _mkdir(out)
    settings = choose_runtime_settings(batch_size, workers)
    console.print(_runtime_line(settings))
    controller = AdaptiveController(settings, adaptive, healthcheck_interval)
    started = time.perf_counter()
    ingested = set()
    rejected_rows = 0
    reject_path = out / "rejects.json"
    with reject_path.open("w", encoding="utf-8") as reject_file, _progress() as progress:
        reject_file.write("[")
        first_reject = True
        task = progress.add_task("Validating and normalizing input", total=None)

        def record_rejects(rows: list[dict]) -> None:
            nonlocal first_reject, rejected_rows
            for row in rows:
                if not first_reject:
                    reject_file.write(",\n")
                json.dump(row, reject_file, default=str)
                first_reject = False
                rejected_rows += 1

        for source in files:
            name = source.stem
            if name in {"ground_truth", "_ground_truth"}:
                continue
            if name not in SCHEMAS:
                console.print(f"[yellow]Skipping unsupported input table {source.name}[/yellow]")
                continue
            target = out / f"{name}.parquet"
            if target.exists():
                target.unlink()
            appender = _ParquetAppender(target)
            wrote_rows = False
            try:
                if format == "csv":
                    # Chunked CSV parsing is the scalable production ingestion path.
                    pending: list[tuple[int, float, Future]] = []

                    def chunks():
                        # DictReader preserves CSV quoting while the manually
                        # bounded buffer lets the *next* batch use new health
                        # settings. pandas' chunksize is fixed at construction.
                        with source.open("r", encoding="utf-8-sig", newline="") as handle:
                            reader = csv.DictReader(handle)
                            while True:
                                rows = []
                                for _ in range(controller.batch_size):
                                    try:
                                        rows.append(next(reader))
                                    except StopIteration:
                                        break
                                if not rows:
                                    return
                                yield pd.DataFrame.from_records(rows, columns=reader.fieldnames)

                    def consume_next() -> None:
                        nonlocal wrote_rows
                        row_count, submitted_at, future = pending.pop(0)
                        normalized, rejected = future.result()
                        appender.write(normalized); wrote_rows = wrote_rows or not normalized.empty
                        record_rejects(rejected); progress.update(task, advance=row_count, description=f"Ingesting {name}: {progress.tasks[0].completed:,} rows")
                        _show_adjustment(controller.after_batch(row_count, time.perf_counter() - submitted_at))

                    if settings.workers == 1 and not adaptive:
                        for chunk in chunks():
                            pending.append((len(chunk), time.perf_counter(), _ImmediateFuture(_normalize_chunk(chunk, str(source), name))))
                            consume_next()
                    else:
                        # At most ``workers`` chunks are in flight, bounding RAM.
                        with ProcessPoolExecutor(max_workers=4 if adaptive else settings.workers) as executor:
                            for chunk in chunks():
                                pending.append((len(chunk), time.perf_counter(), executor.submit(_normalize_chunk, chunk, str(source), name)))
                                if len(pending) >= controller.workers:
                                    consume_next()
                            while pending:
                                consume_next()
                else:
                    # Standard JSON arrays are loaded by pandas; use CSV/NDJSON exports for giant submissions.
                    normalized, rejected = normalize_table(source, format, name)
                    appender.write(normalized); wrote_rows = not normalized.empty
                    record_rejects(rejected); progress.update(task, advance=len(normalized) + len(rejected), description=f"Ingesting {name}")
            finally:
                appender.close()
            if not wrote_rows:
                pd.DataFrame(columns=list(SCHEMAS[name].model_fields)).to_parquet(target, index=False)
            ingested.add(name)
        reject_file.write("]")
    missing = set(SCHEMAS) - ingested
    if missing:
        raise typer.BadParameter(f"Input submission is missing tables: {sorted(missing)}")
    console.print(f"Normalized {len(ingested)} tables; {rejected_rows:,} rejected rows recorded in {reject_path} in {time.perf_counter() - started:.1f}s (final batch size {controller.batch_size:,}, workers {controller.workers}; adaptive={'on' if adaptive else 'off'}).")


@app.command()
def detect(
    data: Path = typer.Option(..., exists=True, file_okay=False),
    detectors: str = typer.Option("execution_gaps,negative_space"),
    config: Path | None = typer.Option(None, exists=True),
    batch_size: Annotated[int, typer.Option(help="Alerts scanned per batch; 0 chooses from available RAM")] = 0,
    workers: Annotated[int, typer.Option(help="Parallel independent detector workers; 0 chooses from CPU/RAM")] = 0,
    adaptive: Annotated[bool, typer.Option("--adaptive/--no-adaptive", help="Continuously tune batch admission from health checks")] = True,
    healthcheck_interval: Annotated[int, typer.Option(min=1, help="Completed batches between adaptive health checks")] = 4,
    out: Path = Path("results/flags.json"),
) -> None:
    """Run detectors by scanning Arrow/parquet batches, never loading all alerts."""
    selected = {part.strip() for part in detectors.split(",") if part.strip()}
    unknown = selected - {"execution_gaps", "negative_space"}
    if unknown:
        raise typer.BadParameter(f"Unknown detector groups: {sorted(unknown)}")
    settings = {"fast_closure_k": 1.5, "coverage_window_days": 30, "coverage_threshold_pct": .25}
    if config:
        settings.update(yaml.safe_load(config.read_text(encoding="utf-8")) or {})
    settings_runtime = choose_runtime_settings(batch_size, workers)
    console.print(_runtime_line(settings_runtime))
    controller = AdaptiveController(settings_runtime, adaptive, healthcheck_interval)
    alert_path = data / "alerts.parquet"
    entity_path, asset_path = data / "entities.parquet", data / "assets.parquet"
    for required in (alert_path, entity_path, asset_path):
        if not required.exists():
            raise typer.BadParameter(f"Missing required normalized data file: {required}")
    entities = pd.read_parquet(entity_path)
    assets = pd.read_parquet(asset_path).merge(entities[["entity_id", "peer_group"]], on="entity_id", how="left")
    total_rows = pq.ParquetFile(alert_path).metadata.num_rows
    started = time.perf_counter()
    flags: list[Flag] = []
    volumes: Counter[str] = Counter()
    observed: Counter[tuple[str, str]] = Counter()
    reference: pd.Timestamp | None = None
    with tempfile.TemporaryDirectory(prefix="sat_sa_closure_") as temporary:
        temp = Path(temporary)
        duration_paths = {severity: temp / f"{severity}.bin" for severity in ("critical", "high", "medium", "low")}
        # First pass writes only 8-byte closure-duration values to temporary disk.
        with _progress() as progress:
            task = progress.add_task("Pass 1/2: deriving baselines", total=total_rows)
            for batch in _alert_batches(alert_path, lambda: controller.batch_size):
                batch_started = time.perf_counter()
                volumes.update(batch["entity_id"].astype(str))
                created = pd.to_datetime(batch["created_at"], utc=True)
                batch_reference = created.max()
                reference = batch_reference if reference is None or batch_reference > reference else reference
                if "execution_gaps" in selected:
                    closed = pd.to_datetime(batch["closed_at"], utc=True)
                    minutes = (closed - created).dt.total_seconds() / 60
                    for severity, values in minutes.groupby(batch["severity"]):
                        with duration_paths[str(severity)].open("ab") as duration_file:
                            values.dropna().to_numpy(dtype=np.float64).tofile(duration_file)
                progress.update(task, advance=len(batch))
                _show_adjustment(controller.after_batch(len(batch), time.perf_counter() - batch_started))
        baselines = []
        if "execution_gaps" in selected:
            for severity, path in duration_paths.items():
                count = path.stat().st_size // 8 if path.exists() else 0
                if count:
                    values = np.memmap(path, dtype=np.float64, mode="r+", shape=(count,))
                    q1, q3 = np.quantile(values, [.25, .75], overwrite_input=True)
                    baselines.append({"severity": severity, "q1": float(q1), "iqr": float(q3 - q1), "sample_size": int(count)})
                    del values
        stats = pd.DataFrame(baselines, columns=["severity", "q1", "iqr", "sample_size"])
        window_days = int(settings["coverage_window_days"])
        window_start = (reference - pd.Timedelta(days=window_days)) if reference is not None else None
        with _progress() as progress:
            task = progress.add_task("Pass 2/2: detecting supervisory signals", total=total_rows)
            for batch in _alert_batches(alert_path, lambda: controller.batch_size):
                batch_started = time.perf_counter()
                if "execution_gaps" in selected:
                    if controller.workers > 1:
                        # These rules do not depend on one another; threads share
                        # the immutable batch and avoid duplicate memory copies.
                        with ThreadPoolExecutor(max_workers=2) as executor:
                            fast = executor.submit(detect_fast_closure, batch, stats, float(settings["fast_closure_k"]))
                            no_escalation = executor.submit(detect_critical_no_escalation, batch)
                            batch_flags = fast.result() + no_escalation.result()
                    else:
                        batch_flags = detect_fast_closure(batch, stats, float(settings["fast_closure_k"]))
                        batch_flags.extend(detect_critical_no_escalation(batch))
                    flags.extend(attach_evidence(flag, {"alerts": batch}) for flag in batch_flags)
                if "negative_space" in selected and window_start is not None:
                    dates = pd.to_datetime(batch["created_at"], utc=True)
                    recent = batch[(dates >= window_start) & (dates <= reference)]
                    observed.update((str(entity), str(asset)) for entity, asset in zip(recent["entity_id"], recent["asset_id"]) if pd.notna(asset))
                progress.update(task, advance=len(batch))
                _show_adjustment(controller.after_batch(len(batch), time.perf_counter() - batch_started))
        if "negative_space" in selected:
            count_frame = pd.DataFrame([{"entity_id": entity, "asset_id": asset, "observed_count": count} for (entity, asset), count in observed.items()], columns=["entity_id", "asset_id", "observed_count"])
            coverage_flags = detect_low_critical_asset_coverage_from_counts(count_frame, assets, reference if reference is not None else pd.Timestamp.now(tz="UTC"), window_days=window_days, threshold_pct=float(settings["coverage_threshold_pct"]))
            flags.extend(attach_evidence(flag, {"assets": assets}) for flag in coverage_flags)
    # IDs are globally unique after multiple detector modules independently create flags.
    flags = [flag.model_copy(update={"flag_id": f"fg_{index:05d}"}) for index, flag in enumerate(flags, 1)]
    _write_flags(out, flags)
    (out.parent / "alert_volumes.json").write_text(json.dumps({entity: int(count) for entity, count in volumes.items()}, indent=2), encoding="utf-8")
    console.print(f"Detected [bold]{len(flags)}[/bold] flags; evidence written to {out} in {time.perf_counter() - started:.1f}s (final batch size {controller.batch_size:,}, workers {controller.workers}; adaptive={'on' if adaptive else 'off'}).")


class _ImmediateFuture:
    """Tiny Future-compatible wrapper used by the one-worker ingestion path."""

    def __init__(self, value):
        self.value = value

    def result(self):
        return self.value


@app.command("system-info")
def system_info(
    batch_size: Annotated[int, typer.Option(help="Requested batch size; 0 uses automatic tuning")] = 0,
    workers: Annotated[int, typer.Option(help="Requested workers; 0 uses automatic tuning")] = 0,
) -> None:
    """Show local CPU/RAM detection and the conservative automatic settings."""
    console.print_json(json.dumps(settings_dict(choose_runtime_settings(batch_size, workers)), indent=2))


@app.command()
def score(
    flags: Path = typer.Option(..., exists=True),
    out: Path = Path("results/entity_scores.csv"),
    config: Path | None = typer.Option(None, exists=True),
) -> None:
    """Risk-score and rank entities, correcting raw flag volume by alert volume."""
    loaded = _load_flags(flags)
    volume_path = flags.parent / "alert_volumes.json"
    volumes = json.loads(volume_path.read_text(encoding="utf-8")) if volume_path.exists() else {}
    settings = yaml.safe_load(config.read_text(encoding="utf-8")) if config else {}
    scores = score_entities(loaded, volumes, (settings or {}).get("weights"))
    _mkdir(out.parent); scores.to_csv(out, index=False)
    console.print(f"Scored {len(scores)} entities in {out}")


@app.command()
def report(
    scores: Path = typer.Option(..., exists=True),
    flags: Path = typer.Option(..., exists=True),
    format: str = typer.Option("table", help="json or table"),
    out: Path = Path("results/report.json"),
) -> None:
    """Emit JSON report and optionally render a supervisor-friendly priority table."""
    if format not in {"json", "table"}:
        raise typer.BadParameter("format must be json or table")
    score_frame = pd.read_csv(scores)
    loaded = _load_flags(flags)
    entities = []
    for _, score_row in score_frame.iterrows():
        own = [flag.as_json() for flag in loaded if flag.entity_id == score_row.entity_id]
        entities.append({"entity_id": score_row.entity_id, "risk_score": score_row.risk_score, "priority_rank": int(score_row.priority_rank), "flags": own})
    payload = {"generated_at": pd.Timestamp.now(tz="UTC").isoformat(), "entities": entities,
               "summary": {"entities_analyzed": len(score_frame), "total_flags": len(loaded), "flags_by_detector": dict(Counter(flag.detector for flag in loaded))}}
    _mkdir(out.parent); out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    if format == "table":
        table = Table(title="SAT-SA Supervisory Priority Report")
        table.add_column("Entity"); table.add_column("Rank", justify="right"); table.add_column("Risk", justify="right"); table.add_column("Top flag reasons")
        for entity in entities:
            reasons = "\n".join(flag["rationale"] for flag in entity["flags"][:2]) or "No flags"
            table.add_row(entity["entity_id"], str(entity["priority_rank"]), f"{entity['risk_score']:.4f}", reasons)
        console.print(table)
    console.print(f"Report written to {out}")


@app.command()
def explain(entity_id: str = typer.Option(...), flags: Path = typer.Option(..., exists=True)) -> None:
    """Print every finding and exact source evidence for a single entity."""
    matches = [flag for flag in _load_flags(flags) if flag.entity_id == entity_id]
    if not matches:
        raise typer.Exit(code=1)
    for flag in matches:
        console.rule(f"{flag.flag_id} · {flag.detector}")
        console.print(flag.rationale)
        console.print_json(json.dumps(flag.evidence, default=str))


@app.command()
def validate(
    flags: Path = typer.Option(..., exists=True),
    synth_ground_truth: Path = typer.Option(..., exists=True),
) -> None:
    """Calculate exact-key precision, recall and F1 against hidden synthetic injections."""
    predicted = _load_flags(flags)
    truth = pd.read_parquet(synth_ground_truth) if synth_ground_truth.suffix == ".parquet" else pd.read_csv(synth_ground_truth)
    rows = []
    for detector in sorted(set(truth.detector) | {flag.detector for flag in predicted}):
        expected = set()
        for _, row in truth[truth.detector == detector].iterrows():
            expected.add((str(row.entity_id), str(row.alert_id) if pd.notna(row.alert_id) else str(row.asset_id)))
        actual = set()
        for flag in (flag for flag in predicted if flag.detector == detector):
            ids = flag.evidence.get("alert_ids", []) or flag.evidence.get("asset_ids", [])
            actual.update((flag.entity_id, str(item)) for item in ids)
        tp = len(actual & expected); precision = tp / len(actual) if actual else 0; recall = tp / len(expected) if expected else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        rows.append((detector, len(expected), len(actual), precision, recall, f1))
    table = Table(title="Synthetic Ground-Truth Validation")
    for column in ("Detector", "Injected", "Detected", "Precision", "Recall", "F1"):
        table.add_column(column)
    for row in rows:
        table.add_row(row[0], str(row[1]), str(row[2]), *(f"{value:.3f}" for value in row[3:]))
    console.print(table)


if __name__ == "__main__":  # pragma: no cover
    app()

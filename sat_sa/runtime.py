"""Local, dependency-free resource detection and conservative runtime tuning."""
from __future__ import annotations

import ctypes
import os
from dataclasses import asdict, dataclass
from typing import NamedTuple


@dataclass(frozen=True)
class SystemProfile:
    logical_cpus: int
    available_memory_mb: int
    total_memory_mb: int
    platform: str


@dataclass(frozen=True)
class RuntimeSettings:
    batch_size: int
    workers: int
    profile: SystemProfile


class CpuTimes(NamedTuple):
    idle: int
    total: int


@dataclass(frozen=True)
class RuntimeAdjustment:
    old_batch_size: int
    new_batch_size: int
    old_workers: int
    new_workers: int
    reason: str
    available_memory_mb: int
    cpu_pct: float | None


def detect_system() -> SystemProfile:
    """Return CPU count and currently *available* RAM without cloud telemetry."""
    memory_bytes = total_bytes = 0
    if os.name == "nt":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        status = MemoryStatus(); status.dwLength = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            memory_bytes = status.ullAvailPhys
            total_bytes = status.ullTotalPhys
    elif hasattr(os, "sysconf"):
        try:
            memory_bytes = os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
            total_bytes = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError):
            pass
    return SystemProfile(logical_cpus=max(1, os.cpu_count() or 1), available_memory_mb=max(1, memory_bytes // (1024 * 1024)), total_memory_mb=max(1, total_bytes // (1024 * 1024)), platform=os.name)


def _cpu_times() -> CpuTimes | None:
    """Read host CPU counters without adding a runtime dependency such as psutil."""
    if os.name == "nt":
        class FileTime(ctypes.Structure):
            _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

        idle, kernel, user = FileTime(), FileTime(), FileTime()
        if ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            def value(item: FileTime) -> int:
                return (item.dwHighDateTime << 32) + item.dwLowDateTime
            idle_value, kernel_value, user_value = value(idle), value(kernel), value(user)
            return CpuTimes(idle_value, kernel_value + user_value)
    return None


def choose_runtime_settings(batch_size: int = 0, workers: int = 0) -> RuntimeSettings:
    """Choose bounded concurrency; explicit positive settings always win.

    Defaults deliberately favour throughput. Adaptive mode reacts to genuine
    pressure while the job is running; free RAM alone is not treated as a hard
    concurrency cap because file cache and reclaimable pages distort that value.
    """
    profile = detect_system()
    if batch_size < 0 or workers < 0:
        raise ValueError("batch_size and workers must be zero (automatic) or positive")
    if batch_size == 0:
        available = profile.available_memory_mb
        batch_size = 10_000 if available < 1_024 else 50_000 if available < 4_096 else 100_000 if available < 8_192 else 200_000
    if workers == 0:
        workers = 1 if profile.available_memory_mb < 768 else min(12, max(2, profile.logical_cpus - 2))
    return RuntimeSettings(batch_size=batch_size, workers=workers, profile=profile)


def settings_dict(settings: RuntimeSettings) -> dict:
    result = asdict(settings)
    result["profile"] = asdict(settings.profile)
    return result


class AdaptiveController:
    """Conservatively tune bounded batches and worker admission as a host changes."""

    def __init__(self, settings: RuntimeSettings, enabled: bool = True, check_every_batches: int = 4):
        if check_every_batches < 1:
            raise ValueError("check_every_batches must be positive")
        self.batch_size = settings.batch_size
        # Never turn a deliberately small user batch into a larger one when
        # pressure is detected; automatic defaults retain a 1,000-row floor.
        self.min_batch_size = min(1_000, settings.batch_size)
        self.workers = settings.workers
        self.enabled = enabled
        self.check_every_batches = check_every_batches
        self._batches_since_check = 0
        self._previous_cpu = _cpu_times()
        self._last_throughput: float | None = None

    def after_batch(self, records: int = 0, elapsed_seconds: float | None = None) -> RuntimeAdjustment | None:
        """Health-check after a completed batch and return an adjustment if needed."""
        if not self.enabled:
            return None
        self._batches_since_check += 1
        if self._batches_since_check < self.check_every_batches:
            return None
        self._batches_since_check = 0
        profile = detect_system()
        current_cpu = _cpu_times()
        cpu_pct: float | None = None
        if current_cpu and self._previous_cpu:
            total_delta = current_cpu.total - self._previous_cpu.total
            idle_delta = current_cpu.idle - self._previous_cpu.idle
            if total_delta > 0:
                cpu_pct = max(0.0, min(100.0, 100 * (1 - idle_delta / total_delta)))
        self._previous_cpu = current_cpu
        old_batch, old_workers = self.batch_size, self.workers
        throughput = records / elapsed_seconds if records and elapsed_seconds and elapsed_seconds > 0 else None
        regressed = throughput is not None and self._last_throughput is not None and throughput < self._last_throughput * .60
        if throughput is not None:
            # Keep the high-water mark instead of being pulled down by a single
            # transient slow write; reduction requires a 40% regression.
            self._last_throughput = max(throughput, self._last_throughput or 0)
        # High CPU is productive use. Back off only on critically low free RAM,
        # or a sharp throughput collapse while both CPU and RAM are saturated.
        choking = profile.available_memory_mb < 512 or (profile.available_memory_mb < 1_024 and (cpu_pct or 0) > 98 and regressed)
        if choking:
            self.batch_size = max(self.min_batch_size, self.batch_size // 2)
            self.workers = max(1, self.workers - 1)
            reason = "host pressure detected"
        else:
            ceiling = 50_000 if profile.available_memory_mb < 1_024 else 100_000 if profile.available_memory_mb < 4_096 else 200_000 if profile.available_memory_mb < 8_192 else 500_000
            worker_ceiling = 1 if profile.available_memory_mb < 768 else min(12, max(2, profile.logical_cpus - 2))
            has_growth_headroom = profile.available_memory_mb >= 768 and (cpu_pct is None or cpu_pct < 98)
            if has_growth_headroom and (self.batch_size < ceiling or self.workers < worker_ceiling):
                self.batch_size = min(ceiling, max(self.batch_size + 1_000, int(self.batch_size * 1.25)))
                self.workers = min(worker_ceiling, self.workers + 1)
                reason = "headroom available"
            else:
                return None
        if (old_batch, old_workers) == (self.batch_size, self.workers):
            return None
        return RuntimeAdjustment(old_batch, self.batch_size, old_workers, self.workers, reason, profile.available_memory_mb, cpu_pct)

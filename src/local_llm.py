# src/local_llm.py — Local-LLM engine for the "ถามต่อกับ AI" chat box
# ────────────────────────────────────────────────────────────────────
#   SCOPE: this module powers the Chat-with-AI box ONLY. Every other AI
#   surface in VULNEX (the AI Analysis sections, the per-module insight
#   cards, the PDF report prose) still runs on the Gemini / OpenRouter
#   API-key cascade in ai_engine.py. Nothing here touches those paths.
#
#   WHERE THE MODEL RUNS: Streamlit executes server-side, so the model is
#   loaded on the machine running `streamlit run` — a laptop in local dev,
#   the container on Streamlit Cloud. It never runs in the visitor's
#   browser. On a host with no Ollama (e.g. Streamlit Cloud) the chat box
#   reports "ไม่พบ Local LLM" and stays disabled by design: no cloud
#   fallback, per the product decision.
#
#   MODEL POLICY (three rules, in the order they matter):
#     1. Every model the team shortlisted is present in CATALOG below —
#        including the ones whose Ollama tag does not exist yet (Gemma 4,
#        GLM-4.7-Flash, Mistral Large 3). Each entry carries an ordered
#        tuple of candidate tags: the aspirational tag first, a real,
#        pullable stand-in second. resolve_tag() walks that tuple against
#        the live Ollama registry and takes the first tag that exists, so a
#        model that ships tomorrow is picked up with no code change, and one
#        that does not exist today never breaks the chat.
#     2. Only TWO models are ever loaded: the smartest QUALITY model and the
#        smartest FAST model whose memory footprint actually fits the
#        detected hardware (see _memory_budget_gb). Everything larger stays
#        in the catalog, unloaded. The chains are ordered smartest-first, so
#        "best that fits" is just "first that fits".
#     3. Disk hygiene: VULNEX deletes, on app exit, exactly the models IT
#        pulled — tracked in a manifest (~/.vulnex/managed_models.json). A
#        model the user already had is never registered and never deleted.
#
#   NETWORK: the only host contacted is the loopback Ollama daemon. The SSRF
#   guard in utils/network.py deliberately does NOT apply here — it exists to
#   stop the *scanner* from reaching internal hosts, and would (correctly)
#   reject 127.0.0.1. This client follows no redirects and speaks only to the
#   configured OLLAMA_HOST, so it cannot be steered elsewhere.
# ────────────────────────────────────────────────────────────────────
from __future__ import annotations

import atexit
import ctypes
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator

import httpx

# ── Ollama daemon ────────────────────────────────────────────────────
_DEFAULT_HOST = "127.0.0.1:11434"


def _base_url() -> str:
    """Ollama's own env convention: OLLAMA_HOST=host:port (no scheme)."""
    host = (os.getenv("OLLAMA_HOST") or _DEFAULT_HOST).strip()
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host.rstrip("/")


# Connect fast (the daemon is loopback — it answers instantly or not at all),
# but never time out on reads: a CPU-bound model can take minutes to finish a
# deep-think answer, and a multi-GB pull streams for just as long.
_T_PROBE  = httpx.Timeout(3.0, connect=1.5)
_T_STREAM = httpx.Timeout(None, connect=5.0)


# ════════════════════════════════════════════════════════════════════
# Hardware detection
# ════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Hardware:
    gpu_name:   str      # "" when no discrete GPU was found
    vram_gb:    float    # dedicated VRAM; 0.0 on CPU-only / iGPU boxes
    ram_gb:     float    # total system RAM
    unified:    bool     # Apple Silicon — RAM is shared with the GPU
    cpu:        str
    cores:      int
    tier:       str      # "high" | "mid" | "entry" | "cpu"
    budget_gb:  float    # memory a model may actually occupy here
    accel:      str      # "GPU" | "Apple GPU" | "CPU"

    @property
    def tier_label(self) -> str:
        return {
            "high":  "High-End",
            "mid":   "Mid-Range",
            "entry": "Entry-Level",
            "cpu":   "CPU-Only",
        }[self.tier]

    @property
    def summary(self) -> str:
        """One Thai line for the panel's hardware chip."""
        if self.unified:
            return f"Apple Silicon · Unified {self.ram_gb:.0f} GB"
        if self.vram_gb > 0:
            return f"{self.gpu_name} · VRAM {self.vram_gb:.0f} GB"
        return f"CPU · RAM {self.ram_gb:.0f} GB"


def _total_ram_gb() -> float:
    """System RAM in GB, stdlib only (psutil is not a project dependency)."""
    try:
        if sys.platform == "win32":
            class _MemStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = _MemStatus()
            stat.dwLength = ctypes.sizeof(_MemStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return stat.ullTotalPhys / 1024 ** 3
        if sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                                 capture_output=True, text=True, timeout=4)
            return int(out.stdout.strip()) / 1024 ** 3
        # Linux
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / 1024 ** 2
    except Exception:      # noqa: BLE001 — detection must never crash the app
        pass
    return 0.0


def _nvidia_vram() -> tuple[str, float]:
    """(name, VRAM GB) from nvidia-smi, or ("", 0.0)."""
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=6,
        )
        rows = [r for r in out.stdout.strip().splitlines() if r.strip()]
        if not rows:
            return "", 0.0
        # Multi-GPU: Ollama will not shard one model across cards by default,
        # so the usable ceiling is the LARGEST single card, not the sum.
        best_name, best_mib = "", 0.0
        for row in rows:
            name, _, mib = row.partition(",")
            try:
                val = float(mib.strip())
            except ValueError:
                continue
            if val > best_mib:
                best_name, best_mib = name.strip(), val
        return best_name, best_mib / 1024
    except Exception:      # noqa: BLE001
        return "", 0.0


def _windows_vram() -> tuple[str, float]:
    """Real dedicated VRAM on Windows via the display adapter's registry key.

    Win32_VideoController.AdapterRAM is a 32-bit field — it silently wraps at
    4 GB and reports shared memory for integrated chips, so it cannot tell a
    2 GB iGPU from a 24 GB RTX 4090. HardwareInformation.qwMemorySize is the
    64-bit truth the driver writes. An integrated chip has no dedicated VRAM
    entry, so it correctly falls through to 0 and we treat the box as CPU.
    """
    try:
        ps = (
            r"$k='HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}';"
            r"Get-ChildItem $k -EA SilentlyContinue | ForEach-Object {"
            r"  $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue;"
            r"  if ($p.'HardwareInformation.qwMemorySize') {"
            r"    '{0}|{1}' -f $p.DriverDesc, $p.'HardwareInformation.qwMemorySize' } }"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        best_name, best_gb = "", 0.0
        for line in out.stdout.strip().splitlines():
            name, _, size = line.partition("|")
            try:
                gb = int(size.strip()) / 1024 ** 3
            except ValueError:
                continue
            if gb > best_gb:
                best_name, best_gb = name.strip(), gb
        return best_name, best_gb
    except Exception:      # noqa: BLE001
        return "", 0.0


def _memory_budget_gb(vram_gb: float, ram_gb: float, unified: bool) -> tuple[float, str]:
    """How much memory a model may actually occupy on this box → (budget, accel).

    The number the model files are compared against. It is deliberately
    conservative: a model that *just* fits its raw weights will thrash once the
    KV cache, the OS and Streamlit itself are accounted for, and a swapping
    model is worse than a smaller one that runs.
    """
    if unified:
        # Metal caps GPU-usable unified memory well below the physical total.
        return max(0.0, ram_gb * 0.70), "Apple GPU"
    if vram_gb >= 6.0:
        # Full GPU offload. Reserve ~1.2 GB for the KV cache + the desktop.
        return max(0.0, vram_gb - 1.2), "GPU"
    # CPU inference out of system RAM. Reserve enough for the OS, the browser
    # and the Streamlit/Chromium (PDF engine) processes this app itself runs:
    # a 3.5 GB floor covers Windows + Streamlit + a browser tab, and the 40 %
    # term keeps a big workstation from handing almost everything to the model
    # (the same box is also running the scan). Scaling the reserve rather than
    # fixing it is what stops a small machine from picking a model that swaps.
    reserve = max(3.5, ram_gb * 0.40)
    return max(0.0, ram_gb - reserve), "CPU"


_hw_cache: Hardware | None = None
_hw_lock = threading.Lock()


def detect_hardware(refresh: bool = False) -> Hardware:
    """Probe GPU / VRAM / RAM once per process (the answer cannot change)."""
    global _hw_cache
    with _hw_lock:
        if _hw_cache is not None and not refresh:
            return _hw_cache

        ram_gb  = _total_ram_gb()
        unified = sys.platform == "darwin" and platform.machine() == "arm64"

        gpu_name, vram_gb = _nvidia_vram()
        if not vram_gb and sys.platform == "win32":
            gpu_name, vram_gb = _windows_vram()

        budget, accel = _memory_budget_gb(vram_gb, ram_gb, unified)

        # Tier is the team's own spec sheet (VRAM 48+/16+/8+), used for the
        # display chip. Model SELECTION never reads it — that goes off `budget`,
        # which is measured, so a 24 GB card is never asked to hold a 123 B model.
        if vram_gb >= 48 or (unified and ram_gb >= 128):
            tier = "high"
        elif vram_gb >= 16:
            tier = "mid"
        elif vram_gb >= 8:
            tier = "entry"
        else:
            tier = "cpu"

        _hw_cache = Hardware(
            gpu_name=gpu_name, vram_gb=round(vram_gb, 1), ram_gb=round(ram_gb, 1),
            unified=unified, cpu=platform.processor() or platform.machine(),
            cores=os.cpu_count() or 1, tier=tier,
            budget_gb=round(budget, 1), accel=accel,
        )
        return _hw_cache


# ════════════════════════════════════════════════════════════════════
# Model catalog — every shortlisted model lives here
# ════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class LocalModel:
    key:     str
    label:   str                   # the name the team knows it by
    vendor:  str
    params:  str
    size_gb: float                 # 4-bit weights, on disk
    need_gb: float                 # weights + KV cache headroom → the fit test
    tags:    tuple[str, ...]       # candidate Ollama tags, best first
    tier:    str                   # the tier this model was shortlisted for
    why:     str                   # Thai rationale, shown in the model picker

    @property
    def size_label(self) -> str:
        return f"{self.size_gb:.1f} GB" if self.size_gb < 100 else f"{self.size_gb:.0f} GB"


# QUALITY chain — "โหมดคิดนาน". Ordered smartest → smallest; the resolver takes
# the first entry that fits the measured memory budget.
QUALITY_CHAIN: tuple[LocalModel, ...] = (
    LocalModel(
        key="llama4-maverick", label="Llama 4 Maverick", vendor="Meta",
        params="400B MoE (17B active)", size_gb=245.0, need_gb=250.0,
        tags=("llama4:maverick",), tier="high",
        why="ที่สุดของการวิเคราะห์เชิงลึก — MoE ขนาดใหญ่ ไล่เหตุผลช่องโหว่ทีละขั้นเหมือนซีเนียร์นั่งอ่านโค้ดให้",
    ),
    LocalModel(
        key="mistral-large-3", label="Mistral Large 3", vendor="Mistral AI",
        params="123B", size_gb=73.0, need_gb=76.0,
        tags=("mistral-large:3", "mistral-large:123b", "mistral-large"), tier="high",
        why="ตรรกะแน่นและเป็นกลาง อธิบายเส้นทางการโจมตี (attack vector) ได้เป็นเหตุเป็นผล",
    ),
    LocalModel(
        key="llama4-scout", label="Llama 4 Scout", vendor="Meta",
        params="109B MoE (17B active)", size_gb=67.0, need_gb=70.0,
        tags=("llama4:scout",), tier="high",
        why="รุ่นน้องของ Maverick — คิดลึกใกล้เคียงกันแต่กินหน่วยความจำน้อยกว่ามาก",
    ),
    LocalModel(
        key="glm-z1-32b", label="GLM-Z1-32B", vendor="Zhipu",
        params="32B", size_gb=20.0, need_gb=22.0,
        tags=("glm-z1:32b", "glm4:32b"), tier="mid",
        why="เทรนมาเป็น “สายนักคิด” โดยเฉพาะ — เหมาะกับคำถามที่ต้องแตกเหตุผลหลายชั้น",
    ),
    LocalModel(
        key="qwen3-32b", label="Qwen3 32B", vendor="Alibaba",
        params="32B", size_gb=20.0, need_gb=22.0,
        tags=("qwen3:32b",), tier="mid",
        why="โมเดลเหตุผลระดับ 32B ที่หาโหลดได้จริงเสมอ — ตัวยืนพื้นของชั้น Mid-Range",
    ),
    LocalModel(
        key="gemma4-26b", label="Gemma 4 26B", vendor="Google",
        params="26B", size_gb=17.0, need_gb=19.0,
        tags=("gemma4:26b", "gemma3:27b"), tier="mid",
        why="แม่นยำเชิงเทคนิคสูง สรุปผลสแกนได้ครบโดยไม่กินการ์ดจอทั้งใบ",
    ),
    LocalModel(
        key="gemma4-12b", label="Gemma 4 12B", vendor="Google",
        params="12B", size_gb=8.1, need_gb=9.5,
        tags=("gemma4:12b", "gemma3:12b"), tier="entry",
        why="อัดแน่นด้วยความสามารถด้าน reasoning เกินขนาดตัว — ตัวเลือกคิดลึกของการ์ดจอ 8–12 GB",
    ),
    LocalModel(
        key="qwen3-8b", label="Qwen3 8B", vendor="Alibaba",
        params="8B", size_gb=5.2, need_gb=6.2,
        tags=("qwen3:8b",), tier="entry",
        why="ตอบไทยได้ดีในไซซ์เล็ก และยังไล่เหตุผลเป็นขั้นเป็นตอนได้",
    ),
    LocalModel(
        key="llama31-8b", label="Llama 3.1 8B Instruct", vendor="Meta",
        params="8B", size_gb=4.9, need_gb=5.9,
        tags=("llama3.1:8b",), tier="entry",
        why="ทำงานลื่นบนการ์ดจอเล่นเกมทั่วไป ตอบตรงคำถามและไม่กินทรัพยากร",
    ),
    LocalModel(
        key="gemma3-4b", label="Gemma 3 4B", vendor="Google",
        params="4B", size_gb=3.3, need_gb=4.0,
        tags=("gemma3:4b",), tier="cpu",
        why="รุ่นเล็กที่ยังเข้าใจภาษาไทยดี — สำหรับเครื่องที่ไม่มีการ์ดจอแยก",
    ),
    LocalModel(
        key="phi4-mini", label="Phi-4-mini", vendor="Microsoft",
        params="3.8B", size_gb=2.5, need_gb=3.2,
        tags=("phi4-mini",), tier="cpu",
        why="เล็กแต่เก่งเรื่องการให้เหตุผล — พื้นที่สุดท้ายที่เครื่องสเปกจำกัดยังคิดเป็นขั้นตอนได้",
    ),
    LocalModel(
        key="llama32-3b", label="Llama 3.2 3B", vendor="Meta",
        params="3B", size_gb=2.0, need_gb=2.6,
        tags=("llama3.2:3b",), tier="cpu",
        why="รันได้แทบทุกเครื่อง — ใช้เมื่อแรมเหลือน้อยจริง ๆ",
    ),
    LocalModel(
        key="qwen3-1_7b", label="Qwen3 1.7B", vendor="Alibaba",
        params="1.7B", size_gb=1.4, need_gb=1.9,
        tags=("qwen3:1.7b",), tier="cpu",
        why="ขั้นต่ำสุดของระบบ — พอตอบคำถามสั้น ๆ เกี่ยวกับผลสแกนได้",
    ),
)

# FAST chain — "โหมดตอบเร็ว". Same rule, but ordered by throughput-at-quality
# rather than raw depth.
FAST_CHAIN: tuple[LocalModel, ...] = (
    LocalModel(
        key="glm-47-flash", label="GLM-4.7-Flash", vendor="Zhipu",
        params="30B MoE (3B active)", size_gb=18.0, need_gb=20.0,
        tags=("glm-4.7-flash", "glm4.7:flash", "glm4:9b"), tier="high",
        why="MoE ที่กินแรงจริงแค่ 3B ต่อโทเคน — ได้ความเร็วระดับรุ่นเล็ก บนฐานความรู้ระดับ 30B",
    ),
    LocalModel(
        key="gemma4-26b-fast", label="Gemma 4 26B", vendor="Google",
        params="26B", size_gb=17.0, need_gb=19.0,
        tags=("gemma4:26b", "gemma3:27b"), tier="mid",
        why="เร็วมากบนการ์ดจอระดับกลาง และแม่นเรื่องชื่อช่องโหว่/ระดับความรุนแรง",
    ),
    LocalModel(
        key="gemma4-12b-fast", label="Gemma 4 12B", vendor="Google",
        params="12B", size_gb=8.1, need_gb=9.5,
        tags=("gemma4:12b", "gemma3:12b"), tier="mid",
        why="สรุปผลสแกนเบื้องต้นได้แทบจะทันที — จุดสมดุลของความเร็วกับความแม่น",
    ),
    LocalModel(
        key="llama31-8b-fast", label="Llama 3.1 8B Instruct", vendor="Meta",
        params="8B", size_gb=4.9, need_gb=5.9,
        tags=("llama3.1:8b",), tier="entry",
        why="แชมป์ความเร็วรุ่นเล็ก — ทะลุ 50–100 tokens/วินาที บนการ์ดจอทั่วไป",
    ),
    LocalModel(
        key="gemma3-4b-fast", label="Gemma 3 4B", vendor="Google",
        params="4B", size_gb=3.3, need_gb=4.0,
        tags=("gemma3:4b",), tier="cpu",
        why="เล็ก เร็ว และยังตอบไทยได้เป็นธรรมชาติ",
    ),
    LocalModel(
        key="phi4-mini-fast", label="Phi-4-mini", vendor="Microsoft",
        params="3.8B", size_gb=2.5, need_gb=3.2,
        tags=("phi4-mini",), tier="cpu",
        why="ตอบไวแบบเสี้ยววินาที ไม่กินทรัพยากร — เหมาะกับเครื่องที่ไม่มีการ์ดจอแยก",
    ),
    LocalModel(
        key="llama32-3b-fast", label="Llama 3.2 3B", vendor="Meta",
        params="3B", size_gb=2.0, need_gb=2.6,
        tags=("llama3.2:3b",), tier="cpu",
        why="ไซซ์เล็กสุดที่ยังคุยรู้เรื่อง — สำรองไว้ให้เครื่องแรมน้อย",
    ),
    LocalModel(
        key="qwen3-1_7b-fast", label="Qwen3 1.7B", vendor="Alibaba",
        params="1.7B", size_gb=1.4, need_gb=1.9,
        tags=("qwen3:1.7b",), tier="cpu",
        why="ขั้นต่ำสุดของระบบ",
    ),
)

CATALOG: tuple[LocalModel, ...] = QUALITY_CHAIN + FAST_CHAIN


@dataclass
class Plan:
    """The two models this machine will actually run."""
    quality: LocalModel | None
    fast:    LocalModel | None
    hw:      Hardware
    skipped: list[LocalModel] = field(default_factory=list)   # too big for this box

    def pick(self, mode: str) -> LocalModel | None:
        return self.quality if mode == "deep" else self.fast

    @property
    def same_model(self) -> bool:
        """True when the box is small enough that both modes land on one model."""
        return bool(self.quality and self.fast and self.quality.tags == self.fast.tags)


def resolve_plan(hw: Hardware | None = None) -> Plan:
    """Pick the smartest QUALITY + FAST model whose footprint fits this machine.

    Pure arithmetic against `hw.budget_gb` — no network, no Ollama needed. It
    answers "what *could* this box run", which is what the panel shows before
    anything is downloaded. Availability (is the tag real, is it pulled yet) is
    a separate question, answered by resolve_tag() / installed_tags().
    """
    hw = hw or detect_hardware()
    fits = lambda m: m.need_gb <= hw.budget_gb                       # noqa: E731
    quality = next((m for m in QUALITY_CHAIN if fits(m)), None)
    fast    = next((m for m in FAST_CHAIN    if fits(m)), None)
    skipped = [m for m in QUALITY_CHAIN if not fits(m)]
    return Plan(quality=quality, fast=fast, hw=hw, skipped=skipped)


# ════════════════════════════════════════════════════════════════════
# Ollama backend
# ════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Status:
    installed: bool          # the ollama binary exists on this machine
    running:   bool          # the daemon answers on the API port
    version:   str
    base_url:  str
    error:     str


def _ollama_exe() -> str:
    """Path to the ollama binary, or "". The Windows installer drops it in a
    per-user directory that is only added to PATH for *new* shells, so a fresh
    install is invisible to an already-running Streamlit process until it is
    restarted — check the well-known location too."""
    found = shutil.which("ollama")
    if found:
        return found
    candidates = []
    if sys.platform == "win32":
        local = os.getenv("LOCALAPPDATA", "")
        if local:
            candidates.append(os.path.join(local, "Programs", "Ollama", "ollama.exe"))
        candidates.append(r"C:\Program Files\Ollama\ollama.exe")
    else:
        candidates += ["/usr/local/bin/ollama", "/usr/bin/ollama",
                       "/opt/homebrew/bin/ollama"]
    return next((p for p in candidates if os.path.isfile(p)), "")


def _ping() -> tuple[bool, str]:
    """Is the daemon up? → (running, version-or-error)."""
    try:
        with httpx.Client(timeout=_T_PROBE, follow_redirects=False) as c:
            r = c.get(f"{_base_url()}/api/version")
            if r.status_code == 200:
                return True, str(r.json().get("version", "")).strip()
            return False, f"HTTP {r.status_code}"
    except Exception as exc:                     # noqa: BLE001
        return False, type(exc).__name__


def start_daemon(wait_sec: float = 12.0) -> bool:
    """Start `ollama serve` detached and wait for the API to answer.

    On Windows the daemon normally runs as a tray app, but right after a silent
    install (or on a server login) nothing has started it yet. Launching it
    ourselves is the difference between "chat just works" and "chat tells the
    user to go open an app".
    """
    exe = _ollama_exe()
    if not exe:
        return False
    if _ping()[0]:
        return True
    try:
        kwargs: dict = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                | getattr(subprocess, "DETACHED_PROCESS", 0)
            )
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen([exe, "serve"], **kwargs)                  # noqa: S603
    except Exception:                            # noqa: BLE001
        return False

    deadline = time.time() + wait_sec
    while time.time() < deadline:
        if _ping()[0]:
            return True
        time.sleep(0.4)
    return False


def backend_status(autostart: bool = True) -> Status:
    """Where the local engine stands right now. Cheap enough to call per rerun."""
    exe = _ollama_exe()
    running, info = _ping()
    if not running and exe and autostart:
        if start_daemon():
            running, info = _ping()
    return Status(
        installed=bool(exe),
        running=running,
        version=info if running else "",
        base_url=_base_url(),
        error="" if running else info,
    )


def installed_tags() -> set[str]:
    """Model tags present on this machine, both bare and :latest-suffixed."""
    try:
        with httpx.Client(timeout=_T_PROBE, follow_redirects=False) as c:
            r = c.get(f"{_base_url()}/api/tags")
            r.raise_for_status()
            names = {str(m.get("name", "")) for m in (r.json().get("models") or [])}
    except Exception:                            # noqa: BLE001
        return set()
    out: set[str] = set()
    for n in names:
        if not n:
            continue
        out.add(n)
        out.add(n.split(":")[0] if n.endswith(":latest") else n)
    return out


def resolve_tag(model: LocalModel) -> str:
    """First candidate tag of this model that is ALREADY on the machine, else "".

    Used to skip a download when the model (or its stand-in) is already there.
    """
    have = installed_tags()
    for tag in model.tags:
        if tag in have or f"{tag}:latest" in have:
            return tag
    return ""


# ── Managed-model manifest (disk hygiene) ────────────────────────────
# Policy, decided with the team: VULNEX deletes its models when the app closes.
# The manifest is what keeps that promise honest — it records ONLY the tags this
# app pulled itself. A model the user already had is never written here, so the
# exit sweep can never delete someone's pre-existing 27 GB download.
_MANIFEST_DIR  = os.path.join(os.path.expanduser("~"), ".vulnex")
_MANIFEST_PATH = os.path.join(_MANIFEST_DIR, "managed_models.json")
_manifest_lock = threading.Lock()


def _read_manifest() -> list[str]:
    try:
        with open(_MANIFEST_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        tags = data.get("tags", [])
        return [t for t in tags if isinstance(t, str) and t]
    except Exception:                            # noqa: BLE001
        return []


def _write_manifest(tags: list[str]) -> None:
    try:
        os.makedirs(_MANIFEST_DIR, exist_ok=True)
        with open(_MANIFEST_PATH, "w", encoding="utf-8") as fh:
            json.dump({"tags": sorted(set(tags))}, fh, ensure_ascii=False, indent=2)
    except Exception:                            # noqa: BLE001
        pass


def managed_tags() -> list[str]:
    with _manifest_lock:
        return _read_manifest()


def _register_managed(tag: str) -> None:
    with _manifest_lock:
        tags = _read_manifest()
        if tag not in tags:
            tags.append(tag)
            _write_manifest(tags)


def managed_size_gb() -> float:
    """Disk currently held by the models VULNEX pulled (for the cleanup button)."""
    owned = set(managed_tags())
    if not owned:
        return 0.0
    try:
        with httpx.Client(timeout=_T_PROBE, follow_redirects=False) as c:
            r = c.get(f"{_base_url()}/api/tags")
            r.raise_for_status()
            models = r.json().get("models") or []
    except Exception:                            # noqa: BLE001
        return 0.0
    total = 0
    for m in models:
        name = str(m.get("name", ""))
        if name in owned or name.split(":")[0] in owned:
            total += int(m.get("size", 0) or 0)
    return total / 1024 ** 3


def delete_model(tag: str) -> bool:
    try:
        with httpx.Client(timeout=httpx.Timeout(30.0, connect=3.0),
                          follow_redirects=False) as c:
            r = c.request("DELETE", f"{_base_url()}/api/delete", json={"model": tag})
            return r.status_code in (200, 404)
    except Exception:                            # noqa: BLE001
        return False


def cleanup_managed() -> list[str]:
    """Delete every model VULNEX pulled. Returns the tags actually removed.

    Runs on app exit (see register_exit_cleanup) and behind the panel's
    "ลบโมเดลออกจากเครื่อง" button. Idempotent: a second call finds an empty
    manifest and does nothing.
    """
    tags = managed_tags()
    if not tags:
        return []
    if not _ping()[0]:
        # Daemon already gone (it dies with the tray app / the container). The
        # manifest is left intact so the next graceful exit still cleans up.
        return []
    removed = [t for t in tags if delete_model(t)]
    with _manifest_lock:
        remaining = [t for t in _read_manifest() if t not in removed]
        _write_manifest(remaining)
    return removed


_exit_hooked = False


def register_exit_cleanup() -> None:
    """Wire the exit sweep to process shutdown, once.

    "ปิดแอป" means the Streamlit *server process* stops (Ctrl-C, SIGTERM, a
    container being torn down) — Streamlit exposes no per-browser-tab close
    hook, and using one would be wrong anyway: with two people on the app, one
    closing a tab must not delete the model the other is mid-question with.
    A hard kill (taskkill /F) bypasses atexit; the manifest survives it, so the
    next graceful exit — or the panel's delete button — still cleans up.
    """
    global _exit_hooked
    if _exit_hooked:
        return
    _exit_hooked = True
    atexit.register(cleanup_managed)


# ── Pull ─────────────────────────────────────────────────────────────
@dataclass
class PullProgress:
    status:    str
    completed: int = 0
    total:     int = 0

    @property
    def pct(self) -> float:
        return (self.completed / self.total) if self.total else 0.0


def pull_model(
    model: LocalModel,
    on_progress: Callable[[PullProgress], None] | None = None,
) -> tuple[str, str]:
    """Download the first candidate tag of `model` that actually exists.

    This is where the catalog's aspirational names get reconciled with reality:
    a tag the registry has never heard of (gemma4:26b today) fails on the
    manifest lookup within a second and costs no bandwidth, so we simply try the
    next candidate (gemma3:27b) and pull that. Returns (tag, "") on success or
    ("", error) when every candidate is a dead end.
    """
    pre_existing = installed_tags()
    errors: list[str] = []

    for tag in model.tags:
        try:
            with httpx.Client(timeout=_T_STREAM, follow_redirects=False) as c:
                with c.stream("POST", f"{_base_url()}/api/pull",
                              json={"model": tag, "stream": True}) as resp:
                    if resp.status_code != 200:
                        resp.read()
                        errors.append(f"{tag}: HTTP {resp.status_code}")
                        continue
                    failed = ""
                    for line in resp.iter_lines():
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                        except ValueError:
                            continue
                        if evt.get("error"):
                            failed = str(evt["error"])
                            break
                        if on_progress:
                            on_progress(PullProgress(
                                status=str(evt.get("status", "")),
                                completed=int(evt.get("completed", 0) or 0),
                                total=int(evt.get("total", 0) or 0),
                            ))
                    if failed:
                        errors.append(f"{tag}: {failed}")
                        continue
        except Exception as exc:                 # noqa: BLE001
            errors.append(f"{tag}: {exc}")
            continue

        # Only claim ownership of a model that was NOT already on this machine.
        if tag not in pre_existing and f"{tag}:latest" not in pre_existing:
            _register_managed(tag)
        return tag, ""

    return "", " · ".join(errors) or "ไม่พบโมเดลนี้ใน Ollama registry"


# ── Generation ───────────────────────────────────────────────────────
# Deep-think trades every second it can for a better answer (bigger context, a
# longer budget to actually finish the reasoning, lower temperature). Fast mode
# is tuned to feel instant. Both are near-deterministic: this is security advice
# about real findings, not creative writing.
_OPTS = {
    "fast": {"temperature": 0.3, "top_p": 0.9, "num_ctx": 4096, "num_predict": 800},
    "deep": {"temperature": 0.2, "top_p": 0.9, "num_ctx": 8192, "num_predict": 2000},
}
# Keep the weights resident between questions — a cold load of a multi-GB model
# is the single biggest latency in the box, and re-paying it per message would
# make the chat feel broken.
_KEEP_ALIVE = "10m"


def chat_stream(
    tag: str,
    messages: list[dict],
    mode: str = "fast",
    stop_flag: Callable[[], bool] | None = None,
) -> Iterator[str]:
    """Stream an assistant reply from Ollama. Yields text chunks.

    Raises RuntimeError with a Thai message on any failure so the caller can
    surface it verbatim in the panel.
    """
    payload = {
        "model":      tag,
        "messages":   messages,
        "stream":     True,
        "options":    _OPTS.get(mode, _OPTS["fast"]),
        "keep_alive": _KEEP_ALIVE,
        # Small local models love to narrate their reasoning. The chat box wants
        # the answer, not the monologue — Ollama strips <think> blocks for us.
        "think":      False,
    }
    try:
        with httpx.Client(timeout=_T_STREAM, follow_redirects=False) as c:
            with c.stream("POST", f"{_base_url()}/api/chat", json=payload) as resp:
                if resp.status_code != 200:
                    resp.read()
                    raise RuntimeError(
                        f"Ollama ตอบกลับ HTTP {resp.status_code} — {resp.text[:200]}"
                    )
                for line in resp.iter_lines():
                    if stop_flag and stop_flag():
                        return
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except ValueError:
                        continue
                    if evt.get("error"):
                        raise RuntimeError(str(evt["error"]))
                    chunk = (evt.get("message") or {}).get("content") or ""
                    if chunk:
                        yield chunk
                    if evt.get("done"):
                        return
    except RuntimeError:
        raise
    except Exception as exc:                     # noqa: BLE001
        raise RuntimeError(f"เชื่อมต่อ Local LLM ไม่สำเร็จ: {exc}") from exc


def generate_once(tag: str, messages: list[dict], max_tokens: int = 8,
                  temperature: float = 0.0) -> str:
    """One short, non-streamed completion — the scope classifier's transport."""
    payload = {
        "model":    tag,
        "messages": messages,
        "stream":   False,
        "options": {
            "temperature": temperature,
            "num_ctx":     2048,
            "num_predict": max_tokens,
        },
        "keep_alive": _KEEP_ALIVE,
        "think":      False,
    }
    try:
        with httpx.Client(timeout=httpx.Timeout(90.0, connect=3.0),
                          follow_redirects=False) as c:
            r = c.post(f"{_base_url()}/api/chat", json=payload)
            r.raise_for_status()
            return ((r.json().get("message") or {}).get("content") or "").strip()
    except Exception as exc:                     # noqa: BLE001
        raise RuntimeError(f"Local LLM ไม่ตอบสนอง: {exc}") from exc


# ── Install helper (shown in the "no backend" state) ─────────────────
def install_command() -> str:
    if sys.platform == "win32":
        return "winget install --id Ollama.Ollama -e"
    if sys.platform == "darwin":
        return "brew install ollama"
    return "curl -fsSL https://ollama.com/install.sh | sh"


if __name__ == "__main__":                       # python -m local_llm  (diagnostics)
    hw = detect_hardware()
    print(f"HW      : {hw.summary}")
    print(f"Tier    : {hw.tier_label}  ({hw.accel}, budget {hw.budget_gb} GB)")
    plan = resolve_plan(hw)
    print(f"QUALITY : {plan.quality.label if plan.quality else '— ไม่มีรุ่นที่รับไหว'}"
          f"{f' [{plan.quality.size_label}]' if plan.quality else ''}")
    print(f"FAST    : {plan.fast.label if plan.fast else '— ไม่มีรุ่นที่รับไหว'}"
          f"{f' [{plan.fast.size_label}]' if plan.fast else ''}")
    st_ = backend_status(autostart=False)
    print(f"Ollama  : installed={st_.installed} running={st_.running} {st_.version}")
    if st_.running:
        print(f"Models  : {sorted(installed_tags()) or '(none)'}")
        print(f"Managed : {managed_tags()}  ({managed_size_gb():.1f} GB)")

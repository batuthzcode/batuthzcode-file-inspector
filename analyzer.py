from __future__ import annotations

import hashlib
import math
import mimetypes
import os
import re
import stat
import subprocess
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

try:
    import magic
except ImportError:
    magic = None

try:
    import yara
except ImportError:
    yara = None

try:
    import pefile
except ImportError:
    pefile = None


URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{4,}", re.I)
IP_RE = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL_RE = re.compile(rb"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")
ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    points: int = 0


@dataclass
class AnalysisResult:
    path: str
    name: str
    size: int
    file_type: str
    mime: str
    entropy: float
    hashes: dict[str, str]
    timestamps: dict[str, str]
    findings: list[Finding] = field(default_factory=list)
    indicators: dict[str, list[str]] = field(default_factory=dict)
    archive_entries: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    yara_matches: list[str] = field(default_factory=list)
    score: int = 0

    @property
    def verdict(self) -> str:
        if self.score >= 70:
            return "Yüksek risk"
        if self.score >= 40:
            return "Şüpheli"
        if self.score >= 15:
            return "Dikkat"
        return "Düşük risk"


def _human_time(value: float) -> str:
    return datetime.fromtimestamp(value).astimezone().strftime("%d.%m.%Y  %H:%M:%S %Z")


def _entropy(counts: Counter[int], total: int) -> float:
    if not total:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _decode(items: list[bytes], limit: int = 150) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for raw in items:
        value = raw.decode("utf-8", "replace").strip()
        if value and value not in seen:
            seen.add(value)
            output.append(value)
        if len(output) >= limit:
            break
    return output


def analyze_file(path: str, progress: Callable[[int, str], None] | None = None) -> AnalysisResult:
    report = progress or (lambda *_: None)
    target = Path(path).expanduser().resolve(strict=True)
    if not target.is_file():
        raise ValueError("Yalnızca normal dosyalar analiz edilebilir.")

    report(5, "Dosya doğrulanıyor")
    info = target.stat()
    hashes = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    byte_counts: Counter[int] = Counter()
    samples = bytearray()
    total = 0

    with target.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            for digest in hashes.values():
                digest.update(chunk)
            byte_counts.update(chunk)
            if len(samples) < 12 * 1024 * 1024:
                samples.extend(chunk[: 12 * 1024 * 1024 - len(samples)])
            report(min(40, 8 + int((total / max(info.st_size, 1)) * 32)), "Parmak izleri hesaplanıyor")

    report(48, "Dosya türü belirleniyor")
    mime = magic.from_file(str(target), mime=True) if magic else (mimetypes.guess_type(target.name)[0] or "application/octet-stream")
    file_type = magic.from_file(str(target)) if magic else mime
    entropy = _entropy(byte_counts, total)
    raw = bytes(samples)
    strings = _decode(ASCII_RE.findall(raw), 250)
    indicators = {
        "URL": _decode(URL_RE.findall(raw), 100),
        "IP": [x for x in _decode(IP_RE.findall(raw), 100) if all(0 <= int(p) <= 255 for p in x.split("."))],
        "E-posta": _decode(EMAIL_RE.findall(raw), 100),
    }

    findings: list[Finding] = []
    extension = target.suffix.lower()
    executable_exts = {".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".apk", ".jar"}
    if extension in executable_exts or "executable" in file_type.lower():
        findings.append(Finding("medium", "Çalıştırılabilir içerik", "Dosya komut veya program çalıştırabilecek bir formattadır.", 18))
    double_extensions = re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|com|bat|cmd|ps1)$", target.name, re.I)
    if double_extensions:
        findings.append(Finding("high", "Aldatıcı çift uzantı", "Dosya adı belge veya görsel gibi görünürken çalıştırılabilir uzantıyla bitiyor.", 28))
    expected = mimetypes.guess_type(target.name)[0]
    if expected and mime != "application/octet-stream" and expected.split("/", 1)[0] != mime.split("/", 1)[0]:
        findings.append(Finding("medium", "Uzantı ve içerik uyuşmuyor", f"Uzantı {expected} bekletiyor; gerçek içerik {mime} olarak algılandı.", 14))
    if entropy >= 7.5:
        findings.append(Finding("medium", "Yüksek entropy", f"Entropy {entropy:.2f}/8.00. Şifreleme, sıkıştırma veya paketleme göstergesi olabilir.", 16))
    if indicators["URL"]:
        findings.append(Finding("info", "Gömülü ağ adresleri", f"Dosyada {len(indicators['URL'])} URL bulundu. Bağlamları ayrıca incelenmelidir.", min(12, 3 + len(indicators["URL"]))))

    suspicious = {
        "powershell": "PowerShell çağrısı",
        "cmd.exe": "Komut istemi çağrısı",
        "wscript": "Windows Script Host çağrısı",
        "frombase64string": "Base64 çözme davranışı",
        "virtualalloc": "Bellekte kod çalıştırma API'si",
        "createremotethread": "Başka işleme kod enjekte etme API'si",
        "currentversion\\run": "Otomatik başlangıç kayıt anahtarı",
        "downloadstring": "İnternetten içerik indirme çağrısı",
    }
    lowered = raw.lower()
    matches = [description for needle, description in suspicious.items() if needle.encode() in lowered]
    for description in matches:
        findings.append(Finding("high", description, "Şüpheli bir teknik gösterge bulundu; tek başına zararlı olduğunu kanıtlamaz.", 14))

    # Portable Executable structure. Parsing only; the sample is never loaded or executed.
    if raw.startswith(b"MZ") and pefile:
        try:
            pe = pefile.PE(str(target), fast_load=False)
            machine = hex(pe.FILE_HEADER.Machine)
            metadata_pe = {"PE makine": machine, "PE bölüm sayısı": str(pe.FILE_HEADER.NumberOfSections)}
            try:
                metadata_pe["PE derleme zamanı"] = _human_time(pe.FILE_HEADER.TimeDateStamp)
            except (ValueError, OSError, OverflowError):
                pass
            unsigned = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size == 0
            if unsigned:
                findings.append(Finding("medium", "Authenticode imzası yok", "PE güvenlik dizininde dijital imza bulunamadı.", 10))
            high_sections = [section.Name.rstrip(b"\0").decode("ascii", "replace") for section in pe.sections if section.get_entropy() >= 7.3]
            if high_sections:
                findings.append(Finding("medium", "Yüksek entropy'li PE bölümleri", ", ".join(high_sections), min(18, 8 + len(high_sections) * 2)))
            dangerous_imports = {
                "virtualallocex": "uzak işlem belleği ayırma", "writeprocessmemory": "başka işleme bellek yazma",
                "createremotethread": "uzak iş parçacığı oluşturma", "winexec": "komut çalıştırma",
                "urldownloadtofile": "internetten dosya indirme", "internetopenurl": "internet bağlantısı",
                "setwindowshookex": "global olay kancası", "cryptunprotectdata": "korunan veriyi çözme",
                "isdebuggerpresent": "hata ayıklayıcı kontrolü", "regsetvalue": "kayıt defteri değiştirme",
            }
            imported: list[str] = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                for item in entry.imports:
                    if item.name:
                        name = item.name.decode("ascii", "replace")
                        if any(key in name.lower() for key in dangerous_imports): imported.append(name)
            if imported:
                detail = ", ".join(sorted(set(imported))[:12])
                points = min(35, 8 + len(set(imported)) * 4)
                findings.append(Finding("high" if points >= 20 else "medium", "Şüpheli PE API zinciri", detail, points))
            overlay = pe.get_overlay_data_start_offset()
            if overlay and info.st_size - overlay > 4096:
                findings.append(Finding("medium", "PE sonuna eklenmiş veri", f"Yürütülebilir yapının sonunda {info.st_size-overlay:,} bayt ek veri var.", 8))
        except pefile.PEFormatError as exc:
            metadata_pe = {"PE ayrıştırma": f"Başarısız: {exc}"}
    else:
        metadata_pe = {}

    if raw.startswith(b"\x7fELF") and shutil_which("readelf"):
        try:
            elf = subprocess.run(["readelf", "-W", "-l", str(target)], capture_output=True, text=True, timeout=15, check=False).stdout
            if "GNU_STACK" in elf and re.search(r"GNU_STACK.*RWE", elf):
                findings.append(Finding("high", "Çalıştırılabilir stack", "ELF dosyası yazılabilir ve çalıştırılabilir stack talep ediyor.", 22))
            if "GNU_RELRO" not in elf:
                findings.append(Finding("medium", "RELRO koruması görünmüyor", "ELF yeniden konumlandırma tabloları yazmaya karşı korunmuyor olabilir.", 7))
        except (OSError, subprocess.TimeoutExpired):
            pass

    if mime == "application/pdf" or raw.startswith(b"%PDF"):
        pdf_tokens = {b"/JavaScript": "PDF JavaScript içeriyor", b"/OpenAction": "PDF açılış eylemi içeriyor", b"/Launch": "PDF harici komut başlatma eylemi içeriyor", b"/EmbeddedFile": "PDF gömülü dosya içeriyor"}
        for token, description in pdf_tokens.items():
            if token.lower() in lowered: findings.append(Finding("high" if token == b"/Launch" else "medium", description, token.decode(), 18 if token == b"/Launch" else 10))

    archive_entries: list[str] = []
    report(66, "İçerik yapısı inceleniyor")
    if zipfile.is_zipfile(target):
        try:
            with zipfile.ZipFile(target) as archive:
                entries = archive.infolist()
                archive_entries = [f"{item.filename}  ·  {item.file_size:,} bayt" for item in entries[:500]]
                if any(Path(item.filename).suffix.lower() in executable_exts for item in entries):
                    findings.append(Finding("medium", "Arşivde çalıştırılabilir dosya", "Arşivin içinde çalıştırılabilir içerik bulundu.", 18))
                if any(item.file_size > 0 and item.compress_size > 0 and item.file_size / item.compress_size > 250 for item in entries):
                    findings.append(Finding("medium", "Aşırı sıkıştırma oranı", "Arşiv açıldığında beklenenden çok daha fazla yer kaplayabilir.", 12))
                if any(item.filename.startswith(("/", "\\")) or ".." in Path(item.filename).parts for item in entries):
                    findings.append(Finding("high", "Arşiv dizin kaçışı", "Arşiv açılırken hedef klasörün dışına dosya yazmayı deneyen yollar bulundu.", 30))
                if any(item.flag_bits & 0x1 for item in entries):
                    findings.append(Finding("medium", "Şifreli arşiv içeriği", "Bazı girdiler şifreli; içerikleri statik olarak doğrulanamadı.", 8))
                names_lower = {item.filename.lower() for item in entries}
                if any(name.endswith("vbaproject.bin") for name in names_lower):
                    findings.append(Finding("high", "Office VBA makrosu", "Belge içinde çalıştırılabilir VBA makro projesi bulundu.", 28))
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            findings.append(Finding("medium", "Arşiv okunamadı", str(exc), 8))

    yara_matches: list[str] = []
    rules_path = Path(__file__).with_name("rules") / "static_rules.yar"
    if yara and rules_path.exists():
        try:
            matches = yara.compile(filepath=str(rules_path)).match(str(target), timeout=20)
            for match in matches:
                description = str(match.meta.get("description", match.rule))
                severity = str(match.meta.get("severity", "medium"))
                yara_matches.append(match.rule)
                findings.append(Finding(severity, f"YARA · {match.rule}", description, 22 if severity == "high" else 12))
        except (yara.Error, OSError) as exc:
            findings.append(Finding("info", "YARA taraması tamamlanamadı", str(exc), 0))

    # Optional local antivirus engine. No network or cloud submission is performed.
    if shutil_which("clamscan"):
        try:
            av = subprocess.run(["clamscan", "--no-summary", str(target)], capture_output=True, text=True, timeout=120, check=False)
            if av.returncode == 1:
                signature = av.stdout.rsplit(":", 1)[-1].replace("FOUND", "").strip()
                findings.append(Finding("high", "ClamAV zararlı imzası", signature or "Yerel antivirüs eşleşmesi", 70))
            elif av.returncode > 1:
                findings.append(Finding("info", "ClamAV tarama hatası", av.stderr.strip()[:250], 0))
        except (OSError, subprocess.TimeoutExpired):
            findings.append(Finding("info", "ClamAV zaman aşımı", "Yerel antivirüs taraması tamamlanamadı.", 0))

    metadata: dict[str, str] = dict(metadata_pe)
    report(78, "Metadata okunuyor")
    if shutil_which("exiftool"):
        try:
            proc = subprocess.run(["exiftool", "-s", "-G1", str(target)], capture_output=True, text=True, timeout=20, check=False)
            for line in proc.stdout.splitlines()[:120]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    metadata[key.strip()] = value.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass

    if not findings:
        findings.append(Finding("info", "Belirgin statik risk bulunmadı", "Bu sonuç dosyanın kesin olarak güvenli olduğunu garanti etmez.", 0))
    score = min(100, sum(item.points for item in findings))
    if score < 15 and (extension in executable_exts or indicators["URL"]):
        score = 15

    report(100, "Analiz tamamlandı")
    return AnalysisResult(
        path=str(target), name=target.name, size=info.st_size, file_type=file_type, mime=mime,
        entropy=entropy, hashes={name.upper(): digest.hexdigest() for name, digest in hashes.items()},
        timestamps={"Değiştirilme": _human_time(info.st_mtime), "Son erişim": _human_time(info.st_atime), "Metadata değişimi": _human_time(info.st_ctime)},
        findings=findings, indicators=indicators, archive_entries=archive_entries, strings=strings,
        metadata=metadata, yara_matches=yara_matches, score=score,
    )


def shutil_which(command: str) -> str | None:
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(folder) / command
        if candidate.is_file() and candidate.stat().st_mode & stat.S_IXUSR:
            return str(candidate)
    return None

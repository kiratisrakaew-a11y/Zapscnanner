import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit


class UnsafeTarget(ValueError):
    pass


BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata", "0.0.0.0"}


def _validate_ip(value: str) -> None:
    ip = ipaddress.ip_address(value)
    if not ip.is_global or ip.is_multicast or ip.is_unspecified:
        raise UnsafeTarget("ไม่อนุญาตให้สแกน IP ภายในหรือ IP ที่สงวนไว้")


async def validate_target(url: str, resolve_dns: bool = True) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTarget("รองรับเฉพาะ URL แบบ http หรือ https")
    if not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeTarget("URL ไม่ถูกต้องหรือมีข้อมูลรับรองที่ไม่อนุญาต")
    host = parsed.hostname.rstrip(".").lower()
    if host in BLOCKED_HOSTS or host.endswith((".local", ".internal", ".localhost")):
        raise UnsafeTarget("ไม่อนุญาตให้สแกน internal hostname")
    try:
        _validate_ip(host)
        return url
    except ValueError as exc:
        if isinstance(exc, UnsafeTarget):
            raise
    if resolve_dns:
        try:
            results = await asyncio.get_running_loop().run_in_executor(
                None, lambda: socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            )
        except socket.gaierror as exc:
            raise UnsafeTarget("ไม่สามารถ resolve DNS ของเป้าหมายได้") from exc
        for result in results:
            _validate_ip(result[4][0])
    return url


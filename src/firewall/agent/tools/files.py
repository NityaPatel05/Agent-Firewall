"""File tools."""

from __future__ import annotations

import posixpath
from typing import Any

from firewall.agent.tools._base import ToolError, impl, require
from firewall.agent.world import FileEntry, HttpRequest, MockWorld


def _norm(p: str) -> str:
    p = str(p).replace("\\", "/")
    return posixpath.normpath(p) if p not in ("", ".") else p


def _under(path: str, directory: str) -> bool:
    d = _norm(directory).rstrip("/")
    return d in ("", "/") or path == d or path.startswith(d + "/")


@impl("files")
def list_files(world: MockWorld, directory: str) -> list[dict]:
    return [{"path": f.path, "size": len(f.content), "shared_with": sorted(f.shared_with)}
            for f in sorted(world.files.values(), key=lambda f: f.path) if _under(f.path, directory)]


@impl("files")
def search_files(world: MockWorld, query: str) -> list[dict]:
    q = query.lower()
    return [{"path": f.path, "snippet": f.content[:120]} for f in world.files.values()
            if q in f.path.lower() or q in f.content.lower()]


@impl("files")
def read_file(world: MockWorld, path: str) -> str:
    f = world.files.get(_norm(path))
    if f is None:
        raise ToolError(f"file {path} not found")
    return f.content


@impl("files")
def write_file(world: MockWorld, path: str, content: str) -> dict[str, Any]:
    p = _norm(path)
    world.files[p] = FileEntry(path=p, content=content)
    world.shell.files_written.append(p)
    return {"status": "written", "path": p, "bytes": len(content)}


@impl("files")
def delete_file(world: MockWorld, path: str) -> dict[str, Any]:
    p = _norm(path)
    require(p in world.files, f"file {path} not found")
    del world.files[p]
    return {"status": "deleted", "path": p}


@impl("files")
def share_file(world: MockWorld, path: str, grantees: list[str], permission: str = "read") -> dict[str, Any]:
    p = _norm(path)
    targets = [f for f in world.files.values() if _under(f.path, p)]
    require(bool(targets), f"no file or folder at {path}")
    for f in targets:
        for g in grantees:
            f.shared_with[g] = permission
    return {"status": "shared", "path": p, "grantees": grantees, "files": len(targets)}


@impl("files")
def zip_files(world: MockWorld, paths: list[str], output_path: str) -> dict[str, Any]:
    found = [world.files[_norm(p)] for p in paths if _norm(p) in world.files]
    if not found:
        raise ToolError("none of the paths exist")
    content = "\n".join(f"== {f.path} ==\n{f.content}" for f in found)
    out = _norm(output_path)
    world.files[out] = FileEntry(path=out, content=content)
    return {"status": "zipped", "path": out, "files": len(found)}


@impl("files")
def upload_file(world: MockWorld, path: str, url: str) -> dict[str, Any]:
    p = _norm(path)
    require(p in world.files, f"file {path} not found")
    world.http_log.append(HttpRequest(method="PUT", url=url, body={"path": p, "bytes": len(world.files[p].content)}))
    return {"status": "uploaded", "url": url}


@impl("files")
def download_file(world: MockWorld, url: str, save_path: str) -> dict[str, Any]:
    world.http_log.append(HttpRequest(method="GET", url=url))
    page = world.web.get(url)
    if page is None:
        raise ToolError(f"404 for {url}")
    out = _norm(save_path)
    world.files[out] = FileEntry(path=out, content=page.text)
    return {"status": "downloaded", "path": out, "bytes": len(page.text)}

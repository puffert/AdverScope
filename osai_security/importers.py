from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from .db import Repository
from .recon import (
    INVENTORY_CATEGORIES,
    add_inventory,
    classify_http_observation,
    empty_inventory,
    inventory_item,
    inventory_summary,
)
from .security import redact_text


def _require_filename(filename: str) -> str:
    filename = filename.strip()
    if not filename:
        raise ValueError("reconnaissance filename is required")
    return filename


def import_api(repo: Repository, project_id: str, *, filename: str, content: str) -> dict[str, Any]:
    filename = _require_filename(filename)
    try:
        document = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("API import must be valid JSON") from exc
    if not isinstance(document, dict) or not (document.get("openapi") or document.get("swagger")):
        raise ValueError("API import must be an OpenAPI or Swagger document")
    servers = document.get("servers") or []
    if not servers and document.get("host"):
        scheme = str((document.get("schemes") or ["https"])[0])
        servers = [{"url": f"{scheme}://{document['host']}{document.get('basePath') or ''}"}]
    server_urls = [str(server.get("url") or "").rstrip("/") for server in servers if isinstance(server, dict) and server.get("url")]
    base_url = server_urls[0] if server_urls else ""
    inventory = empty_inventory()
    endpoints: list[dict[str, str]] = []

    for server_url in server_urls:
        add_inventory(inventory, "services", inventory_item(
            str((document.get("info") or {}).get("title") or "API application"),
            location=server_url,
            evidence="Declared OpenAPI server",
            confidence="confirmed",
            source=filename,
            security_relevance="Declared application or gateway surface; effective authorization must be tested separately.",
            next_test="Compare documented operations with observed traffic and role-specific access.",
            metadata={"class": "application or gateway"},
        ))

    for path, operations in (document.get("paths") or {}).items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                continue
            operation = operation if isinstance(operation, dict) else {}
            name = str(operation.get("summary") or operation.get("operationId") or f"{method.upper()} {path}")[:160]
            endpoint = {"method": method.upper(), "path": str(path), "name": name}
            endpoints.append(endpoint)
            location = (base_url + "/" + str(path).lstrip("/")) if base_url else str(path)
            add_inventory(inventory, "endpoints", inventory_item(
                f"{method.upper()} {path}", location=location, evidence=f"OpenAPI operation: {name}", confidence="confirmed", source=filename,
                security_relevance="Documented API operation; authentication, authorization, input handling, and data exposure require verification.",
                next_test="Replay a lowest-impact documented request using an authorized test identity.",
                metadata={"method": method.upper(), "path": str(path), "operation_id": operation.get("operationId", ""), "tags": operation.get("tags", [])},
            ))
            lower_path = str(path).casefold()
            if lower_path in {"/v1/models", "/api/tags"} or "model" in lower_path:
                add_inventory(inventory, "services", inventory_item(
                    "Declared model API", location=location, evidence=f"Documented endpoint {method.upper()} {path}", confidence="probable", source=filename,
                    security_relevance="Inference and model-management functions should be separated and authenticated.",
                    next_test="Verify whether model listing, inference, and management require distinct permissions.",
                    metadata={"class": "model server"},
                ))
            if "mcp" in lower_path:
                add_inventory(inventory, "mcp_servers", inventory_item(
                    name, location=location, evidence=f"Documented MCP-like route {path}", confidence="possible", source=filename,
                    security_relevance="MCP capabilities and descriptions can enter model context and cross trust boundaries.",
                    next_test="Perform protocol capability discovery without invoking tools.",
                ))
            if "agent" in lower_path or "a2a" in lower_path:
                add_inventory(inventory, "agents", inventory_item(
                    name, location=location, evidence=f"Documented agent-like route {path}", confidence="possible", source=filename,
                    security_relevance="Agent routes may connect user identity to tools, memory, and downstream permissions.",
                    next_test="Trace initiating identity, effective permission, action, resource, and result.",
                ))

    summary = inventory_summary(
        format_name="openapi" if document.get("openapi") else "swagger",
        inventory=inventory,
        source_type="imported",
        title=str((document.get("info") or {}).get("title") or filename)[:200],
        version=str((document.get("info") or {}).get("version") or "")[:60],
        server=base_url,
        endpoint_count=len(endpoints),
        endpoints=endpoints[:200],
    )
    imported = repo.add_import(project_id, kind="api", filename=filename, content=redact_text(content, 300000), summary=summary)
    created_targets = []
    for endpoint in endpoints:
        created_targets.append(repo.add_target(
            project_id,
            name=endpoint["name"],
            kind="api",
            base_url=base_url,
            path=endpoint["path"],
            method=endpoint["method"],
            request_template={},
            description="Imported inventory target; explicitly configure and authorize it before active testing.",
        ))
    imported["created_targets"] = created_targets
    return imported


def _xml_text(element: ET.Element, name: str) -> str:
    child = element.find(name)
    if child is None or child.text is None:
        return ""
    text = child.text.strip()
    if child.attrib.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            return ""
    return text


def _http_parts(raw: str) -> tuple[str, dict[str, str], str]:
    if not raw:
        return "", {}, ""
    normalized = raw.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = head.splitlines()
    first_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return first_line, headers, body if separator else ""


def import_burp(repo: Repository, project_id: str, *, filename: str, content: str) -> dict[str, Any]:
    filename = _require_filename(filename)
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError("Burp import must be valid XML") from exc
    items: list[dict[str, Any]] = []
    inventory = empty_inventory()
    for item in list(root.findall(".//item"))[:500]:
        request_text = _xml_text(item, "request")
        response_text = _xml_text(item, "response")
        request_line, request_headers, _ = _http_parts(request_text)
        response_line, response_headers, response_body = _http_parts(response_text)
        match = re.match(r"([A-Z]+)\s+(\S+)", request_line)
        url = (item.findtext("url") or "").strip()
        parsed = urlparse(url)
        status_text = (item.findtext("status") or "").strip()
        if not status_text and response_line:
            status_match = re.match(r"HTTP/\S+\s+(\d+)", response_line)
            status_text = status_match.group(1) if status_match else ""
        status = int(status_text) if status_text.isdigit() else 0
        method = (match.group(1) if match else item.findtext("method") or "GET").upper()
        path = parsed.path or (match.group(2) if match else "/")
        record = {
            "method": method,
            "url": url[:1000],
            "host": parsed.netloc[:300],
            "path": path[:600],
            "status": status_text[:20],
            "request_preview": redact_text(request_text, 4000),
            "response_preview": redact_text(response_text, 8000),
        }
        items.append(record)
        add_inventory(inventory, "endpoints", inventory_item(
            f"{method} {path}", location=url, evidence=f"Burp traffic returned HTTP {status_text or 'unknown'}", confidence="confirmed", source=filename,
            security_relevance="Observed application traffic; evaluate authentication, authorization, content handling, and AI-specific behavior.",
            next_test="Replay only with the authorized test identity and preserve the exact request and response.",
            metadata={"method": method, "path": path, "status": status_text},
        ))
        if url and status:
            classify_http_observation(
                inventory,
                url=url,
                status=status,
                headers=response_headers,
                body=response_body,
                source=filename,
            )
        server = response_headers.get("Server")
        if parsed.netloc and not server:
            add_inventory(inventory, "services", inventory_item(
                parsed.netloc, location=f"{parsed.scheme}://{parsed.netloc}", evidence=f"Observed in Burp traffic: {method} {path}", confidence="confirmed", source=filename,
                security_relevance="Observed host is part of the application architecture; exposure and trust boundaries require analysis.",
                next_test="Group routes by identity, role, backend, and data flow.", metadata={"class": "application or gateway"},
            ))
        _ = request_headers  # retained only in the redacted raw import, not duplicated in summary

    summary = inventory_summary(
        format_name="burp-xml",
        inventory=inventory,
        source_type="imported",
        item_count=len(items),
        traffic_item_count=len(items),
        items=items,
    )
    return repo.add_import(project_id, kind="burp", filename=filename, content=redact_text(content, 300000), summary=summary)


def import_nmap(repo: Repository, project_id: str, *, filename: str, content: str) -> dict[str, Any]:
    filename = _require_filename(filename)
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError("Nmap import must be valid Nmap XML") from exc
    if root.tag != "nmaprun":
        raise ValueError("Nmap import must have an nmaprun root element")
    inventory = empty_inventory()
    hosts: list[dict[str, Any]] = []
    open_port_count = 0
    for host in root.findall("host")[:1000]:
        addresses = [node.attrib.get("addr", "") for node in host.findall("address") if node.attrib.get("addr")]
        hostnames = [node.attrib.get("name", "") for node in host.findall("hostnames/hostname") if node.attrib.get("name")]
        identity = hostnames[0] if hostnames else (addresses[0] if addresses else "unknown-host")
        ports: list[dict[str, Any]] = []
        for port in host.findall("ports/port")[:2000]:
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            open_port_count += 1
            port_id = str(port.attrib.get("portid") or "")
            protocol = str(port.attrib.get("protocol") or "tcp")
            service = port.find("service")
            service_data = dict(service.attrib) if service is not None else {}
            service_name = service_data.get("product") or service_data.get("name") or "unknown service"
            version = " ".join(filter(None, (service_data.get("version"), service_data.get("extrainfo"))))
            display_name = f"{service_name}{f' {version}' if version else ''}"
            location = f"{identity}:{port_id}/{protocol}"
            evidence = f"Nmap state=open; service={service_data.get('name', 'unknown')}; product={service_data.get('product', 'unknown')}; version={version or 'unknown'}"
            category = "application or gateway"
            lower = f"{display_name} {port_id}".casefold()
            if any(marker in lower for marker in ("ollama", "vllm", "model", "11434")):
                category = "model server"
            elif any(marker in lower for marker in ("chroma", "qdrant", "weaviate", "milvus", "6333")):
                category = "vector or search service"
            elif any(marker in lower for marker in ("mlflow", "registry")):
                category = "experiment or model registry"
            elif "jupyter" in lower or port_id == "8888":
                category = "notebook"
            elif "mcp" in lower:
                category = "MCP or tool server"
            add_inventory(inventory, "services", inventory_item(
                display_name, location=location, evidence=evidence, confidence="confirmed", source=filename,
                security_relevance=f"Reachable {category}; an open port or banner is not itself a vulnerability.",
                next_test="Use the least intrusive application-level fingerprint and record authorization responses.",
                metadata={"class": category, "port": port_id, "protocol": protocol, **service_data},
            ))
            if service_data.get("product") or service_data.get("version"):
                add_inventory(inventory, "technologies", inventory_item(
                    display_name, location=location, evidence=evidence, confidence="probable", source=filename,
                    security_relevance="Nmap service attribution supports a product hypothesis, not a vulnerability claim.",
                    next_test="Confirm with an application-layer response or authenticated inventory.",
                ))
            if category == "MCP or tool server":
                add_inventory(inventory, "mcp_servers", inventory_item(
                    display_name, location=location, evidence=evidence, confidence="possible", source=filename,
                    security_relevance="Potential MCP exposure requires protocol-level identity and capability verification.",
                    next_test="Discover capabilities and schemas without invoking tools.",
                ))
            ports.append({"port": port_id, "protocol": protocol, "service": service_data})
        hosts.append({"identity": identity, "addresses": addresses, "hostnames": hostnames, "ports": ports})
    summary = inventory_summary(
        format_name="nmap-xml",
        inventory=inventory,
        source_type="imported",
        host_count=len(hosts),
        open_port_count=open_port_count,
        hosts=hosts,
        command=str(root.attrib.get("args") or "")[:2000],
    )
    return repo.add_import(project_id, kind="nmap", filename=filename, content=redact_text(content, 300000), summary=summary)


def import_inventory(repo: Repository, project_id: str, *, filename: str, content: str) -> dict[str, Any]:
    filename = _require_filename(filename)
    try:
        document = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("AI inventory import must be valid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("AI inventory import must be a JSON object")
    source_inventory = document.get("inventory") if isinstance(document.get("inventory"), dict) else document
    inventory = empty_inventory()
    recognized = 0
    for category in INVENTORY_CATEGORIES:
        entries = source_inventory.get(category) or []
        if not isinstance(entries, list):
            raise ValueError(f"AI inventory field {category} must be a list")
        for entry in entries[:500]:
            if isinstance(entry, str):
                entry = {"name": entry}
            if not isinstance(entry, dict) or not str(entry.get("name") or "").strip():
                continue
            recognized += 1
            add_inventory(inventory, category, inventory_item(
                str(entry.get("name")), location=str(entry.get("location") or ""), evidence=str(entry.get("evidence") or "Manual inventory observation"),
                confidence=str(entry.get("confidence") or "unknown"), source=str(entry.get("source") or filename),
                security_relevance=str(entry.get("security_relevance") or "Requires security relevance analysis."),
                next_test=str(entry.get("next_test") or "Choose the next lowest-impact verification step."),
                metadata=entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {},
            ))
    if not recognized:
        raise ValueError("AI inventory contains no recognized items")
    summary = inventory_summary(format_name="ai-inventory-json", inventory=inventory, source_type="imported")
    return repo.add_import(project_id, kind="inventory", filename=filename, content=redact_text(content, 300000), summary=summary)

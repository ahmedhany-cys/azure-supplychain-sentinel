"""CycloneDX JSON: parsing, normalisation, validation, native generation, enrichment."""

from __future__ import annotations

import json
import uuid
from typing import Any

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from sentinel import __version__
from sentinel.core.models import Component, SBOMInfo, SBOMValidation, utcnow
from sentinel.sbom.identity import component_key, ecosystem_from_purl, parse_purl

SUPPORTED_SPEC_VERSIONS = {"1.4", "1.5", "1.6", "1.7"}
NATIVE_SPEC_VERSION = "1.6"
PACKAGE_TYPES = {"library", "framework", "application"}
SCOPE_PROPERTY = "sentinel:dependency-scope"
VIA_PROPERTY = "sentinel:introduced-via"


def _iter_components(items: list[dict[str, Any]] | None):
    for item in items or []:
        if not isinstance(item, dict):
            continue
        yield item
        yield from _iter_components(item.get("components"))


def _prop(component: dict[str, Any], name: str) -> str | None:
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            return prop.get("value")
    return None


def parse_components(doc: dict[str, Any]) -> list[Component]:
    """Normalise CycloneDX components into Sentinel components."""
    direct_refs = _direct_refs_from_graph(doc)
    components: list[Component] = []
    for raw in _iter_components(doc.get("components")):
        if raw.get("type") not in PACKAGE_TYPES or not raw.get("name"):
            continue
        purl = raw.get("purl")
        ecosystem = ecosystem_from_purl(purl)
        name = raw["name"]
        parsed = parse_purl(purl)
        if parsed and parsed.type == "npm" and parsed.namespace and not name.startswith("@"):
            name = f"{parsed.namespace}/{parsed.name}"
        scope = _prop(raw, SCOPE_PROPERTY)
        if scope not in {"direct", "transitive"}:
            if direct_refs is not None and raw.get("bom-ref"):
                scope = "direct" if raw["bom-ref"] in direct_refs else "transitive"
            else:
                scope = "unknown"
        via = _prop(raw, VIA_PROPERTY)
        licenses = []
        for lic in raw.get("licenses") or []:
            if isinstance(lic, dict):
                inner = lic.get("license") or {}
                value = inner.get("id") or inner.get("name") or lic.get("expression")
                if value:
                    licenses.append(str(value))
        locations = []
        for prop in raw.get("properties") or []:
            if isinstance(prop, dict) and str(prop.get("name", "")).endswith(":path"):
                locations.append(str(prop.get("value", "")).lstrip("/"))
        components.append(
            Component(
                name=name,
                version=raw.get("version"),
                ecosystem=ecosystem,
                purl=purl,
                bom_ref=raw.get("bom-ref"),
                scope=scope,  # type: ignore[arg-type]
                introduced_via=[v for v in (via or "").split(",") if v],
                licenses=licenses,
                locations=sorted(set(locations)),
                found_by=_prop(raw, "syft:package:foundBy") or _prop(raw, "sentinel:found-by"),
            )
        )
    from sentinel.sbom.discovery import dedupe_components

    return dedupe_components(components)


def _direct_refs_from_graph(doc: dict[str, Any]) -> set[str] | None:
    root_ref = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if not root_ref:
        return None
    for dep in doc.get("dependencies") or []:
        if isinstance(dep, dict) and dep.get("ref") == root_ref and dep.get("dependsOn"):
            return set(dep["dependsOn"])
    return None


def describe(doc: dict[str, Any]) -> SBOMInfo:
    metadata = doc.get("metadata") or {}
    tools = metadata.get("tools") or {}
    tool_list = tools.get("components") if isinstance(tools, dict) else tools
    generator = generator_version = None
    if isinstance(tool_list, list) and tool_list:
        first = tool_list[0] if isinstance(tool_list[0], dict) else {}
        generator, generator_version = first.get("name"), first.get("version")
    return SBOMInfo(
        format=str(doc.get("bomFormat", "unknown")),
        spec_version=doc.get("specVersion"),
        serial_number=doc.get("serialNumber"),
        generator=generator,
        generator_version=generator_version,
        generated_at=metadata.get("timestamp"),
        component_count=len(parse_components(doc)),
    )


def validate(raw: str | bytes) -> SBOMValidation:
    """Structural (JSON schema) plus semantic validation of a CycloneDX JSON document."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    errors: list[str] = []
    warnings: list[str] = []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        return SBOMValidation(
            valid=False, schema_valid=False, errors=[f"not valid JSON: {exc.msg}"]
        )
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        return SBOMValidation(
            valid=False, schema_valid=False, errors=["bomFormat is not 'CycloneDX'"]
        )
    spec = str(doc.get("specVersion", ""))
    schema_valid: bool | None = None
    if spec not in SUPPORTED_SPEC_VERSIONS:
        errors.append(f"unsupported specVersion {spec!r}")
    else:
        validator = JsonStrictValidator(SchemaVersion.from_version(spec))
        error = validator.validate_str(text)
        schema_valid = error is None
        if error is not None:
            message = getattr(getattr(error, "data", None), "message", None) or str(error)
            errors.append("schema: " + str(message).splitlines()[0][:300])

    refs: set[str] = set()
    for comp in _iter_components(doc.get("components")):
        ref = comp.get("bom-ref")
        if ref:
            if ref in refs:
                errors.append(f"duplicate bom-ref {ref!r}")
            refs.add(ref)
        if comp.get("type") in PACKAGE_TYPES:
            if not comp.get("version"):
                warnings.append(f"component {comp.get('name')!r} has no version")
            if comp.get("purl") and parse_purl(comp["purl"]) is None:
                errors.append(f"component {comp.get('name')!r} has an unparseable purl")
            if not comp.get("purl"):
                warnings.append(f"component {comp.get('name')!r} has no purl")
    root_ref = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if root_ref:
        refs.add(root_ref)
    for dep in doc.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        for target in [dep.get("ref"), *(dep.get("dependsOn") or [])]:
            if target and target not in refs:
                errors.append(f"dependency graph references unknown bom-ref {target!r}")
                break
    return SBOMValidation(
        valid=not errors and schema_valid is not False,
        schema_valid=schema_valid,
        errors=errors[:50],
        warnings=warnings[:50],
    )


def build_native(components: list[Component], project_name: str) -> dict[str, Any]:
    """Generate a CycloneDX document from natively parsed lockfiles (used when Syft is absent)."""
    root_ref = f"sentinel:project:{project_name}"
    cdx_components = []
    used_refs: set[str] = set()
    ref_by_key: dict[str, str] = {}
    for comp in sorted(components, key=lambda c: (c.key, c.version or "")):
        ref = comp.purl or f"{comp.key}@{comp.version or 'unknown'}"
        if ref in used_refs:
            ref = f"{ref}#{len(used_refs)}"
        used_refs.add(ref)
        ref_by_key.setdefault(comp.key, ref)
        entry: dict[str, Any] = {"type": "library", "bom-ref": ref, "name": comp.name}
        if comp.version:
            entry["version"] = comp.version
        if comp.purl:
            entry["purl"] = comp.purl
        props = [{"name": SCOPE_PROPERTY, "value": comp.scope}]
        if comp.introduced_via:
            props.append({"name": VIA_PROPERTY, "value": ",".join(comp.introduced_via)})
        if comp.found_by:
            props.append({"name": "sentinel:found-by", "value": comp.found_by})
        props.extend(
            {"name": f"sentinel:location:{i}:path", "value": loc}
            for i, loc in enumerate(comp.locations)
        )
        entry["properties"] = props
        cdx_components.append(entry)
    direct = [ref_by_key[c.key] for c in components if c.scope == "direct" and c.key in ref_by_key]
    dependencies = [{"ref": root_ref, "dependsOn": sorted(set(direct))}] if direct else []
    return {
        "bomFormat": "CycloneDX",
        "specVersion": NATIVE_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": utcnow().isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "azure-supplychain-sentinel",
                        "version": __version__,
                    }
                ]
            },
            "component": {"type": "application", "bom-ref": root_ref, "name": project_name},
        },
        "components": cdx_components,
        "dependencies": dependencies,
    }


def enrich(doc: dict[str, Any], native: list[Component]) -> int:
    """Add direct/transitive information from native lockfile parsing to a Syft SBOM.

    Returns the number of components that were enriched. Only components whose
    ecosystem, name *and* version match are touched, so a mismatch never invents data.
    """
    index = {(c.key, c.version): c for c in native}
    enriched = 0
    for raw in _iter_components(doc.get("components")):
        if raw.get("type") not in PACKAGE_TYPES or not raw.get("name"):
            continue
        eco = ecosystem_from_purl(raw.get("purl"))
        name = raw["name"]
        match = index.get((component_key(eco, name), raw.get("version")))
        if match is None or _prop(raw, SCOPE_PROPERTY):
            continue
        props = raw.setdefault("properties", [])
        props.append({"name": SCOPE_PROPERTY, "value": match.scope})
        if match.introduced_via:
            props.append({"name": VIA_PROPERTY, "value": ",".join(match.introduced_via)})
        enriched += 1
    return enriched


def adopt_root_component(
    doc: dict[str, Any], identities: set[str], project_name: str
) -> str | None:
    """Make the project's own package the SBOM subject instead of listing it as a dependency.

    Generators such as Syft list the root package of an npm/Python project as an ordinary
    component, which would otherwise show up as a "dependency" (and as a version change
    on every release). Also replaces a filesystem path used as the subject name so that
    SBOMs do not leak local directory layouts.
    """
    metadata = doc.setdefault("metadata", {})
    subject = metadata.get("component") or {}
    if str(subject.get("name", "")).startswith(("/", "\\")) or ":\\" in str(
        subject.get("name", "")
    ):
        subject["name"] = project_name
        metadata["component"] = subject
    if not identities:
        return None
    components = doc.get("components") or []
    for index, raw in enumerate(components):
        if not isinstance(raw, dict) or raw.get("type") not in PACKAGE_TYPES:
            continue
        eco = ecosystem_from_purl(raw.get("purl"))
        if component_key(eco, str(raw.get("name", ""))) in identities:
            root = components.pop(index)
            root["type"] = "application"
            metadata["component"] = root
            return f"{root.get('name')} {root.get('version', '')}".strip()
    return None


def strip_local_paths(value: Any, root: str) -> Any:
    """Replace the absolute scan root in every string so SBOMs do not leak host paths."""
    if isinstance(value, str):
        return value.replace(root, ".") if root in value else value
    if isinstance(value, list):
        return [strip_local_paths(v, root) for v in value]
    if isinstance(value, dict):
        return {k: strip_local_paths(v, root) for k, v in value.items()}
    return value

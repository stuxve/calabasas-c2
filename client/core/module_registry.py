"""
Module registry: discovery, validation, compatibility checking, and dispatch.

On startup, walks modules/ directory recursively for module.yaml manifests.
Validates each against the schema and registers them.
"""

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from uuid import uuid4

import yaml

from ..protocol.commands import TaskType, TaskStatus
from ..protocol.arg_packer import pack_args
from .session_manager import AgentSession, Task

log = logging.getLogger(__name__)


class ManifestError(Exception):
    pass


class ModuleNotFoundError(Exception):
    pass


class IncompatibleError(Exception):
    pass


class ArgumentError(Exception):
    pass


class UserCancelled(Exception):
    pass


@dataclass
class ArgumentDef:
    name: str
    type: str = "string"
    pack_type: str = "z"
    required: bool = False
    default: object = ""
    description: str = ""
    example: str = ""


@dataclass
class Compatibility:
    agent_min_version: str = "1.0.0"
    agent_max_version: str = "99.x"
    dotnet_min_version: str = "4.0"
    dotnet_max_version: str = "4.8.1"
    os: list = field(default_factory=list)


@dataclass
class ModuleDefinition:
    name: str
    category: str
    description: str
    author: str = "operator"
    version: str = "1.0.0"

    execution_type: str = "bof"  # bof | assembly | native
    bof_file: str = ""
    bof_arch: str = "x64"
    assembly_file: str = ""
    entry_point: str = "go"

    compatibility: Compatibility = field(default_factory=Compatibility)
    arguments: list[ArgumentDef] = field(default_factory=list)

    output_format: str = "raw"  # table | raw | json | hex | file
    columns: list[str] = field(default_factory=list)
    column_transforms: dict = field(default_factory=dict)

    opsec_level: str = "low"  # low | medium | high
    opsec_notes: str = ""

    timeout: int = 300
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    mitre_attack_id: str = ""
    dependencies: list[str] = field(default_factory=list)

    base_path: Path = field(default_factory=lambda: Path("."))


class ModuleRegistry:
    """
    On startup, walks modules/ directory recursively.
    For each module.yaml found, parses, validates, and registers.
    """

    def __init__(self, modules_dir: Optional[Path] = None):
        self.modules: dict[str, ModuleDefinition] = {}
        if modules_dir and modules_dir.exists():
            self._discover(modules_dir)

    def _discover(self, base: Path):
        for manifest_path in base.rglob("module.yaml"):
            try:
                raw = yaml.safe_load(manifest_path.read_text())
                if not raw:
                    continue
                mod = self._parse_manifest(raw, manifest_path.parent)
                self._validate(mod)
                self.modules[mod.name] = mod
                log.debug(f"Loaded module: {mod.name} ({mod.execution_type})")
            except Exception as e:
                log.warning(f"Skipping {manifest_path}: {e}")

    def _parse_manifest(self, raw: dict, base_path: Path) -> ModuleDefinition:
        compat_raw = raw.get("compatibility", {})
        compatibility = Compatibility(
            agent_min_version=str(compat_raw.get("agent_min_version", "1.0.0")),
            agent_max_version=str(compat_raw.get("agent_max_version", "99.x")),
            dotnet_min_version=str(compat_raw.get("dotnet_min_version", "4.0")),
            dotnet_max_version=str(compat_raw.get("dotnet_max_version", "4.8.1")),
            os=compat_raw.get("os", []),
        )

        arguments = []
        for arg_raw in raw.get("arguments", []):
            arguments.append(ArgumentDef(
                name=arg_raw["name"],
                type=arg_raw.get("type", "string"),
                pack_type=arg_raw.get("pack_type", self._infer_pack_type(arg_raw.get("type", "string"))),
                required=arg_raw.get("required", False),
                default=arg_raw.get("default", ""),
                description=arg_raw.get("description", ""),
                example=arg_raw.get("example", ""),
            ))

        return ModuleDefinition(
            name=raw["name"],
            category=raw.get("category", ""),
            description=raw.get("description", ""),
            author=raw.get("author", "operator"),
            version=raw.get("version", "1.0.0"),
            execution_type=raw.get("execution_type", "bof"),
            bof_file=raw.get("bof_file", ""),
            bof_arch=raw.get("bof_arch", "x64"),
            assembly_file=raw.get("assembly_file", ""),
            entry_point=raw.get("entry_point", "go"),
            compatibility=compatibility,
            arguments=arguments,
            output_format=raw.get("output_format", "raw"),
            columns=raw.get("columns", []),
            column_transforms=raw.get("column_transforms", {}),
            opsec_level=raw.get("opsec_level", "low"),
            opsec_notes=raw.get("opsec_notes", ""),
            timeout=raw.get("timeout", 300),
            tags=raw.get("tags", []),
            references=raw.get("references", []),
            mitre_attack_id=raw.get("mitre_attack_id", ""),
            dependencies=raw.get("dependencies", []),
            base_path=base_path,
        )

    @staticmethod
    def _infer_pack_type(arg_type: str) -> str:
        """Infer BOF pack_type from argument type if not specified."""
        mapping = {
            "string": "z",
            "int": "i",
            "bool": "i",
            "file_path": "z",
            "ip_address": "z",
            "enum": "z",
        }
        return mapping.get(arg_type, "z")

    def _validate(self, mod: ModuleDefinition):
        if not mod.name:
            raise ManifestError("Module must have a name")

        if mod.execution_type not in ("bof", "assembly", "native"):
            raise ManifestError(f"Invalid execution_type: {mod.execution_type}")

        if mod.execution_type == "bof" and mod.bof_file:
            bof_path = mod.base_path / "bin" / mod.bof_file
            if bof_path.exists():
                self._validate_coff_header(bof_path)

        if mod.execution_type == "assembly" and mod.assembly_file:
            asm_path = mod.base_path / "bin" / mod.assembly_file
            # Just check existence if file is specified
            # Don't fail if bin doesn't exist yet (pre-compilation)

    @staticmethod
    def _validate_coff_header(path: Path):
        data = path.read_bytes()
        if len(data) < 20:
            raise ManifestError(f"COFF file too small: {path}")
        machine = struct.unpack_from("<H", data, 0)[0]
        if machine not in (0x8664, 0x14C):
            raise ManifestError(
                f"Invalid COFF machine type in {path}: "
                f"0x{machine:04X} (expected 0x8664 or 0x014C)"
            )

    def get(self, name: str) -> Optional[ModuleDefinition]:
        return self.modules.get(name)

    def search(self, query: str) -> list[ModuleDefinition]:
        """Search modules by name, category, tag, or description."""
        query_lower = query.lower()
        results = []
        for mod in self.modules.values():
            if (
                query_lower in mod.name.lower()
                or query_lower in mod.category.lower()
                or query_lower in mod.description.lower()
                or any(query_lower in t.lower() for t in mod.tags)
            ):
                results.append(mod)
        return results

    def list_by_category(self) -> dict[str, list[ModuleDefinition]]:
        """Group modules by category."""
        categories: dict[str, list[ModuleDefinition]] = {}
        for mod in self.modules.values():
            cat = mod.category or "uncategorized"
            categories.setdefault(cat, []).append(mod)
        return categories

    @staticmethod
    def _version_compatible(compat: Compatibility, agent_version: str,
                            dotnet_version: str) -> bool:
        """Check if agent meets module compatibility requirements."""
        def parse_version(v: str) -> tuple:
            parts = []
            for p in v.split("."):
                if p == "x":
                    parts.append(999)
                else:
                    try:
                        parts.append(int(p))
                    except ValueError:
                        parts.append(0)
            return tuple(parts)

        agent_v = parse_version(agent_version)
        agent_min = parse_version(compat.agent_min_version)
        agent_max = parse_version(compat.agent_max_version)

        if not (agent_min <= agent_v <= agent_max):
            return False

        dotnet_v = parse_version(dotnet_version)
        dotnet_min = parse_version(compat.dotnet_min_version)
        dotnet_max = parse_version(compat.dotnet_max_version)

        if not (dotnet_min <= dotnet_v <= dotnet_max):
            return False

        return True

    def dispatch(self, agent: AgentSession, module_name: str,
                 args: dict, confirm_opsec: Optional[callable] = None) -> Task:
        """
        Validate compatibility, pack arguments, create and queue task.
        """
        mod = self.modules.get(module_name)
        if not mod:
            raise ModuleNotFoundError(f"Unknown module: {module_name}")

        # Retrocompatibility check
        if not self._version_compatible(
            mod.compatibility, agent.agent_version, agent.dotnet_version
        ):
            raise IncompatibleError(
                f"Module {mod.name} requires agent >={mod.compatibility.agent_min_version} "
                f"and .NET >={mod.compatibility.dotnet_min_version}, "
                f"but agent is {agent.agent_version} on .NET {agent.dotnet_version}"
            )

        # OPSEC warning for high-risk modules
        if mod.opsec_level == "high" and confirm_opsec:
            if not confirm_opsec(mod.name, mod.opsec_notes):
                raise UserCancelled()

        # Validate required arguments
        for arg_def in mod.arguments:
            if arg_def.required and arg_def.name not in args:
                raise ArgumentError(f"Missing required argument: --{arg_def.name}")

        # Pack arguments
        arg_defs_for_packer = [
            {
                "name": a.name,
                "pack_type": a.pack_type,
                "default": a.default,
            }
            for a in mod.arguments
        ]
        packed_args = pack_args(arg_defs_for_packer, args)

        # Load payload bytes
        payload = b""
        if mod.execution_type == "bof" and mod.bof_file:
            bof_path = mod.base_path / "bin" / mod.bof_file
            if bof_path.exists():
                payload = bof_path.read_bytes()

                # Check cache to avoid re-upload
                payload_hash = hashlib.sha256(payload).hexdigest()
                cached_hash = agent.loaded_modules_cache.get(module_name, "")
                if payload_hash == cached_hash:
                    payload = b""  # Agent already has it

        elif mod.execution_type == "assembly" and mod.assembly_file:
            asm_path = mod.base_path / "bin" / mod.assembly_file
            if asm_path.exists():
                payload = asm_path.read_bytes()

        # Determine task type
        if mod.execution_type == "bof":
            task_type = TaskType.BOF
        elif mod.execution_type == "assembly":
            task_type = TaskType.ASSEMBLY
        else:
            task_type = TaskType.NATIVE

        from datetime import datetime
        task = Task(
            task_id=str(uuid4()),
            task_type=task_type,
            module_name=module_name,
            payload=payload,
            arguments=packed_args,
            created_at=datetime.utcnow(),
            timeout_seconds=mod.timeout or 300,
        )
        agent.pending_tasks.append(task)
        return task

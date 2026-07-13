"""
Calabasas C2 — Operator Client Entry Point.

Usage:
  python -m client.main [--modules-dir ./modules] [--profile profiles/default.yaml]
                        [--listen-host 0.0.0.0] [--listen-port 443]
                        [--cert ./certs/server.pem] [--key ./certs/server.key]
                        [--rsa-key ./keys/server_priv.pem]
                        [--log-dir ./logs]
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path

from .core.session_manager import SessionManager
from .core.task_manager import TaskManager
from .core.module_registry import ModuleRegistry
from .core.events import event_bus
from .logging.operator_logger import OperatorLogger
from .profiles.parser import load_profile, MalleableProfile
from .listeners.https_listener import HttpsListener
from .cli.shell import OperatorShell

log = logging.getLogger("calabasas")


def parse_args():
    p = argparse.ArgumentParser(description="Calabasas C2 Operator Client")
    p.add_argument("--modules-dir", type=Path, default=Path("./modules"),
                    help="Directory containing modules")
    p.add_argument("--profile", type=Path, default=None,
                    help="Malleable C2 profile YAML")
    p.add_argument("--listen-host", default="0.0.0.0",
                    help="Listener bind address")
    p.add_argument("--listen-port", type=int, default=443,
                    help="Listener port")
    p.add_argument("--cert", type=Path, default=None,
                    help="TLS certificate PEM file")
    p.add_argument("--key", type=Path, default=None,
                    help="TLS private key PEM file")
    p.add_argument("--rsa-key", type=Path, default=None,
                    help="RSA private key for agent key exchange")
    p.add_argument("--log-dir", type=Path, default=Path("./logs"),
                    help="Log output directory")
    p.add_argument("--debug", action="store_true",
                    help="Enable debug logging")
    return p.parse_args()


async def main():
    args = parse_args()

    # Logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Core components
    session_manager = SessionManager()
    task_manager = TaskManager()
    task_manager.start_monitor()
    module_registry = ModuleRegistry(args.modules_dir)
    op_logger = OperatorLogger(args.log_dir)

    # Load profile
    profile = MalleableProfile()
    if args.profile and args.profile.exists():
        profile = load_profile(args.profile)
        log.info(f"Loaded profile: {profile.name}")

    # Initialize event queue
    event_bus.init_queue()

    # Start HTTPS listener
    listener = HttpsListener(
        listener_id=1,
        host=args.listen_host,
        port=args.listen_port,
        session_manager=session_manager,
        task_manager=task_manager,
        profile=profile,
        logger=op_logger,
        rsa_private_key_path=args.rsa_key,
        cert_path=args.cert,
        key_path=args.key,
    )
    await listener.start()

    # Start CLI shell
    shell = OperatorShell(
        session_manager=session_manager,
        task_manager=task_manager,
        module_registry=module_registry,
        logger=op_logger,
        history_file=args.log_dir / ".shell_history",
    )
    shell.register_listener(listener)

    try:
        await shell.run()
    finally:
        await listener.stop()
        task_manager.stop_monitor()


def entry():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    entry()

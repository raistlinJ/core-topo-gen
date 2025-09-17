#!/usr/bin/env python3
import os
import sys
import grpc

# We rely on CORE's installed python package providing these modules
try:
    from core.api.grpc import core_pb2_grpc, core_pb2
except Exception as e:
    print("ERROR: could not import CORE gRPC stubs. Is CORE installed in this Python env?", file=sys.stderr)
    raise

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "7443"))
ADDR = f"{HOST}:{PORT}"

CA_CERT = os.environ.get("CA_CERT", os.path.join(os.path.dirname(__file__), "..", "certs", "ca.crt"))
CLIENT_CERT = os.environ.get("CLIENT_CERT")
CLIENT_KEY = os.environ.get("CLIENT_KEY")

print(f"Connecting to Envoy at {ADDR} with TLS")

root_certs = None
private_key = None
cert_chain = None

if CA_CERT and os.path.exists(CA_CERT):
    with open(CA_CERT, "rb") as f:
        root_certs = f.read()

if CLIENT_CERT and CLIENT_KEY and os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
    with open(CLIENT_KEY, "rb") as f:
        private_key = f.read()
    with open(CLIENT_CERT, "rb") as f:
        cert_chain = f.read()

creds = grpc.ssl_channel_credentials(root_certificates=root_certs, private_key=private_key, certificate_chain=cert_chain)

options = [
    ("grpc.max_send_message_length", 50 * 1024 * 1024),
    ("grpc.max_receive_message_length", 50 * 1024 * 1024),
]

channel = grpc.secure_channel(ADDR, creds, options=options)
stub = core_pb2_grpc.CoreApiStub(channel)

try:
    resp = stub.GetSessions(core_pb2.GetSessionsRequest())
    print(f"OK: received {len(resp.sessions)} session(s)")
    for s in resp.sessions:
        print(f"- id={s.id} state={s.state} nodes={s.nodes}")
except grpc.RpcError as e:
    print(f"gRPC error: code={e.code()} details={e.details()}")
    sys.exit(1)
finally:
    channel.close()

import socket, struct, subprocess, time, hmac, hashlib, base64
from collections import defaultdict

SECRET_KEY_B32 = "JBSWY3DPEHPK3PXP"
SECRET_KEY = base64.b32decode(SECRET_KEY_B32, casefold=True)

B = 10000
M = 40000
PORT_MIN = B
PORT_MAX = B + M
STATE_WINDOW = 5
ACCESS_TIMEOUT = "60s"
TOTP_STEP = 30
MAX_PORTS_PER_CLIENT = 8

NFT_FAMILY = "inet"
NFT_TABLE = "filter"
NFT_SET = "dynamic_access"


def hotp(key: bytes, counter: int, digits: int = 6) -> int:
    msg = struct.pack("!Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    dbc = struct.unpack("!I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return dbc % (10 ** digits)


def current_counters(ts=None, step=TOTP_STEP, window=1):
    if ts is None:
        ts = int(time.time())
    c = ts // step
    return [c + w for w in range(-window, window + 1)]


def totp_values(key: bytes, ts=None, step=TOTP_STEP, window=1):
    values = []
    for counter in current_counters(ts=ts, step=step, window=window):
        if counter >= 0:
            values.append((counter, hotp(key, counter)))
    return values


def compute_p2(v_totp: int, target_port: int) -> int:
    msg = struct.pack("!IH", v_totp, target_port)
    digest = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
    return B + (int.from_bytes(digest[:4], "big") % M)


def recover_target_port(p3: int, v_totp: int) -> int:
    return (p3 - B - v_totp) % M


def valid_service_port(port: int) -> bool:
    return 1 <= port <= 65535


def nft_add_access(client_ip: str, target_port: int):
    cmd = [
        "nft", "add", "element",
        NFT_FAMILY, NFT_TABLE, NFT_SET,
        "{", f"{client_ip} . {target_port} timeout {ACCESS_TIMEOUT}", "}"
    ]
    subprocess.run(cmd, check=True)


def parse_ipv4_udp(frame: bytes):
    if len(frame) < 42:
        return None

    eth_proto = struct.unpack("!H", frame[12:14])[0]
    if eth_proto != 0x0800:
        return None

    ip_header = frame[14:34]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4

    if version != 4:
        return None

    proto = iph[6]
    if proto != 17:
        return None

    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    udp_offset = 14 + ihl
    if len(frame) < udp_offset + 8:
        return None

    src_port, dst_port, udp_len, checksum = struct.unpack("!HHHH", frame[udp_offset:udp_offset + 8])

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "udp_len": udp_len,
    }


def cleanup_states(states, used_tokens):
    now = time.time()

    expired_clients = []
    for ip, state in states.items():
        if now - state["created_at"] > STATE_WINDOW:
            expired_clients.append(ip)
    for ip in expired_clients:
        del states[ip]

    expired_tokens = [k for k, exp in used_tokens.items() if exp < now]
    for k in expired_tokens:
        del used_tokens[k]


def try_authorize(client_ip, state, used_tokens):
    ports = list(state["ports"])
    ts = int(time.time())

    for _, v_totp in totp_values(SECRET_KEY, ts=ts, step=TOTP_STEP, window=1):
        expected_p1 = B + (v_totp % M)

        if expected_p1 not in ports:
            continue

        for p3 in ports:
            if p3 == expected_p1:
                continue

            target_port = recover_target_port(p3, v_totp)
            if not valid_service_port(target_port):
                continue

            expected_p2 = compute_p2(v_totp, target_port)
            if expected_p2 not in ports:
                continue

            token_key = (client_ip, v_totp, target_port)
            if token_key in used_tokens:
                return False

            try:
                nft_add_access(client_ip, target_port)
                used_tokens[token_key] = time.time() + TOTP_STEP * 2
                print(f"[+] Authorized {client_ip} -> {target_port}")
                return True
            except subprocess.CalledProcessError as e:
                print(f"[!] nft error for {client_ip}:{target_port}: {e}")
                return False

    return False


def listen_knocks(interface="eth0"):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    conn.bind((interface, 0))

    states = defaultdict(lambda: {"ports": set(), "created_at": time.time()})
    used_tokens = {}

    print(f"[*] Listening on interface {interface}")

    while True:
        raw_data, _ = conn.recvfrom(65535)
        packet = parse_ipv4_udp(raw_data)
        if not packet:
            continue

        src_ip = packet["src_ip"]
        dest_port = packet["dst_port"]

        cleanup_states(states, used_tokens)

        if not (PORT_MIN <= dest_port < PORT_MAX):
            continue

        state = states[src_ip]

        if time.time() - state["created_at"] > STATE_WINDOW:
            states[src_ip] = {"ports": set(), "created_at": time.time()}
            state = states[src_ip]

        if len(state["ports"]) >= MAX_PORTS_PER_CLIENT:
            state["ports"].clear()
            state["created_at"] = time.time()

        state["ports"].add(dest_port)

        if try_authorize(src_ip, state, used_tokens):
            del states[src_ip]


if __name__ == "__main__":
    listen_knocks("eth0")
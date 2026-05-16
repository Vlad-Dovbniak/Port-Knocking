import pyotp, hmac, hashlib, socket, time, struct, base64, argparse

SECRET_KEY_B32 = "JBSWY3DPEHPK3PXP"
SECRET_KEY = base64.b32decode(SECRET_KEY_B32, casefold=True)
B = 10000
M = 40000

def generate_ports(target_port):
    totp = pyotp.TOTP(SECRET_KEY_B32)
    v_totp = int(totp.now())
    
    p1 = B + (v_totp % M)
    msg = struct.pack('!IH', v_totp, target_port)
    h = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
    p2 = B + (int.from_bytes(h[:4], 'big') % M)
    p3 = B + ((target_port + v_totp) % M)
    
    return [p1, p2, p3]

def knock(ip, target_port):
    ports = generate_ports(target_port)
    print(f"[*] Ініціалізація авторизації до {ip}:{target_port}")
    print(f"[*] Згенеровані порти: {ports}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for p in ports:
        sock.sendto(b'', (ip, p)) # Відправка порожніх пакетів
        time.sleep(0.05)
    sock.close()
    print("[+] Криптографічний стукіт надіслано.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True, help="IP сервера")
    parser.add_argument("--port", type=int, default=22, help="Цільовий порт")
    args = parser.parse_args()
    knock(args.ip, args.port)
import pyotp, hmac, hashlib, socket, time, struct

SECRET_KEY = "JBSWY3DPEHPK3PXP" # Base32 Pre-Shared Key
B = 10000
M = 40000

def generate_ports(target_port):
    totp = pyotp.TOTP(SECRET_KEY)
    v_totp = int(totp.now())
    
    p1 = B + (v_totp % M)
    msg = struct.pack('!IH', v_totp, target_port)
    h = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).digest()
    p2 = B + (int.from_bytes(h[:4], 'big') % M)
    p3 = B + ((target_port + v_totp) % M)
    
    return [p1, p2, p3]

def knock(ip, target_port):
    ports = generate_ports(target_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Ініціалізація авторизації. Порти: {ports}")
    
    for p in ports:
        sock.sendto(b'', (ip, p)) # Payload = 0 байт
        time.sleep(0.05) # Мінімальна затримка для збереження послідовності
    sock.close()
# Python 3.6 +
import sys
import json
import struct
import socket
import threading
import uuid
import time
import stun



def addr_from_args(args, host='127.0.0.1', port=9999):
    if len(args) >= 3:
        host, port = args[1], int(args[2])
    elif len(args) == 2:
        host, port = host, int(args[1])
    else:
        host, port = host, port
    return host, port


def msg_to_addr(data):
    ip, port = data.decode('utf-8').strip().split(':')
    return (ip, int(port))


def addr_to_msg(addr):
    return '{}:{}'.format(addr[0], str(addr[1])).encode('utf-8')


def send_msg(sock, msg):
    msg = struct.pack('>I', len(msg)) + msg.encode('utf-8')
    sock.sendall(msg)


def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)





def p2pconnect():
    print("noer")

def p2psend():
    print("noer")


def p2plister():
    print("noer")

    

class P2Pserver(threading.Thread):

    def __init__(self, host, port):

        self.host=host
        self.port=port
        super(P2Pserver, self).__init__() #CAll Thread.__init__()


    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(1)
            s.settimeout(30)
            print("noer")
            while True:
                try:
                    print("running")
                    conn, addr = s.accept()
                    
                except socket.timeout:
                    continue

                message = json.loads(recv_msg(conn))
                if message['type'] == "HAND":
                    print('---------------HANDLOL----------')
                    client=message['clientid']
                    nat=message['nat']
                    pip=message['private_ip']
                    ppo=message['private_port']
                    print(f'Client ID:{client}')
                    print(f'Client NAT: {nat}')
                    print(f'Client Private Addr: {pip},{ppo}')




class P2Pclient(threading.Thread):

    def __init__(self, host, port):

        self.host=host
        self.port=port
        super(P2Pclient, self).__init__() #CAll Thread.__init__()

    def run(self):
        clientid=str(uuid.uuid4()).replace('-','').upper()
        print(f"clientID:{clientid}")
        nat="IDK"
        try:
            nat, _, _ = stun.get_ip_info()
        except:
            print('NAT Fail')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((self.host, self.port))
            s.settimeout(10)
            private_addr = s.getsockname()

            hand = {
                'type': "HAND",
                'clientid': clientid,
                'nat': nat,
                'private_ip': private_addr[0],
                'private_port': private_addr[1]
            }

            send_msg(s, json.dumps(hand))
            #-------------------------------------






def main():
    argv = sys.argv
    if len(argv) < 2:
        print('Invalid arguments: mode must be one of (server, client).')
        return

    if argv[1] == 'server':
        if len(argv[2:]) == 1:
            port = int(argv[2])
            print("lol")
            P2Pserver('0.0.0.0', port).start()
        else:
            print('Invalid arguments: eg. server <port>')
    elif argv[1] == 'client':
        host, port = argv[2], int(argv[3])
        P2Pclient(host,port).start()
    else:
        print('mode must be one of (server, client}')
        return






if __name__ == '__main__':
    main()
import socket

def sniffer(count, bufferSize=65565, showPort=False, showRawData=False):
    # the public network interface
    HOST = socket.gethostbyname(socket.gethostname())

    # create a raw socket and bind it to the public interface
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # prevent socket from being left in TIME_WAIT state, enabling reuse
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, 0))

    # Include IP headers
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # receive all packages
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    for i in range(count):

        # receive a package
        package = s.recvfrom(bufferSize)
        printPacket(package, showPort, showRawData)

    # disabled promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def printPacket(package, showPort, showRawData):

    # index values for (data, header) tuple
    dataIndex = 0
    headerIndex = 1

    # index values for (ipAddress, port) tuple
    ipAddressIndex = 0
    portIndex = 1

    print('IP:', package[headerIndex][ipAddressIndex], end=' ')
    if(showPort):
        print('Port:', package[headerIndex][portIndex], end=' ')            
    print('') #newline
    if(showRawData):
        print('Data:', package[dataIndex])
        
sniffer(count=10,showPort=True,showRawData=True)    

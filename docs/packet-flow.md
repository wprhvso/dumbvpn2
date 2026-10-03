# Packet Flow and Multiplexed Tunnel Architecture

## Complete End-to-End Sequence

    +------+       +-------+       +-------------------+       +-------+       +--------------------+       +----------+
    | curl | <---> | mesh0 | <---> | Client Flow Table | <---> | Envoy | <---> | mesh-server (Hub)  | <---> | Upstream |
    +------+       +-------+       +-------------------+       +-------+       +--------------------+       +----------+
       |               |                     |                     |                     |                        |
       | 1. DNS Query  |                     |                     |                     |                        |
       |-------------->| (Zero-Latency DNS)  |                     |                     |                        |
       |<- Fake IP ----|                     |                     |                     |                        |
       | (198.18.0.x)  |                     |                     |                     |                        |
       |               |                     |                     |                     |                        |
       | 2. TCP SYN    |                     |                     |                     |                        |
       |-------------->| (mesh0 TUN)         |                     |                     |                        |
       |               |-------------------->|                     |                     |                        |
       |               |                     | Allocate Flow Key   |                     |                        |
       |               |                     | stream_id = X       |                     |                        |
       |               |<--------------------|                     |                     |                        |
       |<- SYN-ACK ----|                     |                     |                     |                        |
       |               |                     | MMX CONNECT (X)     |                     |                        |
       |               |                     |-------------------->| (HTTP/2 DATA)       |                        |
       |               |                     |                     |-------------------->| (TCP 127.0.0.1:4000)   |
       |               |                     |                     |                     | Connect to target      |
       |               |                     |                     |                     |----------------------->|
       | 3. TCP ACK    |                     |                     |                     |                        |
       |-------------->|-------------------->| (mark established)  |                     |                        |
       |               |                     |                     |                     |                        |
       | 4. ClientHello|                     |                     |                     |                        |
       |-------------->|-------------------->|                     |                     |                        |
       |<- TCP ACK ----| (local fast ack)    |                     |                     |                        |
       |               |                     | MMX DATA (X)        |                     |                        |
       |               |                     |-------------------->|                     |                        |
       |               |                     |                     |-------------------->| Write to upstream      |
       |               |                     |                     |                     |----------------------->|
       |               |                     |                     |                     |                        |
       |               |                     |                     |                     | ServerHello Response   |
       |               |                     |                     |                     |<-----------------------|
       |               |                     |                     | MMX DATA (X)        |                        |
       |               |                     |<--------------------|<--------------------|                        |
       |               | Build TCP Packet    |                     |                     |                        |
       |               |<--------------------|                     |                     |                        |
       |<- ServerHello-|                     |                     |                     |                        |
       | (PSH | ACK)   |                     |                     |                     |                        |

## Step-by-Step Breakdown

1. DNS Resolution:
   - curl queries 127.0.0.1:53 (handled by zero-latency fake IP engine).
   - Engine stores bidirectional mapping: Domain <-> Allocated 198.18.0.x IPv4 address.
   - Immediate synthetic DNS A response returned to curl.

2. TCP Handshake on mesh0:
   - curl initiates TCP handshake with destination 198.18.0.x:port.
   - mesh-client reads IPv4 SYN packet from mesh0.
   - TcpEngine.handlePacket() parses original client and fake IP addresses without mutating the original source/destination values.
   - FlowTable allocates or finds the 4-tuple (client_ip, fake_ip, client_port, target_port) and assigns an incrementing stream_id.
   - User-space TCP engine immediately builds synthetic SYN-ACK packet and injects it back into mesh0.
   - curl receives SYN-ACK and transitions to ESTABLISHED.

3. Tunnel Multiplexed CONNECT:
   - mesh-client resolves fake IP back to original target domain.
   - Encodes an MMX CONNECT frame (stream_id, target domain, target port).
   - Sends inside HTTP/2 DATA frame over stream 1 to Envoy on 34.88.228.23:443.
   - Envoy proxies stream bytes to mesh-server listening on 127.0.0.1:4000.
   - mesh-server parses MMX CONNECT frame and establishes outbound TCP connection to upstream host.
   - Outbound connection is registered in server session table under stream_id.
   - Dedicated upstream pump thread begins streaming data for stream_id.

4. Forward Data Pipeline (Client -> Upstream):
   - curl sends L4 payload (TLS ClientHello, HTTP request, etc.) to mesh0.
   - mesh-client reads packet, looks up flow by 4-tuple in FlowTable.
   - Advances client sequence number and injects immediate TCP ACK into mesh0.
   - Encodes raw payload into MMX DATA frame tagged with stream_id.
   - Encapsulates into HTTP/2 DATA frame to hub.
   - mesh-server routes payload to upstream TCP socket for stream_id.

5. Reverse Data Pipeline (Upstream -> Client):
   - Upstream responds (TLS ServerHello, HTTP response body, etc.).
   - Hub reads bytes from upstream socket.
   - Hub encodes MMX DATA frame tagged with stream_id.
   - Hub sends across tunnel connection to Envoy.
   - Envoy delivers HTTP/2 DATA frame to mesh-client.
   - runTunnelReader parses MMX frames using streaming FrameParser.
   - Dispatches MMX DATA frame to flow matching stream_id.
   - Synthesizes valid IPv4 TCP packet (src_ip = fake_ip, dst_ip = client_ip, src_port = target_port, dst_port = client_port, updated server_seq, client_seq, correct checksums).
   - Writes packet into mesh0.
   - curl receives data through mesh0 and completes TLS handshake/request seamlessly.

6. Teardown:
   - When upstream or client sends FIN/RST, MMX CLOSE frame is delivered across tunnel.
   - Sessions and flow table entries are pruned cleanly without resource leaks.

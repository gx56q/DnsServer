import logging
import select
import socket
import time
from collections import defaultdict

from dnslib import DNSRecord, DNSHeader, DNSQuestion

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %('
                           'message)s')
logger = logging.getLogger("dns_server")

dns_cache = defaultdict(lambda: {"timestamp": 0, "records": []})


def resolve_recursive(question, root_dns_server=('198.41.0.4', 53)):
    current_qname = question.qname
    current_qtype = question.qtype

    cache_key = (current_qname, current_qtype)
    if (cache_key in dns_cache and time.time() - dns_cache[cache_key][
        "timestamp"]
            < min(ttl for _, ttl in dns_cache[cache_key]["records"])):
        logger.info("Answer found in cache for %s", current_qname)
        return dns_cache[cache_key]["records"]

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
        dns_socket.settimeout(5)
        dns_socket.sendto(
            DNSRecord(q=DNSQuestion(current_qname, current_qtype)).pack(),
            root_dns_server)
        try:
            data, _ = dns_socket.recvfrom(1024)
            response = DNSRecord.parse(data)
            if response.rr:
                logger.info("Answer found in the response: %s",
                            response.rr[0].rdata)

                dns_cache[cache_key]["timestamp"] = time.time()
                dns_cache[cache_key]["records"] = [(rr, rr.ttl) for rr
                                                   in response.rr]

                return dns_cache[cache_key]["records"]
            for rrset in response.ar:
                if rrset.rtype == 1:
                    return resolve_recursive(question,
                                             (str(rrset.rdata), 53))
        except socket.timeout:
            pass

    return None


def handle_dns_request(data):
    try:
        request = DNSRecord.parse(data)
        question = request.questions[0]

        logger.info("Incoming DNS request: %s", question)

        answer = resolve_recursive(question)
        response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                             q=request.q)

        if answer:
            for rr, ttl in answer:
                response.add_answer(rr)
                rr.ttl = ttl

        logger.info("DNS response: %s", response.rr)
        return response.pack()

    except Exception as e:
        logger.error("Error processing DNS request: %s", e, exc_info=True)
        return None


def main():
    host = '127.0.0.1'
    port = 53

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((host, port))

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((host, port))
    tcp_socket.listen(1)

    logger.info("DNS server listening on %s:%d", host, port)

    while True:
        try:
            readable, _, _ = select.select([udp_socket, tcp_socket], [], [], 5)
            for s in readable:
                if s is udp_socket:
                    data, addr = udp_socket.recvfrom(1024)
                    response_data = handle_dns_request(data)
                    if response_data:
                        udp_socket.sendto(response_data, addr)
                elif s is tcp_socket:
                    client_socket, client_addr = tcp_socket.accept()
                    data = client_socket.recv(1024)
                    response_data = handle_dns_request(data)
                    if response_data:
                        client_socket.send(response_data)
                    client_socket.close()
        except KeyboardInterrupt:
            break

    udp_socket.close()
    tcp_socket.close()


if __name__ == "__main__":
    main()

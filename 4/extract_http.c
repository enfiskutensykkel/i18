#include <pcap.h>
#include <ctype.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>


struct hdr
{
    uint32_t src;
    uint16_t sport;
    uint32_t dst;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    size_t   size;
};


static inline void ip_addr_str(char* buff, uint32_t addr)
{
    union ipaddr
    {
        uint32_t addr;
        uint8_t bytes[sizeof(uint32_t) / sizeof(uint8_t)];
    };

    union ipaddr ipaddr;;
    ipaddr.addr = addr;

    snprintf(buff, INET_ADDRSTRLEN, "%u.%u.%u.%u", ipaddr.bytes[3], ipaddr.bytes[2], ipaddr.bytes[1], ipaddr.bytes[0]);
}


static inline const struct hdr* find_reverse(const struct hdr* conns, size_t num_conns, const struct hdr* current)
{
    for (size_t i = 0; i < num_conns; ++i)
    {
        if (conns[i].src == current->dst && conns[i].sport == current->dport && conns[i].dst == current->src && conns[i].dport == current->sport)
        {
            return &conns[i];
        }
    }

    return NULL;
}


static inline const u_char* get_segment(const u_char* pkt, struct hdr* conn)
{
    uint16_t eth_type = ntohs(*((uint16_t*) (pkt + 2 * 6)));
    const u_char* ptr = pkt + 2 * 6 + 2;

check_type:
    if (eth_type == 0x0800) // IP protocol
    {
        uint8_t ip_ver = (*((uint8_t*) ptr) & 0xf0) >> 4;
        if (ip_ver == 4) // is it IPv4 or something else?
        {
            // extract length and IP addresses from IP header
            uint16_t ip_len = ntohs(*((uint16_t*) (ptr + 2)));
            uint8_t ip_ihl = (*((uint8_t*) ptr) & 0x0f);

            uint32_t ip_src = ntohl(*((uint32_t*) (ptr + 12)));
            uint32_t ip_dst = ntohl(*((uint32_t*) (ptr + 16)));

            uint8_t ip_proto = *((uint8_t*) (ptr + 9));
            if (ip_proto == 0x06)
            {
                // extract ports and sequence number from TCP segment
                const u_char* seg = ptr + (32 * ip_ihl) / 8;
                uint16_t seg_len = ip_len - (32 * ip_ihl) / 8;

                uint16_t tcp_sport = ntohs(*((uint16_t*) seg));
                uint16_t tcp_dport = ntohs(*((uint16_t*) (seg + 2)));
                uint32_t tcp_seqno = ntohl(*((uint32_t*) (seg + 4)));
                uint32_t tcp_ackno = ntohl(*((uint32_t*) (seg + 8)));

                uint8_t tcp_flags = *((uint8_t*) (seg + 13));

                // offset to payload
                uint8_t tcp_offset = (*((uint8_t*) (seg + 12)) & 0xf0) >> 4;
                uint16_t tcp_hdr_len = tcp_offset * 4;
                const void* tcp_data = seg + tcp_hdr_len;
                uint16_t tcp_data_len = seg_len - tcp_hdr_len;

                conn->src = ip_src;
                conn->sport = tcp_sport;
                conn->dst = ip_dst;
                conn->dport = tcp_dport;
                conn->seq = tcp_seqno;
                conn->ack = 0;
                if (tcp_flags & (1 << 4))
                {
                    conn->ack = tcp_ackno;
                }
                conn->len = tcp_data_len;
                conn->size = 0;

                return tcp_data;
            }
            
            fprintf(stderr, "Not TCP (proto=%x)\n", ip_proto);
        }
        else
        {
            fprintf(stderr, "Not IPv4 (version=%u)\n", ip_ver);
        }
    }
    else if (eth_type == 0x8100) // Deal with VLAN 
    {
        eth_type = ntohs(*((uint16_t*) (pkt + 2 * 6 + 4)));
        ptr += 4;
        goto check_type;
    }
    else if (eth_type == 0x0806) // ARP
    {
        fprintf(stderr, "ARP\n");
    }
    else
    {
        fprintf(stderr, "Unknown eth type\n");
    }

    return NULL;
}


static size_t identify_connections(pcap_t* handle, struct hdr** connections)
{
    *connections = NULL;
    size_t max = 200;
    size_t curr = 0;

    struct hdr* conns = malloc(sizeof(struct hdr) * max);
    
    // Just extract TCP SYN packets, we assume that we have a complete trace
    struct bpf_program prog;
    if (pcap_compile(handle, &prog, "tcp[tcpflags] & tcp-syn != 0", 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Failed to compile filter\n");
        return 1;
    }

    if (pcap_setfilter(handle, &prog) == -1)
    {
        pcap_freecode(&prog);
        fprintf(stderr, "Failed to set filter\n");
        return 2;
    }

    pcap_freecode(&prog);

    struct pcap_pkthdr* hdr;
    const u_char* pkt;

    while (pcap_next_ex(handle, &hdr, &pkt) == 1)
    {
        if (curr == max)
        {
            // TODO realloc and increase max
        }

        get_segment(pkt, &conns[curr++]);
    }

    for (size_t i = 0; i < curr; ++i)
    {
        struct hdr* c = &conns[i];

        if (c->ack == 0)
        {
            const struct hdr* r = find_reverse(conns, curr, c);
            c->ack = r->seq + 1;
        }
    
    }

    *connections = conns;
    return curr;
}


static int copy_payload_bytes(pcap_t* handle, const struct hdr* conn, void* data)
{
    struct bpf_program prog;
    char filter[256];

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    ip_addr_str(src, conn->src);
    ip_addr_str(dst, conn->dst);

    snprintf(filter, sizeof(filter), "ip src host %s and src port %u and dst host %s and dst port %u and tcp[tcpflags] & tcp-syn == 0 and tcp[tcpflags] & tcp-ack != 0",
        dst, conn->dport, src, conn->sport);

    if (pcap_compile(handle, &prog, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Failed to compile filter\n");
        return EBADF;
    }

    if (pcap_setfilter(handle, &prog) == -1)
    {
        pcap_freecode(&prog);
        fprintf(stderr, "Failed to set filter\n");
        return EBADF;
    }

    pcap_freecode(&prog);

    struct pcap_pkthdr* hdr;
    const u_char* pkt;

    uint8_t* ptr = data;
    uint32_t seq = conn->ack;
    size_t pos = 0;
    while (pcap_next_ex(handle, &hdr, &pkt) == 1)
    {
        struct hdr tcp_header;
        const u_char* payload = get_segment(pkt, &tcp_header);

        if (tcp_header.seq == seq)
        {
            seq += tcp_header.len;
            memcpy(ptr + pos, payload, tcp_header.len);
            pos += tcp_header.len;
        }
    }

    return 0;
}


static int count_payload_bytes(pcap_t* handle, struct hdr* conn)
{
    struct bpf_program prog;
    char filter[256];

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    ip_addr_str(src, conn->src);
    ip_addr_str(dst, conn->dst);

    snprintf(filter, sizeof(filter), "ip src host %s and src port %u and dst host %s and dst port %u and tcp[tcpflags] & tcp-syn == 0 and tcp[tcpflags] & tcp-ack != 0",
        dst, conn->dport, src, conn->sport);

    if (pcap_compile(handle, &prog, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Failed to compile filter\n");
        return EBADF;
    }

    if (pcap_setfilter(handle, &prog) == -1)
    {
        pcap_freecode(&prog);
        fprintf(stderr, "Failed to set filter\n");
        return EBADF;
    }

    pcap_freecode(&prog);

    struct pcap_pkthdr* hdr;
    const u_char* pkt;

    conn->size = 0;
    uint32_t seq = conn->ack;
    while (pcap_next_ex(handle, &hdr, &pkt) == 1)
    {
        struct hdr tcp_header;
        get_segment(pkt, &tcp_header);

        if (tcp_header.seq == seq)
        {
            seq += tcp_header.len;
            conn->size += tcp_header.len;
        }
    }

    return 0;
}


int main()
{
    char errstr[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_offline("data.bin", errstr);
    if (handle == NULL)
    {
        fprintf(stderr, "a %s\n", errstr);
        return 1;
    }

    struct hdr* conns = NULL;
    size_t num_conns = identify_connections(handle, &conns);
    
    pcap_close(handle);

    for (size_t i = 0; i < num_conns; ++i)
    {
        handle = pcap_open_offline("data.bin", errstr);
        if (handle == NULL)
        {
            free(conns);
            fprintf(stderr, "b %s\n", errstr);
            return 2;
        }

        int status = count_payload_bytes(handle, &conns[i]);

        pcap_close(handle);

        if (status != 0)
        {
            free(conns);
            fprintf(stderr, "Unexpected error: %s\n", strerror(status));
            return status;
        }
    }

    char filename[64];
    for (size_t i = 0; i < num_conns; ++i)
    {
        snprintf(filename, sizeof(filename), "conn%zu.http", i);

        void* data = malloc(conns[i].size);
        if (data == NULL)
        {
            free(conns);
            fprintf(stderr, "%s\n", strerror(errno));
            return 3;
        }

        handle = pcap_open_offline("data.bin", errstr);
        if (handle == NULL)
        {
            free(data);
            free(conns);
            fprintf(stderr, "%s\n", errstr);
            return 3;
        }

        int status = copy_payload_bytes(handle, &conns[i], data);
        pcap_close(handle);

        if (status != 0)
        {
            free(data);
            free(conns);
            fprintf(stderr, "Unexpected error: %s\n", strerror(status));
            return status;
        }

        FILE* fp = fopen(filename, "wb");
        if (fp != NULL)
        {
            fwrite(data, 1, conns[i].size, fp);
            fflush(fp);
            fclose(fp);
        }

        free(data);
    }

    free(conns);
    return 0;
}

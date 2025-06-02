#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */

 int static_id = 0;
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    if(buf->len < sizeof(ip_hdr_t)){
        // ip包长度不足ip头长度 包损坏 直接丢弃
        return;
    }
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    if(ip_hdr->version != IP_VERSION_4 || swap16(ip_hdr->total_len16) > buf->len){
        // 检查ip版本号不是4 或者 ip总长度是否小于等于buf长度
        return;
    }
    uint16_t checksum = ip_hdr->hdr_checksum16;//保存数据包的checksum
    ip_hdr->hdr_checksum16 = 0;// 清空checksum
    if(checksum != checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t))){
        // 检查checksum 不匹配
        return;
    }
    ip_hdr->hdr_checksum16 = checksum; // 恢复checksum
    if(memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0){
        // 检查ip地址不匹配 不是发往本机的ip包 不考虑转发 丢弃
        return;
    }
    if(swap16(ip_hdr->total_len16) < buf->len){
        buf_remove_padding(buf, buf->len - ip_hdr->total_len16);
    }
    if(buf_remove_header(buf, sizeof(ip_hdr_t)) == -1){
        // 检查buf移除头部失败
        printf("ip_fragment_out buf_remove_header error\n");
        return;
    }
    if(net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) == -1){
        printf("ip_fragment_out net_in error\n");
        buf_add_header(buf, sizeof(ip_hdr_t));
        memcpy(buf->data, ip_hdr, sizeof(ip_hdr_t));
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->tos = 0;
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->hdr_len = 5;
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 = swap16(offset >> 3 | (mf ? IP_MORE_FRAGMENT : 0));
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    // ip_hdr->total_len16 = swap16(ETHERNET_MAX_TRANSPORT_UNIT);
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    if(buf->len > ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)){
        int length  = buf->len;
        while(length > ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)){
            buf_init(&txbuf, ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
            memcpy(txbuf.data, buf->data+(buf->len - length), ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
            ip_fragment_out(&txbuf, ip, protocol, static_id, buf->len-length, 1);
            length = length - ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ip_hdr_t);
        }
        buf_init(&txbuf, length);
        memcpy(txbuf.data, buf->data+(buf->len - length), length);
        ip_fragment_out(&txbuf, ip, protocol, static_id, buf->len-length, 0);
    }else{
        ip_fragment_out(buf, ip, protocol, static_id, 0, 0); 
    }
    static_id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
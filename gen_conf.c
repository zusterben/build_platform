/*
*
* Copyright (C) 2020-2021 zusterben
*
* This is free software, licensed under the GNU General Public License v3.
*
*/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h> // fcntl
#include <unistd.h> // close
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <limits.h> // [LONG|INT][MIN|MAX]
#include <errno.h>  // errno
#include <unistd.h>
#include <json.h>

typedef enum {
    S2ISUCCESS = 0,
    S2IOVERFLOW,
    S2IUNDERFLOW,
    S2IINCONVERTIBLE
} STR2INT_ERROR;

#define offsetof2(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define MAGIC "magicv1 "
#define MAGIC_LEN 8
#define DBHEADER_LEN 8
#define HEADER_PREFIX (MAGIC_LEN + DBHEADER_LEN)
#define SK_PATH_MAX 128
#define BUF_MAX 2048
#define READ_MAX 65536

#define DELAY_PREFIX "__delay__"
#define DELAY_PREFIX_LEN 9
#define DELAY_KEY_LEN 128

#define SKIPD_DEBUG 3

#define _min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _b : _a; })

#define _max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

//"list "
#define LIST_LEN 5
#define READ_TIMEOUT (800)

typedef struct _dbclient {
    int remote_fd;
    char command[DELAY_KEY_LEN+1];
    char key[DELAY_KEY_LEN+1];
    //unsigned int timeout;

    char* buf;
    int buf_max;
    int buf_len;
    int buf_pos;
} dbclient;

enum {
	TYPE_ERR = -1,
    TYPE_VMESS = 0,
    TYPE_VLESS,
	TYPE_TROJAN,
	TYPE_SS,
	TYPE_SOCKS,
	TYPE_HTTP
};
enum {
	TLS_ERR = -1,
    TLS_TLS = 0,
    TLS_XTLS
};
enum {
	NET_ERR = -1,
    NET_TCP = 0,
    NET_KCP,
    NET_WS,
    NET_H2,
    NET_QUIC,
    NET_GRPC
};

dbclient* gclient;

static STR2INT_ERROR str2int(int *i, char *s, int base) {
  char *end;
  long  l;
  errno = 0;
  l = strtol(s, &end, base);

  if ((errno == ERANGE && l == LONG_MAX) || l > INT_MAX) {
    return S2IOVERFLOW;
  }
  if ((errno == ERANGE && l == LONG_MIN) || l < INT_MIN) {
    return S2IUNDERFLOW;
  }
  if (*s == '\0' || *end != '\0') {
    return S2IINCONVERTIBLE;
  }
  *i = l;
  return S2ISUCCESS;
}
static int create_client_fd(char* sock_path) {
    int len, remote_fd;
    struct sockaddr_un remote;

    if(-1 == (remote_fd = socket(PF_UNIX, SOCK_STREAM, 0))) {
        //perror("socket");
        return -1;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, sock_path);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if(-1 == connect(remote_fd, (struct sockaddr*)&remote, len)) {
        //perror("connect");
        close(remote_fd);
        return -1;
    }

    return remote_fd;
}

int setnonblock(int fd) {
    int flags;

    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static void check_buf(dbclient* client, int len) {
    int clen = _max(len, BUF_MAX);

    if((NULL != client->buf) && (client->buf_max < clen)) {
        free(client->buf);
        client->buf = NULL;
    }

    if(NULL == client->buf) {
        client->buf = (char*)malloc(clen+1);
        client->buf_max = clen;
    }
}

static int read_util(dbclient* client, int len, unsigned int delay) {
    int clen, n;
    unsigned int now, timeout;
    struct timeval tv,  tv2;

    check_buf(client, len);
    gettimeofday(&tv2, NULL);
    timeout = (tv2.tv_sec * 1000) + (tv2.tv_usec / 1000) + delay;
    client->buf_pos = 0;

    for(;;) {
        clen = len - client->buf_pos;
        n = recv(client->remote_fd, client->buf + client->buf_pos, clen, 0);
        if(n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                gettimeofday(&tv, NULL);
                now = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
                if(now > timeout) {
                    break;
                }

                usleep(50);
                continue;
            }
            //timeout
            return -2;
        } else if(n == 0) {
            //socket closed
            return -1;
        } else {
            client->buf_pos += n;
            if(client->buf_pos == len) {
                //read ok
                return 0;
            }
        }
    }

    //unkown error
    return -3;
}

int parse_get_result(dbclient *client, char *val) {
    int n1, n2;
    char *p1, *p2, *magic = MAGIC;

    do {
        n1 = read_util(client, HEADER_PREFIX, READ_TIMEOUT);
        if(n1 < 0) {
            return n1;
        }

        if(0 != memcmp(client->buf, magic, MAGIC_LEN)) {
            //message error
            return -3;
        }

        client->buf[HEADER_PREFIX-1] = '\0';
        if(S2ISUCCESS != str2int(&n2, client->buf+MAGIC_LEN, 10)) {
            //message error
            return -4;
        }

        n1 = read_util(client, n2, 510);
        if(n1 < 0) {
            return n1;
        }

        client->buf[n2] = '\0';
        p1 = strstr(client->buf, " ");
        if(NULL == p1) {
            break;
        }
        p2 = strstr(p1+1, " ");
        if(NULL == p2) {
            break;
        }
		//printf("%s\n",p2);
        n2 -= (p2-client->buf);
        if(!strcmp(p2+1, "none\n")) {
            break;
        }
		snprintf(val, 9999, "%s", p2+1);
		//printf("%s\n",val);
        return 0;
    } while(0);
    return 0;
}

unsigned char *base64_decode(unsigned char *code)
{
	int table[]={0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,62,0,0,0,
			 63,52,53,54,55,56,57,58,
			 59,60,61,0,0,0,0,0,0,0,0,
			 1,2,3,4,5,6,7,8,9,10,11,12,
			 13,14,15,16,17,18,19,20,21,
			 22,23,24,25,0,0,0,0,0,0,26,
			 27,28,29,30,31,32,33,34,35,
			 36,37,38,39,40,41,42,43,44,
			 45,46,47,48,49,50,51
			};
	long len;
	long str_len;
	unsigned char *res;
	int i,j;

	len=strlen(code);
	if(strstr(code,"=="))
		str_len=len/4*3-2;
	else if(strstr(code,"="))
		str_len=len/4*3-1;
	else
		str_len=len/4*3;
	res=malloc(sizeof(unsigned char)*str_len+1);
	res[str_len]='\0';
	for(i=0,j=0;i < len-2;j+=3,i+=4)  
	{
		res[j]=((unsigned char)table[code[i]])<<2 | (((unsigned char)table[code[i+1]])>>4);
		res[j+1]=(((unsigned char)table[code[i+1]])<<4) | (((unsigned char)table[code[i+2]])>>2);
		res[j+2]=(((unsigned char)table[code[i+2]])<<6) | ((unsigned char)table[code[i+3]]);
	}
	return res;
}


static int skipd(char *name, char *val)
{
	int remote_fd;
    int n1, n2, err = 0;
    dbclient* client;
    remote_fd = create_client_fd("/tmp/.skipd_server_sock");
    if(-1 == remote_fd) {
#if 1
        //Try to restart skipd
        system("service start_skipd >/dev/null 2>&1 &");
        sleep(1);
        remote_fd = create_client_fd("/tmp/.skipd_server_sock");
        if(-1 == remote_fd) {
            perror("connect to skipd error");
            return -1;
        }
#else
        perror("connect to skipd error");
        return -1;
#endif
	}
    gclient = (dbclient*)calloc(1, sizeof(dbclient));
    gclient->remote_fd = remote_fd;
    client = gclient;
	strcpy(client->command, "get");
	n1 = strlen(name) + 2 + strlen(client->command);
	check_buf(client, n1 + HEADER_PREFIX);
	n2 = snprintf(client->buf, client->buf_max, "%s%07d %s %s\n", MAGIC, n1, client->command, name);
	write(remote_fd, client->buf, n2);
	setnonblock(remote_fd);
	n1 = parse_get_result(gclient, val);
	if(n1 != 0) {
		return -1;
	}
	return 0;
}

int gen_ss_conf(int type, int netflix, char *path, int local_port)
{
	char k[99], v[9999];
	int node, kcp;
	struct json_object *ssjson = NULL;
	ssjson = json_object_new_object();
	FILE *fp;
	memset(v, 0, sizeof(v));
	skipd("ssconf_basic_node", v);
	node = atoi(v);
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_use_kcp_%d", node);
	skipd(k, v);
	kcp = atoi(v);
	if(type == 0){
		if(kcp==1){
			json_object_object_add(ssjson, "server", json_object_new_string("127.0.0.1"));
			json_object_object_add(ssjson, "server_port", json_object_new_int(1091));
		}else{
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_server_%d", node);
			skipd(k, v);
			json_object_object_add(ssjson, "server", json_object_new_string(v));
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_port_%d", node);
			skipd(k, v);
			json_object_object_add(ssjson, "server_port", json_object_new_int(atoi(v)));
		}
		json_object_object_add(ssjson, "local_address", json_object_new_string("0.0.0.0"));
		json_object_object_add(ssjson, "local_port", json_object_new_int(local_port));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_password_%d", node);
		skipd(k, v);
		json_object_object_add(ssjson, "password", json_object_new_string(base64_decode(v)));
		json_object_object_add(ssjson, "timeout", json_object_new_int(600));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_method_%d", node);
		skipd(k, v);
		json_object_object_add(ssjson, "method", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_ss_v2ray_%d", node);
		skipd(k, v);
		if(atoi(v) == 1){
			json_object_object_add(ssjson, "plugin", json_object_new_string("v2ray-plugin"));
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_ss_v2ray_opts_%d", node);
			skipd(k, v);
			json_object_object_add(ssjson, "plugin_opts", json_object_new_string(v));
		}else{
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_ss_obfs_%d", node);
			skipd(k, v);
			if(strlen(v) > 1){
				char tmp[99];
				memset(tmp, 0, sizeof(tmp));
				snprintf(tmp, sizeof(tmp), "obfs=%s", v);
				memset(v, 0, sizeof(v));
				memset(k, 0, sizeof(k));
				snprintf(k, sizeof(k), "ssconf_basic_ss_obfs_host_%d", node);
				skipd(k, v);
				memset(k, 0, sizeof(k));
				snprintf(k, sizeof(k), "%s;obfs-host=%s", tmp, v);
				json_object_object_add(ssjson, "plugin", json_object_new_string("obfs-local"));
				json_object_object_add(ssjson, "plugin-opts", json_object_new_string(k));
			}
		}
		//if(access("/proc/sys/net/ipv4/tcp_fastopen",F_OK) == 0)
		//	json_object_object_add(ssjson, "fast_open", json_object_new_boolean(1));
		//else
			json_object_object_add(ssjson, "fast_open", json_object_new_boolean(0));
		json_object_object_add(ssjson, "reuse_port", json_object_new_boolean(1));
	} else {
		if(kcp==1){
			json_object_object_add(ssjson, "server", json_object_new_string("127.0.0.1"));
			json_object_object_add(ssjson, "server_port", json_object_new_int(1091));
		}else{
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_server_%d", node);
			skipd(k, v);
			json_object_object_add(ssjson, "server", json_object_new_string(v));
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_port_%d", node);
			skipd(k, v);
			json_object_object_add(ssjson, "server_port", json_object_new_int(atoi(v)));
		}
		json_object_object_add(ssjson, "local_address", json_object_new_string("0.0.0.0"));
		json_object_object_add(ssjson, "local_port", json_object_new_int(local_port));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_password_%d", node);
		skipd(k, v);
		json_object_object_add(ssjson, "password", json_object_new_string(base64_decode(v)));
		json_object_object_add(ssjson, "timeout", json_object_new_int(600));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_method_%d", node);
		skipd(k, v);
		json_object_object_add(ssjson, "method", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_ssr_protocol_%d", node);
		skipd(k, v);
		json_object_object_add(ssjson, "protocol", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_ssr_protocol_param_%d", node);
		skipd(k, v);
		json_object_object_add(ssjson, "protocol_param", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_ssr_obfs_%d", node);
		skipd(k, v);
		json_object_object_add(ssjson, "obfs", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_ssr_obfs_param_%d", node);
		skipd(k, v);
		json_object_object_add(ssjson, "obfs_param", json_object_new_string(v));
		//if(access("/proc/sys/net/ipv4/tcp_fastopen",F_OK) == 0)
		//	json_object_object_add(ssjson, "fast_open", json_object_new_boolean(1));
		//else
			json_object_object_add(ssjson, "fast_open", json_object_new_boolean(0));
		json_object_object_add(ssjson, "reuse_port", json_object_new_boolean(1));
	}
	if((fp = fopen(path, "w"))){
		fprintf(fp, "%s\n", json_object_to_json_string(ssjson));
		fclose(fp);
	}
	json_object_put(ssjson);
	return 0;
}

int gen_xray_conf(int type, int netflix, char *path, int local_port, int socks_port, char *proto)
{
	char k[99], v[9999];
	int tls, transport, node;
	FILE *fp;
	struct json_object *xrayjson = NULL;
	xrayjson = json_object_new_object();
	struct json_object *log_item = json_object_new_object();
	struct json_object *inbound_item = json_object_new_object();
	struct json_object *settings_item = json_object_new_object();
	struct json_object *sniffing_item = json_object_new_object();
	struct json_object *destOverride = json_object_new_array();
	struct json_object *inboundDetour_array = json_object_new_array();
	struct json_object *inboundDetour_item = json_object_new_object();
	struct json_object *settings2_item = json_object_new_object();
	struct json_object *outbound_item = json_object_new_object();
	struct json_object *outbound_settings_item = json_object_new_object();
	struct json_object *outbound_vnext_array = json_object_new_array();
	struct json_object *outbound_vnext_item = json_object_new_object();
	struct json_object *outbound_servers_item = json_object_new_object();
	struct json_object *outbound_servers_array = json_object_new_array();
	struct json_object *outbound_users_array = json_object_new_array();
	struct json_object *outbound_users_item = json_object_new_object();
	struct json_object *outbound_streamSettings = json_object_new_object();
	struct json_object *outbound_tlsSettings = json_object_new_object();
	struct json_object *outbound_xtlsSettings = json_object_new_object();
	struct json_object *outbound_tcpSettings = json_object_new_object();
	struct json_object *outbound_tcpSettings_header = json_object_new_object();
	struct json_object *outbound_tcpSettings_request = json_object_new_object();
	struct json_object *outbound_tcpSettings_headers = json_object_new_object();
	struct json_object *outbound_kcpSettings = json_object_new_object();
	struct json_object *outbound_kcpSettings_header = json_object_new_object();
	struct json_object *outbound_wsSettings = json_object_new_object();
	struct json_object *outbound_wsSettings_headers = json_object_new_object();
	struct json_object *outbound_httpSettings = json_object_new_object();
	struct json_object *outbound_quicSettings = json_object_new_object();
	struct json_object *outbound_quicSettings_header = json_object_new_object();
	struct json_object *outbound_grpcSettings = json_object_new_object();
	struct json_object *mux = json_object_new_object();
	memset(v, 0, sizeof(v));
	skipd("ssconf_basic_node", v);
	node = atoi(v);

	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_v2ray_protocol_%d", node);
	skipd(k, v);
	if(!strcmp(v, "vmess"))
		type = TYPE_VMESS;
	else if(!strcmp(v, "vless"))
		type = TYPE_VLESS;
	else if(!strcmp(v, "trojan"))
		type = TYPE_TROJAN;
	else if(!strcmp(v, "ss"))
		type = TYPE_SS;
	else if(!strcmp(v, "socks"))
		type = TYPE_SOCKS;
	else if(!strcmp(v, "http")){
		type = TYPE_HTTP;
	}else
		type = NET_ERR;


	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_security_%d", node);
	skipd(k, v);
	if(!strcmp(v, "xtls"))
		tls = TLS_XTLS;
	else if(!strcmp(v, "tls"))
		tls = TLS_TLS;
	else
		tls = TLS_ERR;
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_%d", node);
	skipd(k, v);
	if(!strcmp(v, "tcp"))
		transport = NET_TCP;
	else if(!strcmp(v, "kcp"))
		transport = NET_KCP;
	else if(!strcmp(v, "ws"))
		transport = NET_WS;
	else if(!strcmp(v, "h2"))
		transport = NET_H2;
	else if(!strcmp(v, "quic"))
		transport = NET_QUIC;
	else if(!strcmp(v, "grpc")){
		transport = NET_GRPC;
		tls = TLS_TLS;
	}else
		transport = NET_ERR;

	json_object_object_add(log_item, "error", json_object_new_string("/tmp/xray.log"));
	json_object_object_add(log_item, "logleve", json_object_new_string("warning"));
	json_object_object_add(xrayjson, "log", log_item);
	if(local_port != 0){
		json_object_object_add(inbound_item, "port", json_object_new_int(local_port));
		json_object_object_add(inbound_item, "protocol", json_object_new_string("dokodemo-door"));
		json_object_object_add(settings_item, "network", json_object_new_string(proto));
		json_object_object_add(settings_item, "followRedirect", json_object_new_boolean(1));
		json_object_object_add(inbound_item, "settings", settings_item);
		json_object_object_add(sniffing_item, "enabled", json_object_new_boolean(1));
		json_object_array_add(destOverride, json_object_new_string("http"));
		json_object_array_add(destOverride, json_object_new_string("tls"));
		json_object_object_add(sniffing_item, "destOverride", destOverride);
		json_object_object_add(inbound_item, "sniffing", sniffing_item);
		json_object_object_add(xrayjson, "inbound", inbound_item);
	}
	if(socks_port != 0 && strstr(proto, "tcp")){
		json_object_object_add(inboundDetour_item, "protocol", json_object_new_string("socks"));
		json_object_object_add(inboundDetour_item, "port", json_object_new_int(socks_port));
		json_object_object_add(settings2_item, "auth", json_object_new_string("noauth"));
		json_object_object_add(settings2_item, "udp", json_object_new_boolean(1));
		json_object_object_add(inboundDetour_item, "settings", settings2_item);
		json_object_array_add(inboundDetour_array, inboundDetour_item);
	}
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_v2ray_protocol_%d", node);
	skipd(k, v);
	json_object_object_add(outbound_item, "protocol", json_object_new_string(v));
	if(type == TYPE_VMESS || type == TYPE_VLESS){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_server_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_vnext_item, "address", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_port_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_vnext_item, "port", json_object_new_int(atoi(v)));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_uuid_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_users_item, "id", json_object_new_string(v));
		if(type == TYPE_VMESS){
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_v2ray_alterid_%d", node);
			skipd(k, v);
			json_object_object_add(outbound_users_item, "alterId", json_object_new_int(atoi(v)));
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_v2ray_security_%d", node);
			skipd(k, v);
			json_object_object_add(outbound_users_item, "security", json_object_new_string(v));
		} else if (type == TYPE_VLESS){
			//memset(v, 0, sizeof(v));
			//skipd("ss_basic_v2ray_encryption", v);
			json_object_object_add(outbound_users_item, "encryption", json_object_new_string("none"));
			if(tls == TLS_XTLS){
				memset(v, 0, sizeof(v));
				memset(k, 0, sizeof(k));
				snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_flow_%d", node);
				skipd(k, v);
				json_object_object_add(outbound_users_item, "flow", json_object_new_string(v));
			}
		}
		json_object_array_add(outbound_users_array, outbound_users_item);
		json_object_object_add(outbound_vnext_item, "users", outbound_users_array);
		json_object_array_add(outbound_vnext_array, outbound_vnext_item);
		json_object_object_add(outbound_settings_item, "vnext", outbound_vnext_array);
	}else if (type == TYPE_SS || type == TYPE_TROJAN){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_server_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_servers_item, "address", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_port_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_servers_item, "port", json_object_new_int(atoi(v)));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_password_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_servers_item, "password", json_object_new_string(base64_decode(v)));
		if (type == TYPE_SS){
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_method_%d", node);
			skipd(k, v);
			json_object_object_add(outbound_servers_item, "method", json_object_new_string(v));
		}else if(tls == TLS_XTLS){
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_flow_%d", node);
			skipd(k, v);
			json_object_object_add(outbound_servers_item, "flow", json_object_new_string(v));
		}
		json_object_array_add(outbound_servers_array, outbound_servers_item);
		json_object_object_add(outbound_settings_item, "servers", outbound_servers_array);
	}else if (type == TYPE_SOCKS || type == TYPE_HTTP){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_server_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_servers_item, "address", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_port_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_servers_item, "port", json_object_new_int(atoi(v)));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_auth_%d", node);
		skipd(k, v);
		if(atoi(v) == 1){
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_username_%d", node);
			skipd(k, v);
			json_object_object_add(outbound_users_item, "user", json_object_new_string(v));
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_password_%d", node);
			skipd(k, v);
			json_object_object_add(outbound_users_item, "pass", json_object_new_string(base64_decode(v)));
			json_object_object_add(outbound_servers_item, "users", outbound_users_item);
		}

		json_object_array_add(outbound_servers_array, outbound_servers_item);
		json_object_object_add(outbound_settings_item, "servers", outbound_servers_array);
	}
	json_object_object_add(outbound_item, "settings", outbound_settings_item);
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_%d", node);
	skipd(k, v);
	json_object_object_add(outbound_streamSettings, "network", json_object_new_string(v));
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_security_%d", node);
	skipd(k, v);
	json_object_object_add(outbound_streamSettings, "security", json_object_new_string(v));
	if(tls == TLS_TLS){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_fingerprint_%d", node);
		skipd(k, v);
		if(*v)
			json_object_object_add(outbound_tlsSettings, "fingerprint", json_object_new_string(v));
		else
			json_object_object_add(outbound_tlsSettings, "fingerprint", json_object_new_string("disable"));
		json_object_object_add(outbound_tlsSettings, "allowInsecure", json_object_new_boolean(1));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_tlshost_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_tlsSettings, "serverName", json_object_new_string(v));
		json_object_object_add(outbound_streamSettings, "tlsSettings", outbound_tlsSettings);
	} else if(tls == TLS_XTLS){
		json_object_object_add(outbound_xtlsSettings, "allowInsecure", json_object_new_boolean(1));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_tlshost_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_xtlsSettings, "serverName", json_object_new_string(v));
		json_object_object_add(outbound_streamSettings, "xtlsSettings", outbound_xtlsSettings);
	}
	if(transport == NET_TCP){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_headtype_tcp_%d", node);
		skipd(k, v);
		if(!strcmp(v, "http")){
			json_object_object_add(outbound_tcpSettings_header, "type", json_object_new_string("http"));
				//memset(v, 0, sizeof(v));
				//skipd("ss_basic_v2ray_headtype_tcp_http_path", v);
				//fprintf(fp, "						\"path\" = \"{%s}\",\n", v); or {"/"},
			json_object_object_add(outbound_tcpSettings_request, "path", json_object_new_string("/"));
			memset(v, 0, sizeof(v));
			memset(k, 0, sizeof(k));
			snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_host_%d", node);
			skipd(k, v);
			json_object_object_add(outbound_tcpSettings_headers, "Host", json_object_new_string(v));
			json_object_object_add(outbound_tcpSettings_request, "headers", outbound_tcpSettings_headers);
			json_object_object_add(outbound_tcpSettings_header, "request", outbound_tcpSettings_request);
			json_object_object_add(outbound_tcpSettings, "header", outbound_tcpSettings_header);
			json_object_object_add(outbound_streamSettings, "tcpSettings", outbound_tcpSettings);
		}
	}else if(transport == NET_KCP){
		//memset(v, 0, sizeof(v));
		//skipd("ss_basic_v2ray_headtype_kcp_mtu", v);
		json_object_object_add(outbound_kcpSettings, "mtu", json_object_new_int(1500));
		json_object_object_add(outbound_kcpSettings, "tti", json_object_new_int(50));
		json_object_object_add(outbound_kcpSettings, "uplinkCapacity", json_object_new_int(12));
		json_object_object_add(outbound_kcpSettings, "downlinkCapacity", json_object_new_int(100));
		json_object_object_add(outbound_kcpSettings, "congestion", json_object_new_boolean(0));
		json_object_object_add(outbound_kcpSettings, "readBufferSize", json_object_new_int(2));
		json_object_object_add(outbound_kcpSettings, "writeBufferSize", json_object_new_int(2));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_headtype_tcp_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_kcpSettings_header, "type", json_object_new_string(v));
		//memset(v, 0, sizeof(v));
		//skipd("ss_basic_v2ray_headtype_kcp_seed", v);
		//json_object_object_add(outbound_kcpSettings_header, "seed", json_object_new_string(v));
		json_object_object_add(outbound_kcpSettings, "header", outbound_kcpSettings_header);
		json_object_object_add(outbound_streamSettings, "kcpSettings", outbound_kcpSettings);
	}else if(transport == NET_WS){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_path_%d", node);
		skipd(k, v);
		if(strlen(v))
			json_object_object_add(outbound_wsSettings, "path", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_host_%d", node);
		skipd(k, v);
		if(strlen(v)){
			json_object_object_add(outbound_wsSettings_headers, "Host", json_object_new_string(v));
			json_object_object_add(outbound_wsSettings, "headers", outbound_wsSettings_headers);
		}
		json_object_object_add(outbound_streamSettings, "wsSettings", outbound_wsSettings);
	}else if(transport == NET_H2){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_path_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_httpSettings, "path", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_network_host_%d", node);
		skipd(k, v);
		if(strlen(v))
			json_object_object_add(outbound_httpSettings, "host", json_object_new_string(v));
		json_object_object_add(outbound_streamSettings, "httpSettings", outbound_httpSettings);
	}else if(transport == NET_QUIC){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_quic_security_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_quicSettings, "security", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_quic_key_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_quicSettings, "key", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_quic_guise_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_quicSettings_header, "type", json_object_new_string(v));
		json_object_object_add(outbound_quicSettings, "header", outbound_quicSettings_header);
		json_object_object_add(outbound_streamSettings, "quicSettings", outbound_quicSettings);
	}else if(transport == NET_GRPC){
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_grpc_serviceName_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_grpcSettings, "serviceName", json_object_new_string(v));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_mux_enable_%d", node);
		skipd(k, v);
		json_object_object_add(outbound_grpcSettings, "multiMode", json_object_new_boolean(atoi(v)));
		json_object_object_add(outbound_streamSettings, "grpcSettings", outbound_quicSettings);
	}
	json_object_object_add(outbound_item, "streamSettings", outbound_streamSettings);
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_v2ray_mux_enable_%d", node);
	skipd(k, v);
	if(atoi(v) == 1 && tls != TLS_XTLS && transport != NET_GRPC){
		json_object_object_add(mux, "enabled", json_object_new_boolean(1));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_v2ray_mux_concurrency_%d", node);
		skipd(k, v);
		json_object_object_add(mux, "concurrency", json_object_new_int(atoi(v)));
		json_object_object_add(outbound_item, "mux", mux);
	}
	json_object_object_add(xrayjson, "outbound", outbound_item);
	if((fp = fopen(path, "w"))){
		fprintf(fp, "%s\n", json_object_to_json_string(xrayjson));
		fclose(fp);
	}
	json_object_put(mux);
	json_object_put(outbound_grpcSettings);
	json_object_put(outbound_quicSettings_header);
	json_object_put(outbound_quicSettings);
	json_object_put(outbound_httpSettings);
	json_object_put(outbound_wsSettings_headers);
	json_object_put(outbound_wsSettings);
	json_object_put(outbound_kcpSettings_header);
	json_object_put(outbound_kcpSettings);
	json_object_put(outbound_tcpSettings_headers);
	json_object_put(outbound_tcpSettings_request);
	json_object_put(outbound_tcpSettings_header);
	json_object_put(outbound_tcpSettings);
	json_object_put(outbound_tlsSettings);
	json_object_put(outbound_xtlsSettings);
	json_object_put(outbound_streamSettings);
	json_object_put(outbound_users_item);
	json_object_put(outbound_users_array);
	json_object_put(outbound_servers_item);
	json_object_put(outbound_servers_array);
	json_object_put(outbound_vnext_item);
	json_object_put(outbound_vnext_array);
	json_object_put(outbound_settings_item);
	json_object_put(outbound_item);
	json_object_put(settings2_item);
	json_object_put(inboundDetour_item);
	json_object_put(inboundDetour_array);
	json_object_put(destOverride);
	json_object_put(sniffing_item);
	json_object_put(settings_item);
	json_object_put(inbound_item);
	json_object_put(log_item);
	json_object_put(xrayjson);
	return 0;
}

int gen_trojan_conf(int type, int netflix, char *path, int local_port, int socks_port, char *proto)
{
	char k[99], v[9999];
	int tls, transport, node;
	FILE *fp;
	struct json_object *trojanjson = NULL;
	trojanjson = json_object_new_object();
	struct json_object *password = json_object_new_array();
	struct json_object *ssl = json_object_new_object();
	struct json_object *alpn = json_object_new_array();
	struct json_object *mux = json_object_new_object();
	struct json_object *tcp = json_object_new_object();
	memset(v, 0, sizeof(v));
	skipd("ssconf_basic_node", v);
	node = atoi(v);
	json_object_object_add(trojanjson, "log_level", json_object_new_int(3));
	if(!strcmp(proto, "nat") || !strcmp(proto, "tcp"))
		json_object_object_add(trojanjson, "run_type", json_object_new_string("nat"));
	else
		json_object_object_add(trojanjson, "run_type", json_object_new_string("client"));
	json_object_object_add(trojanjson, "local_add", json_object_new_string("0.0.0.0"));
	json_object_object_add(trojanjson, "local_port", json_object_new_int(local_port));
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_server_%d", node);
	skipd(k, v);
	json_object_object_add(trojanjson, "remote_addr", json_object_new_string(v));
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_port_%d", node);
	skipd(k, v);
	json_object_object_add(trojanjson, "remote_port", json_object_new_int(atoi(v)));
	json_object_object_add(trojanjson, "udp_timeout", json_object_new_int(60));
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_password_%d", node);
	skipd(k, v);
	json_object_array_add(password, json_object_new_string(base64_decode(v)));
	json_object_object_add(trojanjson, "password", password);
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_ssl_verify_enable_%d", node);
	skipd(k, v);
	if(atoi(v) == 1)
		json_object_object_add(ssl, "verify", json_object_new_boolean(1));
	else
		json_object_object_add(ssl, "verify", json_object_new_boolean(0));
	//memset(v, 0, sizeof(v));
	//memset(k, 0, sizeof(k));
	//snprintf(k, sizeof(k), "ssconf_basic_trojan_tls_%d", node);
	//skipd(k, v);
	//if(atoi(v) == 1)
		json_object_object_add(ssl, "verify_hostname", json_object_new_boolean(1));
	//else
		//json_object_object_add(ssl, "verify_hostname", json_object_new_boolean(0));
	if(access("/rom/etc/ssl/certs/ca-certificates.crt",F_OK) == 0)
		json_object_object_add(ssl, "cert", json_object_new_string("/rom/etc/ssl/certs/ca-certificates.crt"));
	else
		json_object_object_add(ssl, "cert", json_object_new_string(""));
	json_object_object_add(ssl, "ciphe", json_object_new_string("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA"));
	json_object_object_add(ssl, "cipher_tls13", json_object_new_string("TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"));
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_trojan_sni_%d", node);
	skipd(k, v);
	json_object_object_add(ssl, "sni", json_object_new_string(v));
	json_object_array_add(alpn, json_object_new_string("h2"));
	json_object_array_add(alpn, json_object_new_string("http/1.1"));
	json_object_object_add(ssl, "alpn", alpn);
	json_object_object_add(ssl, "curve", json_object_new_string(""));
	json_object_object_add(ssl, "reuse_sessione", json_object_new_boolean(1));
	//memset(v, 0, sizeof(v));
	//memset(k, 0, sizeof(k));
	//snprintf(k, sizeof(k), "ssconf_basic_trojan_tls_sessionTicket_%d", node);
	//skipd(k, v);
	//if(atoi(v) == 1)
		//json_object_object_add(ssl, "session_ticket", json_object_new_boolean(1));
	//else
		json_object_object_add(ssl, "session_ticket", json_object_new_boolean(0));
	json_object_object_add(trojanjson, "ssl", ssl);
	json_object_object_add(trojanjson, "udp_timeout", json_object_new_int(60));
	memset(v, 0, sizeof(v));
	memset(k, 0, sizeof(k));
	snprintf(k, sizeof(k), "ssconf_basic_trojan_mp_enable_%d", node);
	skipd(k, v);
	if(atoi(v) == 1){
		json_object_object_add(mux, "enabled", json_object_new_boolean(1));
		memset(v, 0, sizeof(v));
		memset(k, 0, sizeof(k));
		snprintf(k, sizeof(k), "ssconf_basic_trojan_mulprocess_%d", node);
		skipd(k, v);
		json_object_object_add(mux, "concurrency", json_object_new_int(atoi(v)));
		json_object_object_add(mux, "idle_timeout", json_object_new_int(60));
		json_object_object_add(trojanjson, "mux", mux);
	}
	json_object_object_add(tcp, "no_delay", json_object_new_boolean(1));
	json_object_object_add(tcp, "keep_alive", json_object_new_boolean(1));
	json_object_object_add(tcp, "reuse_port", json_object_new_boolean(1));
	//if(access("/proc/sys/net/ipv4/tcp_fastopen",F_OK) == 0)
	//	json_object_object_add(tcp, "fast_open", json_object_new_boolean(1));
	//else
		json_object_object_add(tcp, "fast_open", json_object_new_boolean(0));
	json_object_object_add(tcp, "fast_open_qlen", json_object_new_int(20));
	json_object_object_add(trojanjson, "tcp", tcp);
	if((fp = fopen(path, "w"))){
		fprintf(fp, "%s\n", json_object_to_json_string(trojanjson));
		fclose(fp);
	}
	json_object_put(tcp);
	json_object_put(mux);
	json_object_put(alpn);
	json_object_put(ssl);
	json_object_put(password);
	json_object_put(trojanjson);
	return 0;
}

//gen_conf $netflix_enable $conf_file $local_port  $socks_port $proto
int main(int argc, char **argv) {
	if (argc != 6 || (atoi(argv[1]) != 0 && atoi(argv[1]) != 1) || atoi(argv[3]) < 1 || atoi(argv[4]) < 1){
		printf("gen_conf $netflix_enable $conf_file $local_port $socks_port $proto\n");
		printf("Feedback bugs on the website : https://github.com/zusterben/plan_b/issues\n");
		return 0;
	}
	char v[9999];
	int netflix = atoi(argv[1]);
	int port = atoi(argv[3]);
	int socks = atoi(argv[4]);
	memset(v, 0, sizeof(v));
	if(skipd("ssconf_basic_node", v) != 0)
		return 1;
	memset(v, 0, sizeof(v));
	if(skipd("ss_basic_type", v) != 0)
		return 1;
	switch(atoi(v)){
	case 0://ss
		gen_ss_conf(0, netflix, argv[2], port);
		break;
	case 1://ssr
		gen_ss_conf(1, netflix, argv[2], port);
		break;
	case 2://v2ray
		gen_xray_conf(2, netflix, argv[2], port, socks, argv[5]);
		break;
	case 3://trojan
		gen_trojan_conf(3, netflix, argv[2], port, socks, argv[5]);
		break;
	default:
		return 1;
	}
    return 0;
}

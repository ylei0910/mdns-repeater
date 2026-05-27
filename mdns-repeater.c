/*
 * mdns-repeater.c - mDNS repeater daemon
 * Copyright (C) 2011 Darell Tan
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>

#define PACKAGE "mdns-repeater"
#define MDNS_ADDR "224.0.0.251"
#define MDNS_PORT 5353

#ifndef PIDFILE
#define PIDFILE "/var/run/" PACKAGE ".pid"
#endif

#define MAX_SOCKS   16
#define MAX_SUBNETS 16
#define MAX_RULES   16

struct if_sock {
	const char *ifname;
	int sockfd;
	struct in_addr addr;
	struct in_addr mask;
	struct in_addr net;
	int query_only;
	char subnet_str[32];  /* "10.108.0.0/16" — pre-computed at setup */
};

struct subnet {
	struct in_addr addr;
	struct in_addr mask;
	struct in_addr net;
};

/* One rule: personal (Q-only) subnet connects to one or more destination subnets */
struct rule {
	struct subnet q_subnet;
	struct subnet dests[MAX_SOCKS];
	int num_dests;
};

/* Per-socket list of destination socket indices (routing table) */
struct routing_entry {
	int dests[MAX_SOCKS];
	int num_dests;
};

int server_sockfd = -1;

int num_socks = 0;
struct if_sock socks[MAX_SOCKS];

int num_blacklisted_subnets = 0;
struct subnet blacklisted_subnets[MAX_SUBNETS];

int num_whitelisted_subnets = 0;
struct subnet whitelisted_subnets[MAX_SUBNETS];

static struct rule rules[MAX_RULES];
static int num_rules = 0;
static struct routing_entry routing[MAX_SOCKS];

#define PACKET_SIZE 65536
void *pkt_data = NULL;

int foreground = 0;
int shutdown_flag = 0;

char *pid_file = PIDFILE;
char *rules_file = NULL;

const struct passwd *user = NULL;

char *debug_log_file = NULL;
FILE *debug_log_fp = NULL;

char *service_filter_file = NULL;
static char **filter_services = NULL;
static size_t *filter_service_lens = NULL;
static int num_filter_services = 0;

#define MAX_SEEN_NAMES 4096
#define SEEN_KEY_LEN   320
static char seen_keys[MAX_SEEN_NAMES][SEEN_KEY_LEN];

/* -------------------------------------------------------------------------
 * Logging
 * ---------------------------------------------------------------------- */

void log_message(int loglevel, char *fmt_str, ...) {
	va_list ap;
	char buf[2048];

	va_start(ap, fmt_str);
	vsnprintf(buf, 2047, fmt_str, ap);
	va_end(ap);
	buf[2047] = 0;

	if (foreground)
		fprintf(stderr, "%s: %s\n", PACKAGE, buf);
	else
		syslog(loglevel, "%s", buf);
}

/* -------------------------------------------------------------------------
 * Subnet parsing
 * ---------------------------------------------------------------------- */

static int parse(char *input, struct subnet *s) {
	int delim = 0, end = 0;
	while (input[end] != 0) {
		if (input[end] == '/') delim = end;
		end++;
	}
	if (end == 0 || delim == 0 || end == delim) return -1;

	char *addr = (char *)malloc(end + 1);
	memset(addr, 0, end + 1);

	strncpy(addr, input, delim);
	if (inet_pton(AF_INET, addr, &s->addr) != 1) { free(addr); return -2; }

	memset(addr, 0, end + 1);
	strncpy(addr, input + delim + 1, end - delim - 1);
	int mask = atoi(addr);
	free(addr);

	if (mask < 0 || mask > 32) return -3;

	s->mask.s_addr = ntohl((uint32_t)0xFFFFFFFF << (32 - mask));
	s->net.s_addr = s->addr.s_addr & s->mask.s_addr;
	return 0;
}

static int mask_to_prefix(struct in_addr mask) {
	uint32_t m = ntohl(mask.s_addr);
	int prefix = 0;
	while (m & 0x80000000) { prefix++; m <<= 1; }
	return prefix;
}

static int tostring(struct subnet *s, char *buf, int len) {
	char *addr_str = strdup(inet_ntoa(s->addr));
	char *mask_str = strdup(inet_ntoa(s->mask));
	char *net_str  = strdup(inet_ntoa(s->net));
	int l = snprintf(buf, len, "addr %s mask %s net %s", addr_str, mask_str, net_str);
	free(addr_str); free(mask_str); free(net_str);
	return l;
}

/* -------------------------------------------------------------------------
 * DNS name parser (wire format with pointer compression)
 * ---------------------------------------------------------------------- */

static int dns_read_name(const unsigned char *pkt, size_t pktlen, size_t offset,
                          char *out, size_t outlen) {
	size_t pos = offset, out_pos = 0, first_end = 0;
	int jumped = 0, jumps = 0;
	while (pos < pktlen && jumps <= 10) {
		unsigned char label_len = pkt[pos];
		if (label_len == 0) {
			if (!jumped) first_end = pos + 1;
			if (out_pos > 0 && out[out_pos - 1] == '.') out_pos--;
			out[out_pos] = '\0';
			return (int)(first_end - offset);
		}
		if ((label_len & 0xC0) == 0xC0) {
			if (pos + 1 >= pktlen) return -1;
			if (!jumped) first_end = pos + 2;
			jumped = 1;
			pos = ((label_len & 0x3F) << 8) | pkt[pos + 1];
			jumps++;
			continue;
		}
		if (label_len & 0xC0) return -1;
		pos++;
		if (pos + label_len > pktlen || out_pos + label_len + 1 >= outlen) return -1;
		memcpy(out + out_pos, pkt + pos, label_len);
		out_pos += label_len;
		out[out_pos++] = '.';
		pos += label_len;
	}
	return -1;
}

/* -------------------------------------------------------------------------
 * Service filter
 * ---------------------------------------------------------------------- */

static int load_service_filter(const char *file) {
	FILE *f = fopen(file, "r");
	if (!f) {
		log_message(LOG_ERR, "cannot open service filter %s: %s", file, strerror(errno));
		return -1;
	}
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		int len = strlen(line);
		while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
			line[--len] = '\0';
		if (len == 0 || line[0] == '#') continue;
		char **tmp = realloc(filter_services, (num_filter_services + 1) * sizeof(char *));
		if (!tmp) { fclose(f); return -1; }
		size_t *ltmp = realloc(filter_service_lens, (num_filter_services + 1) * sizeof(size_t));
		if (!ltmp) { fclose(f); return -1; }
		filter_services = tmp;
		filter_service_lens = ltmp;
		filter_service_lens[num_filter_services] = (size_t)len;
		filter_services[num_filter_services++] = strdup(line);
	}
	fclose(f);
	return 0;
}

static int packet_matches_filter(const unsigned char *pkt, size_t pktlen) {
	if (num_filter_services == 0) return 1;
	if (pktlen < 12) return 0;
	uint16_t qdcount = (pkt[4] << 8) | pkt[5];
	uint16_t ancount = (pkt[6] << 8) | pkt[7];
	uint16_t total = qdcount + ancount;
	size_t pos = 12;
	char name[256];
	int consumed;
	uint16_t i;
	for (i = 0; i < total && pos < pktlen; i++) {
		consumed = dns_read_name(pkt, pktlen, pos, name, sizeof(name));
		if (consumed <= 0) break;
		pos += (size_t)consumed;
		if (i < qdcount) {
			if (pos + 4 > pktlen) break;
			pos += 4;
		} else {
			if (pos + 10 > pktlen) break;
			uint16_t rdlen = (pkt[pos + 8] << 8) | pkt[pos + 9];
			pos += 10 + rdlen;
		}
		size_t name_len = strlen(name);
		int j;
		for (j = 0; j < num_filter_services; j++) {
			size_t svc_len = filter_service_lens[j];
			if (name_len < svc_len) continue;
			const char *suffix = name + name_len - svc_len;
			if ((suffix == name || *(suffix - 1) == '.') &&
			    strcasecmp(suffix, filter_services[j]) == 0)
				return 1;
		}
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Debug log (deduped, format: <src_ip> <name> -> <dest1/prefix> ... | SKIP)
 * ---------------------------------------------------------------------- */

static int seen_add(const char *key) {
	unsigned int h = 5381;
	const char *p;
	for (p = key; *p; p++) h = h * 33 ^ (unsigned char)*p;
	h %= MAX_SEEN_NAMES;
	unsigned int i = h;
	do {
		if (seen_keys[i][0] == '\0') {
			strncpy(seen_keys[i], key, SEEN_KEY_LEN - 1);
			return 1;
		}
		if (strcmp(seen_keys[i], key) == 0) return 0;
		i = (i + 1) % MAX_SEEN_NAMES;
	} while (i != h);
	return 1;
}

/* dest_str: "-> 192.168.53.0/24 10.108.0.0/16"  or  "SKIP" */
static void log_packet_names(const char *src_ip,
                              const unsigned char *pkt, size_t pktlen,
                              const char *dest_str) {
	if (!debug_log_fp || pktlen < 12) return;
	uint16_t qdcount = (pkt[4] << 8) | pkt[5];
	uint16_t ancount = (pkt[6] << 8) | pkt[7];
	uint16_t total = qdcount + ancount;
	size_t pos = 12;
	char name[256], key[320];
	int consumed;
	uint16_t i;
	for (i = 0; i < total && pos < pktlen; i++) {
		consumed = dns_read_name(pkt, pktlen, pos, name, sizeof(name));
		if (consumed <= 0) break;
		pos += (size_t)consumed;
		if (i < qdcount) {
			if (pos + 4 > pktlen) break;
			pos += 4;
		} else {
			if (pos + 10 > pktlen) break;
			uint16_t rdlen = (pkt[pos + 8] << 8) | pkt[pos + 9];
			pos += 10 + rdlen;
		}
		snprintf(key, sizeof(key), "%s %s %s", src_ip, name, dest_str);
		if (seen_add(key)) {
			fprintf(debug_log_fp, "%s %s %s\n", src_ip, name, dest_str);
			fflush(debug_log_fp);
		}
	}
}

/* -------------------------------------------------------------------------
 * Rules loading
 * ---------------------------------------------------------------------- */

static int load_rules(const char *file) {
	FILE *f = fopen(file, "r");
	if (!f) {
		log_message(LOG_ERR, "cannot open rules file %s: %s", file, strerror(errno));
		return -1;
	}
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		int len = strlen(line);
		while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
		if (len == 0 || line[0] == '#') continue;

		if (num_rules >= MAX_RULES) {
			log_message(LOG_ERR, "too many rules (max %d)", MAX_RULES);
			fclose(f); return -1;
		}

		struct rule *rule = &rules[num_rules];
		rule->num_dests = 0;

		char *colon = strchr(line, ':');
		if (!colon) {
			log_message(LOG_ERR, "invalid rule (missing ':'): %s", line);
			fclose(f); return -1;
		}
		*colon = '\0';

		/* trim Q subnet string */
		char *q_str = line;
		int q_len = strlen(q_str);
		while (q_len > 0 && q_str[q_len-1] == ' ') q_str[--q_len] = '\0';

		if (parse(q_str, &rule->q_subnet) != 0) {
			log_message(LOG_ERR, "invalid Q subnet: %s", q_str);
			fclose(f); return -1;
		}

		char *token = strtok(colon + 1, " \t");
		while (token) {
			if (rule->num_dests >= MAX_SOCKS) {
				log_message(LOG_ERR, "too many destinations in rule");
				fclose(f); return -1;
			}
			if (parse(token, &rule->dests[rule->num_dests]) != 0) {
				log_message(LOG_ERR, "invalid destination subnet: %s", token);
				fclose(f); return -1;
			}
			rule->num_dests++;
			token = strtok(NULL, " \t");
		}

		if (rule->num_dests == 0) {
			log_message(LOG_ERR, "rule has no destinations");
			fclose(f); return -1;
		}

		log_message(LOG_INFO, "rule: %s/%d [Q] -> %d dest(s)",
			inet_ntoa(rule->q_subnet.net),
			mask_to_prefix(rule->q_subnet.mask),
			rule->num_dests);
		num_rules++;
	}
	fclose(f);
	return 0;
}

/* -------------------------------------------------------------------------
 * Socket creation
 * ---------------------------------------------------------------------- */

static int create_recv_sock() {
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "recv socket(): %s", strerror(errno));
		return sd;
	}

	int r = -1;
	int on = 1;
	if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(SO_REUSEADDR): %s", strerror(errno));
		return r;
	}

	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(MDNS_PORT);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
		log_message(LOG_ERR, "recv bind(): %s", strerror(errno));
	}

	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		return r;
	}

#ifdef IP_PKTINFO
	if ((r = setsockopt(sd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_PKTINFO): %s", strerror(errno));
		return r;
	}
#endif

	return sd;
}

static int create_send_sock(int recv_sockfd, const char *ifname, struct if_sock *sockdata) {
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "send socket(): %s", strerror(errno));
		return sd;
	}

	sockdata->ifname = ifname;
	sockdata->sockfd = sd;

	int r = -1;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	struct in_addr *if_addr = &((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

#ifdef SO_BINDTODEVICE
	if ((r = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(struct ifreq))) < 0) {
		log_message(LOG_ERR, "send setsockopt(SO_BINDTODEVICE): %s", strerror(errno));
		return r;
	}
#endif

	if (ioctl(sd, SIOCGIFNETMASK, &ifr) == 0)
		memcpy(&sockdata->mask, if_addr, sizeof(struct in_addr));

	if (ioctl(sd, SIOCGIFADDR, &ifr) == 0)
		memcpy(&sockdata->addr, if_addr, sizeof(struct in_addr));

	sockdata->net.s_addr = sockdata->addr.s_addr & sockdata->mask.s_addr;
	snprintf(sockdata->subnet_str, sizeof(sockdata->subnet_str), "%s/%d",
		inet_ntoa(sockdata->net), mask_to_prefix(sockdata->mask));

	int on = 1;
	if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "send setsockopt(SO_REUSEADDR): %s", strerror(errno));
		return r;
	}

	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(MDNS_PORT);
	serveraddr.sin_addr.s_addr = if_addr->s_addr;
	if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
		log_message(LOG_ERR, "send bind(): %s", strerror(errno));
	}

#if __FreeBSD__
	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &serveraddr.sin_addr, sizeof(serveraddr.sin_addr))) < 0) {
		log_message(LOG_ERR, "send ip_multicast_if(): errno %d: %s", errno, strerror(errno));
	}
#endif

	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(struct ip_mreq));
	mreq.imr_interface.s_addr = if_addr->s_addr;
	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
	if ((r = setsockopt(recv_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
		return r;
	}

	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		return r;
	}

	int ttl = 255;
	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) < 0) {
		log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_TTL): %s", strerror(errno));
		return r;
	}

	char *addr_str = strdup(inet_ntoa(sockdata->addr));
	char *mask_str = strdup(inet_ntoa(sockdata->mask));
	char *net_str  = strdup(inet_ntoa(sockdata->net));
	log_message(LOG_INFO, "dev %s addr %s mask %s net %s%s",
		ifr.ifr_name, addr_str, mask_str, net_str,
		sockdata->query_only ? " [query-only]" : "");
	free(addr_str); free(mask_str); free(net_str);

	return sd;
}

static ssize_t send_packet(int fd, const void *data, size_t len) {
	static struct sockaddr_in toaddr;
	if (toaddr.sin_family != AF_INET) {
		memset(&toaddr, 0, sizeof(struct sockaddr_in));
		toaddr.sin_family = AF_INET;
		toaddr.sin_port = htons(MDNS_PORT);
		toaddr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
	}
	return sendto(fd, data, len, 0, (struct sockaddr *) &toaddr, sizeof(struct sockaddr_in));
}

/* -------------------------------------------------------------------------
 * Subnet -> interface resolution and routing table construction
 * ---------------------------------------------------------------------- */

static const char *find_iface_for_subnet(const struct subnet *s) {
	struct ifaddrs *ifap, *ifa;
	if (getifaddrs(&ifap) != 0) {
		log_message(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	const char *result = NULL;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
		struct in_addr if_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
		if ((if_addr.s_addr & s->mask.s_addr) == s->net.s_addr) {
			result = strdup(ifa->ifa_name);
			break;
		}
	}
	freeifaddrs(ifap);
	return result;
}

static int find_sock_for_iface(const char *ifname) {
	int i;
	for (i = 0; i < num_socks; i++)
		if (strcmp(socks[i].ifname, ifname) == 0)
			return i;
	return -1;
}

static void add_route(int src, int dest) {
	int i;
	struct routing_entry *e = &routing[src];
	for (i = 0; i < e->num_dests; i++)
		if (e->dests[i] == dest) return;
	if (e->num_dests < MAX_SOCKS)
		e->dests[e->num_dests++] = dest;
}

static int setup_sockets(int recv_sockfd) {
	int r, j;

	/* First pass: create one socket per unique interface */
	for (r = 0; r < num_rules; r++) {
		struct rule *rule = &rules[r];

		/* Q subnet */
		const char *q_ifname = find_iface_for_subnet(&rule->q_subnet);
		if (!q_ifname) {
			log_message(LOG_ERR, "no interface found for subnet %s/%d",
				inet_ntoa(rule->q_subnet.net), mask_to_prefix(rule->q_subnet.mask));
			return -1;
		}
		if (find_sock_for_iface(q_ifname) < 0) {
			if (num_socks >= MAX_SOCKS) {
				free((char *)q_ifname);
				log_message(LOG_ERR, "too many sockets (max %d)", MAX_SOCKS);
				return -1;
			}
			socks[num_socks].query_only = 1;
			if (create_send_sock(recv_sockfd, q_ifname, &socks[num_socks]) < 0) return -1;
			num_socks++;
		} else {
			free((char *)q_ifname);
		}

		/* Destination subnets */
		for (j = 0; j < rule->num_dests; j++) {
			struct subnet *ds = &rule->dests[j];
			const char *d_ifname = find_iface_for_subnet(ds);
			if (!d_ifname) {
				log_message(LOG_ERR, "no interface found for subnet %s/%d",
					inet_ntoa(ds->net), mask_to_prefix(ds->mask));
				return -1;
			}
			if (find_sock_for_iface(d_ifname) < 0) {
				if (num_socks >= MAX_SOCKS) {
					free((char *)d_ifname);
					log_message(LOG_ERR, "too many sockets (max %d)", MAX_SOCKS);
					return -1;
				}
				socks[num_socks].query_only = 0;
				if (create_send_sock(recv_sockfd, d_ifname, &socks[num_socks]) < 0) return -1;
				num_socks++;
			} else {
				free((char *)d_ifname);
			}
		}
	}

	/* Second pass: build routing table */
	for (r = 0; r < num_rules; r++) {
		struct rule *rule = &rules[r];

		int participants[MAX_SOCKS + 1];
		int num_p = 0;

		const char *q_ifname = find_iface_for_subnet(&rule->q_subnet);
		if (q_ifname) {
			int qi = find_sock_for_iface(q_ifname);
			free((char *)q_ifname);
			if (qi >= 0) participants[num_p++] = qi;
		}

		for (j = 0; j < rule->num_dests; j++) {
			const char *d_ifname = find_iface_for_subnet(&rule->dests[j]);
			if (d_ifname) {
				int di = find_sock_for_iface(d_ifname);
				free((char *)d_ifname);
				if (di >= 0) {
					int k, found = 0;
					for (k = 0; k < num_p; k++) if (participants[k] == di) { found = 1; break; }
					if (!found) participants[num_p++] = di;
				}
			}
		}

		int a, b;
		for (a = 0; a < num_p; a++)
			for (b = 0; b < num_p; b++)
				if (a != b) add_route(participants[a], participants[b]);
	}

	return 0;
}

/* -------------------------------------------------------------------------
 * Daemon helpers
 * ---------------------------------------------------------------------- */

static void mdns_repeater_shutdown(int sig) {
	(void)sig;
	shutdown_flag = 1;
}

static pid_t already_running() {
	FILE *f;
	int count;
	pid_t pid;

	f = fopen(pid_file, "r");
	if (f != NULL) {
		count = fscanf(f, "%d", &pid);
		fclose(f);
		if (count == 1 && kill(pid, 0) == 0)
			return pid;
	}
	return -1;
}

static int write_pidfile() {
	FILE *f = fopen(pid_file, "w");
	if (f != NULL) {
		int r = fprintf(f, "%d", getpid());
		fclose(f);
		return (r > 0);
	}
	return 0;
}

static void daemonize() {
	pid_t running_pid;
	pid_t pid = fork();
	if (pid < 0) { log_message(LOG_ERR, "fork(): %s", strerror(errno)); exit(1); }
	if (pid > 0) exit(0);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP,  SIG_IGN);
	signal(SIGTERM, mdns_repeater_shutdown);

	setsid();
	umask(0027);
	if (chdir("/") < 0) { log_message(LOG_ERR, "unable to change to root directory"); exit(1); }

	int i;
	for (i = 0; i < 3; i++) {
		close(i);
		if (open("/dev/null", O_RDWR) != i) {
			log_message(LOG_ERR, "unable to open /dev/null for fd %d", i);
			exit(1);
		}
	}

	running_pid = already_running();
	if (running_pid != -1) {
		log_message(LOG_ERR, "already running as pid %d", running_pid);
		exit(1);
	} else if (!write_pidfile()) {
		log_message(LOG_ERR, "unable to write pid file %s", pid_file);
		exit(1);
	}
}

static void switch_user() {
	errno = 0;
	if (setgid(user->pw_gid) != 0) {
		log_message(LOG_ERR, "failed to switch to group %d: %s", user->pw_gid, strerror(errno));
		exit(2);
	}
	if (setuid(user->pw_uid) != 0) {
		log_message(LOG_ERR, "failed to switch to user %s (%d): %s", user->pw_name, user->pw_uid, strerror(errno));
		exit(2);
	}
}

/* -------------------------------------------------------------------------
 * CLI
 * ---------------------------------------------------------------------- */

static void show_help(const char *progname) {
	fprintf(stderr, "mDNS repeater (version " HGVERSION ")\n");
	fprintf(stderr, "Copyright (C) 2011 Darell Tan\n\n");
	fprintf(stderr, "usage: %s -r <rules_file> [options]\n", progname);
	fprintf(stderr, "\n"
					"rules_file: one rule per line, format:  <personal_subnet>:<subnet> [<subnet> ...]\n"
					"  personal_subnet receives the query-only (Q) flag;\n"
					"  traffic is only routed between subnets listed in the same rule.\n"
					"\n"
					" flags:\n"
					"	-r	rules file (required)\n"
					"	-f	run in foreground for debugging\n"
					"	-b	blacklist source subnet (eg. 192.168.1.0/24)\n"
					"	-w	whitelist source subnet (eg. 192.168.1.0/24)\n"
					"	-p	pid file path (default: " PIDFILE ")\n"
					"	-u	run as this user (by name)\n"
					"	-S	only repeat services listed in file (one suffix per line, # comments)\n"
					"	-d	log repeated mDNS names to file (deduped, format: <subnet> <ip> <name>)\n"
					"	-h	shows this help\n"
					"\n"
		);
}

static void parse_opts(int argc, char *argv[]) {
	int c, res;
	int help = 0;
	struct subnet *ss;
	char *msg;

	while ((c = getopt(argc, argv, "hfr:p:b:w:u:S:d:")) != -1) {
		switch (c) {
			case 'h': help = 1; break;
			case 'f': foreground = 1; break;

			case 'r':
				rules_file = optarg;
				break;

			case 'p':
				if (optarg[0] != '/')
					log_message(LOG_ERR, "pid file path must be absolute");
				else
					pid_file = optarg;
				break;

			case 'b':
				if (num_blacklisted_subnets >= MAX_SUBNETS) {
					log_message(LOG_ERR, "too many blacklisted subnets (max %d)", MAX_SUBNETS);
					exit(2);
				}
				if (num_whitelisted_subnets != 0) {
					log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
					exit(2);
				}
				ss = &blacklisted_subnets[num_blacklisted_subnets];
				res = parse(optarg, ss);
				if (res != 0) { log_message(LOG_ERR, "invalid blacklist subnet: %s", optarg); exit(2); }
				num_blacklisted_subnets++;
				msg = malloc(128); memset(msg, 0, 128);
				tostring(ss, msg, 128);
				log_message(LOG_INFO, "blacklist %s", msg);
				free(msg);
				break;

			case 'w':
				if (num_whitelisted_subnets >= MAX_SUBNETS) {
					log_message(LOG_ERR, "too many whitelisted subnets (max %d)", MAX_SUBNETS);
					exit(2);
				}
				if (num_blacklisted_subnets != 0) {
					log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
					exit(2);
				}
				ss = &whitelisted_subnets[num_whitelisted_subnets];
				res = parse(optarg, ss);
				if (res != 0) { log_message(LOG_ERR, "invalid whitelist subnet: %s", optarg); exit(2); }
				num_whitelisted_subnets++;
				msg = malloc(128); memset(msg, 0, 128);
				tostring(ss, msg, 128);
				log_message(LOG_INFO, "whitelist %s", msg);
				free(msg);
				break;

			case 'u':
				if ((user = getpwnam(optarg)) == NULL) {
					log_message(LOG_ERR, "no such user '%s'", optarg);
					exit(2);
				}
				break;

			case 'S':
				service_filter_file = optarg;
				break;

			case 'd':
				debug_log_file = optarg;
				break;

			case '?':
			case ':':
				fputs("\n", stderr);
				break;

			default:
				log_message(LOG_ERR, "unknown option %c", optopt);
				exit(2);
		}
	}

	if (help) { show_help(argv[0]); exit(0); }
}

/* -------------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
	fd_set sockfd_set;
	int r = 0;
	int i;

	parse_opts(argc, argv);

	if (!rules_file) {
		show_help(argv[0]);
		log_message(LOG_ERR, "error: rules file required (-r)");
		exit(2);
	}

	if (load_rules(rules_file) < 0 || num_rules == 0) {
		log_message(LOG_ERR, "failed to load rules from %s", rules_file);
		r = 1;
		goto end_main;
	}

	if (service_filter_file) {
		if (load_service_filter(service_filter_file) < 0) { r = 1; goto end_main; }
		log_message(LOG_INFO, "service filter: %d entries", num_filter_services);
	}

	if (debug_log_file) {
		mkdir("/var/log/mdns-repeater", 0755);
		debug_log_fp = fopen(debug_log_file, "a");
		if (!debug_log_fp)
			log_message(LOG_ERR, "cannot open debug log %s: %s", debug_log_file, strerror(errno));
	}

	openlog(PACKAGE, LOG_PID | LOG_CONS, LOG_DAEMON);

	server_sockfd = create_recv_sock();
	if (server_sockfd < 0) {
		log_message(LOG_ERR, "unable to create server socket");
		r = 1; goto end_main;
	}

	if (setup_sockets(server_sockfd) < 0) {
		r = 1; goto end_main;
	}

	if (num_socks < 2) {
		log_message(LOG_ERR, "need at least 2 interfaces (got %d)", num_socks);
		r = 1; goto end_main;
	}

	if (user) switch_user();

	if (!foreground)
		daemonize();

	pkt_data = malloc(PACKET_SIZE);
	if (pkt_data == NULL) {
		log_message(LOG_ERR, "cannot malloc() packet buffer: %s", strerror(errno));
		r = 1; goto end_main;
	}

	while (!shutdown_flag) {
		struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };

		FD_ZERO(&sockfd_set);
		FD_SET(server_sockfd, &sockfd_set);
		int numfd = select(server_sockfd + 1, &sockfd_set, NULL, NULL, &tv);
		if (numfd <= 0) continue;

		if (FD_ISSET(server_sockfd, &sockfd_set)) {
			struct sockaddr_in fromaddr;
			socklen_t sockaddr_size = sizeof(struct sockaddr_in);

			ssize_t recvsize = recvfrom(server_sockfd, pkt_data, PACKET_SIZE, 0,
				(struct sockaddr *) &fromaddr, &sockaddr_size);
			if (recvsize < 0) {
				log_message(LOG_ERR, "recv(): %s", strerror(errno));
				continue;
			}

			/* Identify source socket */
			int j;
			char discard = 0;
			char our_net = 0;
			int src_sock = -1;
			for (j = 0; j < num_socks; j++) {
				if ((fromaddr.sin_addr.s_addr & socks[j].mask.s_addr) == socks[j].net.s_addr) {
					our_net = 1;
					src_sock = j;
				}
				if (fromaddr.sin_addr.s_addr == socks[j].addr.s_addr) {
					discard = 1;
					break;
				}
			}

			if (discard || !our_net || src_sock < 0) continue;

			/* Whitelist / blacklist */
			if (num_whitelisted_subnets != 0) {
				char ok = 0;
				for (j = 0; j < num_whitelisted_subnets; j++) {
					if ((fromaddr.sin_addr.s_addr & whitelisted_subnets[j].mask.s_addr)
					    == whitelisted_subnets[j].net.s_addr) { ok = 1; break; }
				}
				if (!ok) {
					if (foreground)
						printf("skipping packet from=%s (not whitelisted)\n", inet_ntoa(fromaddr.sin_addr));
					continue;
				}
			} else if (num_blacklisted_subnets != 0) {
				char blocked = 0;
				for (j = 0; j < num_blacklisted_subnets; j++) {
					if ((fromaddr.sin_addr.s_addr & blacklisted_subnets[j].mask.s_addr)
					    == blacklisted_subnets[j].net.s_addr) { blocked = 1; break; }
				}
				if (blocked) {
					if (foreground)
						printf("skipping packet from=%s (blacklisted)\n", inet_ntoa(fromaddr.sin_addr));
					continue;
				}
			}

			char src_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &fromaddr.sin_addr, src_ip, sizeof(src_ip));

			/* Drop announcements (QR=1) originating from Q interface */
			if (socks[src_sock].query_only && recvsize >= 3) {
				unsigned char *dns = (unsigned char *)pkt_data;
				if (dns[2] & 0x80) {
					if (foreground)
						printf("suppressing announcement from Q iface %s (from=%s)\n",
							socks[src_sock].ifname, inet_ntoa(fromaddr.sin_addr));
					log_packet_names(src_ip, (unsigned char *)pkt_data, (size_t)recvsize, "SKIP:Q");
					continue;
				}
			}

			if (foreground)
				printf("data from=%s size=%zd\n", inet_ntoa(fromaddr.sin_addr), recvsize);

			/* Service filter — fail fast before computing destinations */
			if (!packet_matches_filter((unsigned char *)pkt_data, (size_t)recvsize)) {
				if (foreground)
					printf("filtered packet from=%s\n", inet_ntoa(fromaddr.sin_addr));
				log_packet_names(src_ip, (unsigned char *)pkt_data, (size_t)recvsize, "SKIP:service");
				continue;
			}

			/* Compute actual destination list (routing table + Q-only + same-net) */
			int actual_dests[MAX_SOCKS];
			int num_actual_dests = 0;
			char dest_buf[256] = "->";
			size_t dest_len = 2;
			for (j = 0; j < routing[src_sock].num_dests; j++) {
				int dest = routing[src_sock].dests[j];
				if ((fromaddr.sin_addr.s_addr & socks[dest].mask.s_addr) == socks[dest].net.s_addr)
					continue;
				if (!socks[src_sock].query_only && socks[dest].query_only && recvsize >= 3) {
					unsigned char *dns = (unsigned char *)pkt_data;
					if (!(dns[2] & 0x80)) continue;
				}
				actual_dests[num_actual_dests++] = dest;
				dest_len += snprintf(dest_buf + dest_len, sizeof(dest_buf) - dest_len,
					" %s", socks[dest].subnet_str);
			}

			/* Log and forward */
			if (num_actual_dests > 0)
				log_packet_names(src_ip, (unsigned char *)pkt_data, (size_t)recvsize, dest_buf);

			for (j = 0; j < num_actual_dests; j++) {
				int dest = actual_dests[j];
				if (foreground)
					printf("repeating data to %s\n", socks[dest].ifname);
				ssize_t sentsize = send_packet(socks[dest].sockfd, pkt_data, (size_t)recvsize);
				if (sentsize != recvsize) {
					if (sentsize < 0)
						log_message(LOG_ERR, "send(): %s", strerror(errno));
					else
						log_message(LOG_ERR, "send_packet size differs: sent=%zd actual=%zd",
							recvsize, sentsize);
				}
			}
		}
	}

	log_message(LOG_INFO, "shutting down...");

end_main:
	if (pkt_data != NULL) free(pkt_data);
	if (debug_log_fp != NULL) fclose(debug_log_fp);

	if (filter_services != NULL) {
		for (i = 0; i < num_filter_services; i++) free(filter_services[i]);
		free(filter_services);
	}
	if (filter_service_lens != NULL) free(filter_service_lens);

	if (server_sockfd >= 0) close(server_sockfd);

	for (i = 0; i < num_socks; i++) {
		close(socks[i].sockfd);
		free((char *)socks[i].ifname);
	}

	if (already_running() == getpid())
		unlink(pid_file);

	log_message(LOG_INFO, "exit.");
	return r;
}

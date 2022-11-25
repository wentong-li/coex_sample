/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief WiFi station sample
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(sta, CONFIG_LOG_DEFAULT_LEVEL);

#include <nrfx_clock.h>
#include <zephyr/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/printk.h>
#include <zephyr/init.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/socket.h>
#include <zephyr/shell/shell_uart.h>
#include <zephyr/bluetooth/conn.h>
#include "zperf.h"
#define CONFIG_NET_ZPERF_MAX_PACKET_SIZE 1024
#include "zperf_internal.h"
#include "zperf_session.h"
#include "shell_utils.h"
#include "net_private.h"
#include "bt_main.h"

#define INTERVAL_MIN 0x140 /* 320 units, 400 ms */
#define INTERVAL_MAX 0x140 /* 320 units, 400 ms */
#define CONN_LATENCY 0

#define MIN_CONN_INTERVAL   6
#define MAX_CONN_INTERVAL   3200
#define SUPERVISION_TIMEOUT 1000


#define WIFI_SHELL_MODULE "wifi"

#define WIFI_SHELL_MGMT_EVENTS (NET_EVENT_WIFI_CONNECT_RESULT |		\
				NET_EVENT_WIFI_DISCONNECT_RESULT)

#define MAX_SSID_LEN        32
#define WIFI_CONNECTION_TIMEOUT 30

static struct sockaddr_in in4_addr_my = {
	.sin_family = AF_INET,
	.sin_port = htons(CONFIG_NET_CONFIG_PEER_IPV4_PORT),
};

static struct net_mgmt_event_callback wifi_sta_mgmt_cb;
static struct net_mgmt_event_callback net_addr_mgmt_cb;

static struct {
	union {
		struct {
			uint8_t disconnecting	: 1;
			uint8_t _unused		: 6;
		};
		uint8_t all;
	};
} context;


K_SEM_DEFINE(wait_for_next, 0, 1);
struct wifi_benchmark_config
{
	bool is_server;
	bool is_udp;
	int port;
	unsigned int duration_in_ms;
	unsigned int packet_size;
	unsigned int rate_in_kbps;
};

// TODO: Use Kconfig
static const struct wifi_benchmark_config default_config = {
	.is_server = false,
	.is_udp = true,
	.port = 5001,
	.duration_in_ms = 10000,
	.packet_size = 1024,
	.rate_in_kbps = 10000,
};

static void run_wifi_benchmark(void);

K_THREAD_DEFINE(run_wifi_traffic,
		CONFIG_WIFI_THREAD_STACK_SIZE,
		run_wifi_benchmark,
		NULL,
		NULL,
		NULL,
		CONFIG_WIFI_THREAD_PRIORITY,
		0,
		K_TICKS_FOREVER); /* K_FOREVER gives compilation warning k_timeout->int */

static void run_bt_benchmark(void);

K_THREAD_DEFINE(run_bt_traffic,
		CONFIG_WIFI_THREAD_STACK_SIZE,
		run_bt_benchmark,
		NULL,
		NULL,
		NULL,
		CONFIG_WIFI_THREAD_PRIORITY,
		0,
		K_TICKS_FOREVER); /* K_FOREVER gives compilation warning k_timeout->int */

static int cmd_wifi_status(void)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_iface_status status = { 0 };

	if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
				sizeof(struct wifi_iface_status))) {
		printk("Status request failed\n");

		return -ENOEXEC;
	}

	printk("Status: successful\n");
	printk("==================\n");
	printk("State: %s\n", wifi_state_txt(status.state));

	if (status.state >= WIFI_STATE_ASSOCIATED) {
		uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];

		printk("Interface Mode: %s\n",
		       wifi_mode_txt(status.iface_mode));
		printk("Link Mode: %s\n",
		       wifi_link_mode_txt(status.link_mode));
		printk("SSID: %-32s\n", status.ssid);
		printk("BSSID: %s\n",
		       net_sprint_ll_addr_buf(
				status.bssid, WIFI_MAC_ADDR_LEN,
				mac_string_buf, sizeof(mac_string_buf)));
		printk("Band: %s\n", wifi_band_txt(status.band));
		printk("Channel: %d\n", status.channel);
		printk("Security: %s\n", wifi_security_txt(status.security));
		printk("MFP: %s\n", wifi_mfp_txt(status.mfp));
		printk("RSSI: %d\n", status.rssi);
	}

	return 0;
}

static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *) cb->info;

	if (status->status) {
		LOG_ERR("Connection request failed (%d)", status->status);
	} else {
		LOG_INF("Connected");
	}

	cmd_wifi_status();
	k_sem_give(&wait_for_next);
}

static void handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *) cb->info;

	if (context.disconnecting) {
		LOG_INF("Disconnection request %s (%d)",
			 status->status ? "failed" : "done",
					status->status);
		context.disconnecting = false;
	} else {
		LOG_INF("Disconnected");
	}

	cmd_wifi_status();
}

static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				     uint32_t mgmt_event, struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT:
		handle_wifi_connect_result(cb);
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		handle_wifi_disconnect_result(cb);
		break;
	default:
		break;
	}
}

static void print_dhcp_ip(struct net_mgmt_event_callback *cb)
{
	/* Get DHCP info from struct net_if_dhcpv4 and print */
	const struct net_if_dhcpv4 *dhcpv4 = cb->info;
	const struct in_addr *addr = &dhcpv4->requested_ip;
	char dhcp_info[128];

	net_addr_ntop(AF_INET, addr, dhcp_info, sizeof(dhcp_info));

	LOG_INF("IP address: %s", dhcp_info);
	k_sem_give(&wait_for_next);
}

static void net_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				    uint32_t mgmt_event, struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_IPV4_DHCP_BOUND:
		print_dhcp_ip(cb);
		break;
	default:
		break;
	}
}

static int __wifi_args_to_params(struct wifi_connect_req_params *params)
{
	params->timeout = SYS_FOREVER_MS;

	/* SSID */
	params->ssid = CONFIG_STA_SAMPLE_SSID;
	params->ssid_length = strlen(params->ssid);

#if defined(CONFIG_STA_KEY_MGMT_WPA2)
	params->security = 1;
#elif defined(CONFIG_STA_KEY_MGMT_WPA2_256)
	params->security = 2;
#elif defined(CONFIG_STA_KEY_MGMT_WPA3)
	params->security = 3;
#else
	params->security = 0;
#endif

#if !defined(CONFIG_STA_KEY_MGMT_NONE)
	params->psk = CONFIG_STA_SAMPLE_PASSWORD;
	params->psk_length = strlen(params->psk);
#endif
	params->channel = WIFI_CHANNEL_ANY;

	/* MFP (optional) */
	params->mfp = WIFI_MFP_OPTIONAL;

	return 0;
}

static int wifi_connect(void)
{
	struct net_if *iface = net_if_get_default();
	static struct wifi_connect_req_params cnx_params;

	__wifi_args_to_params(&cnx_params);

	if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface,
		     &cnx_params, sizeof(struct wifi_connect_req_params))) {
		LOG_ERR("Connection request failed");

		return -ENOEXEC;
	}

	LOG_INF("Connection requested");

	return 0;
}

static int wifi_disconnect(void)
{
	struct net_if *iface = net_if_get_default();
	int status;

	context.disconnecting = true;

	status = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);

	if (status) {
		context.disconnecting = false;

		if (status == -EALREADY) {
			LOG_INF("Already disconnected");
		} else {
			LOG_ERR("Disconnect request failed");
			return -ENOEXEC;
		}
	} else {
		LOG_INF("Disconnect requested");
	}

	return 0;
}

static int parse_ipv4_addr(char *host,
			   struct sockaddr_in *addr)
{
	int ret;

	if (!host) {
		return -EINVAL;
	}

	ret = net_addr_pton(AF_INET, host, &addr->sin_addr);
	if (ret < 0) {
		LOG_ERR( "Invalid IPv4 address %s\n", host);
		return -EINVAL;
	}

	LOG_INF("IPv4 address %s", host);

	return 0;
}

static void run_wifi_benchmark_client(bool is_udp, int port, unsigned int duration_in_ms,
		unsigned int packet_size, unsigned int rate_in_kbps)
{
	int ret = 0;
	struct zperf_results results = { };
	unsigned int client_rate_in_kbps;
	int sock4;
	int tos = 0;

	const struct shell *const sh = shell_backend_uart_get_ptr();

	sock4 = zsock_socket(AF_INET,
					is_udp ? SOCK_DGRAM : SOCK_STREAM,
					is_udp ? IPPROTO_UDP : IPPROTO_TCP);
	if (sock4 < 0) {
		LOG_ERR("Cannot create IPv4 network socket (%d)\n", errno);
		return;
	}

	if (tos >= 0) {
		if (zsock_setsockopt(sock4, IPPROTO_IP, IP_TOS,
						&tos, sizeof(tos)) != 0) {
			LOG_ERR("Failed to set IP_TOS socket option. "
				"Please enable CONFIG_NET_CONTEXT_DSCP_ECN.\n");
		}
	}

	parse_ipv4_addr(CONFIG_NET_CONFIG_PEER_IPV4_ADDR,
			&in4_addr_my);

	ret = zsock_connect(sock4,
				(struct sockaddr *)&in4_addr_my,
				sizeof(in4_addr_my));
	if (ret < 0) {
		LOG_ERR("IPv4 connect failed (%d)\n", errno);
		return;
	}

	zperf_udp_upload(sh, sock4, port, duration_in_ms,
				packet_size, rate_in_kbps, &results);

	LOG_INF("Wi-Fi benchmark: Upload completed!\n");

	if (results.client_time_in_us != 0U) {
		client_rate_in_kbps = (uint32_t)
			(((uint64_t)results.nb_packets_sent *
				(uint64_t)results.packet_size * (uint64_t)8 *
				(uint64_t)USEC_PER_SEC) /
				((uint64_t)results.client_time_in_us * 1024U));
	} else {
		client_rate_in_kbps = 0U;
	}
	// print results
	LOG_INF("Upload results:\n");
	LOG_INF("  %u bytes in %u ms\n",
		results.nb_packets_sent * results.packet_size,
		results.client_time_in_us / USEC_PER_MSEC);
	LOG_INF("  %u packets sent\n", results.nb_packets_sent);
	LOG_INF("  %u packets lost\n", results.nb_packets_lost);
	LOG_INF("  %u packets received\n", results.nb_packets_rcvd);

	printk("Rate:\t\t\t");
	print_number(sh, rate_in_kbps, KBPS, KBPS_UNIT);
	printk("\t(");
	print_number(sh, client_rate_in_kbps, KBPS, KBPS_UNIT);
	printk(")\n");
}

static void run_wifi_benchmark(void)
{

	zperf_session_init();

	LOG_INF("Starting Wi-Fi benchmark: Zperf %s", default_config.is_server ? "server" : "client");

	if (!default_config.is_server)
	{
		run_wifi_benchmark_client(default_config.is_udp, default_config.port, default_config.duration_in_ms,
				default_config.packet_size, default_config.rate_in_kbps);
	}
	// TODO: Add server, TCP client and server if needed.
}

int wait_for_next_event(const char *event_name, int timeout)
{
	int wait_result;

	if (event_name) {
		LOG_INF("Waiting for %s", event_name);
	}

	wait_result = k_sem_take(&wait_for_next, K_SECONDS(timeout));
	if (wait_result) {
		LOG_ERR("Timeout waiting for %s -> %d", event_name, wait_result);
		return -1;
	}

	LOG_INF("Got %s", event_name);
	k_sem_reset(&wait_for_next);

	return 0;
}

static void run_bt_benchmark(void)
{
	test_run();
}

void main(void)
{
	context.all = 0U;

	net_mgmt_init_event_callback(&wifi_sta_mgmt_cb,
				     wifi_mgmt_event_handler,
				     WIFI_SHELL_MGMT_EVENTS);

	net_mgmt_add_event_callback(&wifi_sta_mgmt_cb);


	net_mgmt_init_event_callback(&net_addr_mgmt_cb,
				     net_mgmt_event_handler,
				     NET_EVENT_IPV4_DHCP_BOUND);

	net_mgmt_add_event_callback(&net_addr_mgmt_cb);

#ifdef CLOCK_FEATURE_HFCLK_DIVIDE_PRESENT
	/* For now hardcode to 128MHz */
	nrfx_clock_divider_set(NRF_CLOCK_DOMAIN_HFCLK,
			       NRF_CLOCK_HFCLK_DIV_1);
#endif
	LOG_INF("Starting %s with CPU frequency: %d MHz", CONFIG_BOARD, SystemCoreClock/MHZ(1));
	k_sleep(K_SECONDS(1));

	/* Wi-Fi connection */
	wifi_connect();

	if (wait_for_next_event("Wi-Fi Connection", WIFI_CONNECTION_TIMEOUT)) {
		return;
	}

	if (wait_for_next_event("Wi-Fi DHCP", 10)) {
		return;
	}

	/* TODO: BLE connection */
	bt_main();
	/* Set role based on Kconfig option */

	select_role(CONFIG_COEX_BT_CENTRAL == 1 ? true : false);
	/* Sleep 3 seconds to allow the BT get connected */
	k_sleep(K_SECONDS(5));
	connection_configuration_set(BT_LE_CONN_PARAM(INTERVAL_MIN, INTERVAL_MAX, CONN_LATENCY,
				       SUPERVISION_TIMEOUT),
			BT_CONN_LE_PHY_PARAM_2M,
			BT_LE_DATA_LEN_PARAM_MAX);
	k_sleep(K_SECONDS(5));
	printk("Timeout for BT config.\n");


	/* Start Wi-Fi traffic */
	k_thread_start(run_wifi_traffic);
	/* TODO - Run BLE traffic */
	/*
	 * Start the throughput sample by calling shell command.
	 * In case it is peripheral, skip this call.
	 */
	if (CONFIG_COEX_BT_CENTRAL)
	{
		k_thread_start(run_bt_traffic);
	}


	k_thread_join(run_wifi_traffic, K_FOREVER);
	k_thread_join(run_bt_traffic, K_FOREVER);

	/* TODO - Enable SR Coex using net_mgmt API (TBD by BLE Team)*

	/* Start Wi-Fi traffic */
	// k_thread_start(run_wifi_traffic);
	/* TODO - Run BLE traffic */
	// k_thread_join(run_wifi_traffic, K_FOREVER);

	/* Wi-Fi disconnection */
	wifi_disconnect();
	/* TODO: BLE disconnection */
}

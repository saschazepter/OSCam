#ifndef MODULE_STREAMRELAY_H_
#define MODULE_STREAMRELAY_H_

#ifdef MODULE_STREAMRELAY

#define STREAM_SERVER_MAX_CONNECTIONS 16

#define DVB_MAX_TS_PACKETS 278
#define DVB_BUFFER_SIZE_CSA 188*DVB_MAX_TS_PACKETS
#define DVB_BUFFER_WAIT_CSA 188*(DVB_MAX_TS_PACKETS-128)
#define DVB_BUFFER_SIZE DVB_BUFFER_SIZE_CSA

#include "cscrypt/md5.h"
#include <dvbcsa/dvbcsa.h>
#if DVBCSA_KEY_ECM
#define DVBCSA_HEADER_ECM 1
#define dvbcsa_bs_key_set(a,b) dvbcsa_bs_key_set_ecm(ecm,a,b)
#else
#define DVBCSA_HEADER_ECM 0
#endif
#ifndef STATIC_LIBDVBCSA
#define STATIC_LIBDVBCSA 0
#endif

#define EVEN 0
#define ODD 1

#define SR_MAX_PES_PIDS 8

// Packets of the new parity in a row that say a period really changed; the
// stragglers of the one being left arrive singly between them.
#define SR_PERIOD_MIN_PACKETS 8

// Two registers per parity, picked by the packet's own parity bit, as a receiver
// without a delay has them. The waiting one exists only because the delayed
// output may still be inside the period whose word is being replaced.
typedef struct
{
	struct dvbcsa_bs_key_s *key[2];      // what the packets of this parity are opened with
	struct dvbcsa_bs_key_s *waiting[2];  // the next word, until the packets ask for it
	uint8_t cw[2][8];                    // the word in the register, to recognise a repeat
	uint8_t cw_waiting[2][8];
	uint8_t mode[2];                     // table it was derived with, part of its identity
	uint8_t mode_waiting[2];
	bool has_waiting[2];
	bool have_key[2];                    // a control word arrived for this parity
	struct timeb start[2];               // when the period now playing began
	int32_t late_ms[2];                  // how long that period went without a word that opens it
	bool run_dead[2];                    // the register does not open this period
	bool probe_armed[2];                 // the register still has to prove itself
	bool probe_retry[2];                 // one failure is not enough to call it dead
	uint8_t cw_judged[2][8];             // the word the last period of this parity was judged with
	bool reported[2];                    // the word in the register has had its say already
	bool miss_pending[2];                // it ran without a word, to be said in the gap where it belongs
	int8_t parity;                       // parity of the period now playing, -1 = none yet
	int8_t turning;                      // parity the packets may be turning to
	uint16_t turn_count;                 // how many of them in a row have said so
} stream_client_key_data;

typedef struct
{
	int32_t connid;
	int8_t have_cat_data;
	int8_t have_pat_data;
	int8_t have_pmt_data;
	int8_t have_ecm_data;
	int8_t have_emm_data;
	uint16_t blocked_caid;
	uint8_t cat_data[1024+208];
	uint8_t pat_data[1024+208];
	uint8_t pmt_data[1024+208];
	uint8_t ecm_data[1024+208];
	uint8_t emm_data[1024+208];
	uint16_t cat_data_pos;
	uint16_t pat_data_pos;
	uint16_t pmt_data_pos;
	uint16_t ecm_data_pos;
	uint16_t emm_data_pos;
	uint16_t srvid;
	uint16_t caid;
	uint16_t tsid;
	uint16_t onid;
	uint32_t ens;
	uint16_t pmt_pid;
	uint16_t ecm_pid;
	uint16_t emm_pid;
	uint16_t pcr_pid;
	uint16_t pes_pid[SR_MAX_PES_PIDS]; // video and audio, what the probe may judge
	uint8_t pes_pids;
	uint8_t ecm_md5[MD5_DIGEST_LENGTH];
} stream_client_data;

void init_stream_server(void);
void stop_stream_server(void);

bool stream_write_cw(ECM_REQUEST *er);

#endif // MODULE_STREAMRELAY

#endif // MODULE_STREAMRELAY_H_

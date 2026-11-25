#ifndef MODULE_STREAMRELAY_DELAY_H_
#define MODULE_STREAMRELAY_DELAY_H_

#ifdef MODULE_STREAMRELAY

// playback delay: 0 off, 1 self sizing, anything else fixed ms
#define SR_DELAY_MAX_MS          5000

#define SR_DELAY_AUTO_START_MS   100

// least added on top of a late key, a fifth of the lateness where that is more
#define SR_DELAY_AUTO_MARGIN_MS  100

// 320 chunks of DVB_BUFFER_SIZE hold 5000 ms of a 26 Mbit/s stream.
#define SR_DELAY_MAX_CHUNKS      320

typedef struct
{
	uint8_t *buf;
	uint32_t len;
	int32_t shift_ms;   // the delay this chunk was held by
	int64_t due;        // monotonic milliseconds, not the wall clock
} sr_delay_chunk;

typedef struct
{
	sr_delay_chunk chunk[SR_DELAY_MAX_CHUNKS];
	uint32_t first;     // oldest chunk in use
	uint32_t count;     // chunks in use
	int32_t delay_ms;   // the delay in force, 0 while the delay line is off
	int32_t stamped_ms; // the shift the stream's clock has been moved by
	int32_t connid;
	bool automatic;
	bool throttled;     // source throttling already reported
} sr_delay_buffer;

// Stuffing for the turns a raise hands out nothing: a reader given nothing at
// all runs into its own end of stream wait, on top of the gap.
#define SR_FILLER_PACKETS 7

const uint8_t *sr_delay_filler(uint32_t *len);

void sr_delay_init(sr_delay_buffer *db, int32_t connid);
void sr_delay_describe(char *buf, size_t len);
void sr_delay_free(sr_delay_buffer *db);
bool sr_delay_active(const sr_delay_buffer *db);
bool sr_delay_push(sr_delay_buffer *db, const uint8_t *buf, uint32_t len);
uint8_t *sr_delay_due(sr_delay_buffer *db, uint32_t *len);
uint8_t *sr_delay_queued(const sr_delay_buffer *db, uint32_t nth, uint32_t *len);
void sr_delay_release(sr_delay_buffer *db);
int32_t sr_delay_grow(sr_delay_buffer *db, int32_t late_ms);
void sr_delay_restamp(sr_delay_buffer *db, uint8_t *buf, uint32_t len, uint16_t packetSize);

#endif // MODULE_STREAMRELAY

#endif // MODULE_STREAMRELAY_DELAY_H_

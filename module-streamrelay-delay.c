#define MODULE_LOG_PREFIX "relay"

#include "globals.h"

#ifdef MODULE_STREAMRELAY

#include "module-streamrelay.h"
#include "module-streamrelay-delay.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include <time.h>

// holds the stream back before descrambling, so a late control word is in time

// monotonic, a corrected wall clock would shift due times
static int64_t sr_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

const uint8_t *sr_delay_filler(uint32_t *len)
{
	static uint8_t filler[SR_FILLER_PACKETS * 188];
	static bool built = false;

	if (!built)
	{
		uint32_t n;

		memset(filler, 0xFF, sizeof(filler));

		for (n = 0; n < SR_FILLER_PACKETS; n++)
		{
			uint8_t *p = filler + n * 188;

			p[0] = 0x47;
			p[1] = 0x1F; // null pid
			p[2] = 0xFF;
			p[3] = 0x10; // payload only, no continuity of its own to keep
		}
		built = true;
	}

	*len = sizeof(filler);

	return filler;
}

void sr_delay_free(sr_delay_buffer *db)
{
	uint32_t i;

	for (i = 0; i < SR_DELAY_MAX_CHUNKS; i++)
		{ NULLFREE(db->chunk[i].buf); }

	memset(db, 0, sizeof(sr_delay_buffer));
}

void sr_delay_init(sr_delay_buffer *db, int32_t connid)
{
	uint32_t want = cfg.stream_relay_playback_delay;

	sr_delay_free(db);
	db->connid = connid;

	if (want == 0)
		{ return; }

	if (want == 1)
	{
		db->automatic = true;
		db->delay_ms = SR_DELAY_AUTO_START_MS;
	}
	else if (want > SR_DELAY_MAX_MS)
	{
		cs_log("WARNING: stream client %i playback delay of %u ms is above the maximum of %d ms",
				connid, want, SR_DELAY_MAX_MS);
		db->delay_ms = SR_DELAY_MAX_MS;
	}
	else
	{
		db->delay_ms = (int32_t)want;
	}
}

// what the connect line says about the delay, which is written before the line
// is set up; the size comes from the configuration either way
void sr_delay_describe(char *buf, size_t len)
{
	uint32_t want = cfg.stream_relay_playback_delay;

	if (want == 0)
		{ buf[0] = '\0'; }
	else if (want == 1)
		{ snprintf(buf, len, " delay=%d ms (automatic)", SR_DELAY_AUTO_START_MS); }
	else
	{
		snprintf(buf, len, " delay=%u ms (fixed)",
				want > SR_DELAY_MAX_MS ? (uint32_t)SR_DELAY_MAX_MS : want);
	}
}

bool sr_delay_active(const sr_delay_buffer *db)
{
	return db->delay_ms > 0;
}

bool sr_delay_push(sr_delay_buffer *db, const uint8_t *buf, uint32_t len)
{
	sr_delay_chunk *chunk;

	if (len == 0)
		{ return true; }

	chunk = db->count < SR_DELAY_MAX_CHUNKS
			? &db->chunk[(db->first + db->count) % SR_DELAY_MAX_CHUNKS]
			: NULL;

	if (chunk != NULL && chunk->buf == NULL && !cs_malloc(&chunk->buf, DVB_BUFFER_SIZE))
		{ chunk = NULL; }

	if (chunk == NULL && db->count == 0)
	{
		// nothing queued to wait for, give the delay up rather than spin
		cs_log("ERROR: stream client %i cannot grow the delay line, playback delay switched off", db->connid);
		db->delay_ms = 0;
		return false;
	}

	if (chunk == NULL)
	{
		// full, wait for the oldest so TCP paces the source
		int64_t wait = db->chunk[db->first].due - sr_now_ms();

		if (wait > 0)
			{ cs_sleepms((uint32_t)wait); }

		if (!db->throttled)
		{
			cs_log("Stream client %i delay line holds its %d ms in %u chunks, throttling the source",
					db->connid, db->delay_ms, db->count);
			db->throttled = true;
		}
		return false;
	}

	if (len > DVB_BUFFER_SIZE)
		{ len = DVB_BUFFER_SIZE; }

	memcpy(chunk->buf, buf, len);
	chunk->len = len;
	chunk->shift_ms = db->delay_ms;
	chunk->due = sr_now_ms() + db->delay_ms;
	db->count++;

	return true;
}

uint8_t *sr_delay_due(sr_delay_buffer *db, uint32_t *len)
{
	if (db->count == 0)
		{ return NULL; }

	if (db->chunk[db->first].due > sr_now_ms())
		{ return NULL; }

	*len = db->chunk[db->first].len;

	return db->chunk[db->first].buf;
}

// any queued chunk, so a verdict can be drawn from data the head is holding up
uint8_t *sr_delay_queued(const sr_delay_buffer *db, uint32_t nth, uint32_t *len)
{
	const sr_delay_chunk *chunk;

	if (nth >= db->count)
		{ return NULL; }

	chunk = &db->chunk[(db->first + nth) % SR_DELAY_MAX_CHUNKS];
	*len = chunk->len;

	return chunk->buf;
}

void sr_delay_release(sr_delay_buffer *db)
{
	sr_delay_chunk *done, *next;

	if (db->count == 0)
		{ return; }

	done = &db->chunk[db->first];
	db->first = (db->first + 1) % SR_DELAY_MAX_CHUNKS;
	db->count--;

	// the buffer follows the data, not the slot
	next = &db->chunk[(db->first + db->count) % SR_DELAY_MAX_CHUNKS];

	if (next == done)
		{ return; } // the line was full, so this slot is next in turn again

	if (next->buf == NULL)
	{
		next->buf = done->buf;
		done->buf = NULL;
	}
	else
	{
		NULLFREE(done->buf); // the line is carrying fewer chunks than it has buffers
	}
}

int32_t sr_delay_grow(sr_delay_buffer *db, int32_t late_ms)
{
	int32_t margin = late_ms / 5 > SR_DELAY_AUTO_MARGIN_MS ? late_ms / 5 : SR_DELAY_AUTO_MARGIN_MS;
	// what the delay fell short by, so it goes on top of what is covered already
	int32_t step = late_ms + margin;
	uint32_t i;

	if (!db->automatic || db->delay_ms >= SR_DELAY_MAX_MS)
		{ return 0; }

	if (db->delay_ms + step > SR_DELAY_MAX_MS)
		{ step = SR_DELAY_MAX_MS - db->delay_ms; }

	db->delay_ms += step;

	// queued chunks included, so one gap for the client instead of one per step
	for (i = 0; i < db->count; i++)
	{
		sr_delay_chunk *chunk = &db->chunk[(db->first + i) % SR_DELAY_MAX_CHUNKS];

		chunk->due += step;
		chunk->shift_ms += step;
	}

	return step;
}

// A 33 bit clock at 90 kHz, as PCR base, PTS and DTS all carry it.
#define SR_TS_CLOCK_MASK 0x1FFFFFFFFULL

static void sr_shift_pcr(uint8_t *p, int64_t ticks)
{
	uint64_t base = ((uint64_t)p[0] << 25) | ((uint64_t)p[1] << 17) | ((uint64_t)p[2] << 9)
					| ((uint64_t)p[3] << 1) | ((uint64_t)p[4] >> 7);
	uint32_t ext = (((uint32_t)p[4] & 0x01) << 8) | p[5];

	base = (base + (uint64_t)ticks) & SR_TS_CLOCK_MASK;

	p[0] = (uint8_t)(base >> 25);
	p[1] = (uint8_t)(base >> 17);
	p[2] = (uint8_t)(base >> 9);
	p[3] = (uint8_t)(base >> 1);
	p[4] = (uint8_t)(((base & 0x01) << 7) | 0x7E | (ext >> 8));
	p[5] = (uint8_t)ext;
}

static void sr_shift_pts(uint8_t *p, int64_t ticks)
{
	uint64_t v = (((uint64_t)p[0] & 0x0E) << 29) | ((uint64_t)p[1] << 22)
				| (((uint64_t)p[2] & 0xFE) << 14) | ((uint64_t)p[3] << 7) | ((uint64_t)p[4] >> 1);

	v = (v + (uint64_t)ticks) & SR_TS_CLOCK_MASK;

	p[0] = (uint8_t)((p[0] & 0xF0) | ((v >> 29) & 0x0E) | 0x01);
	p[1] = (uint8_t)(v >> 22);
	p[2] = (uint8_t)(((v >> 14) & 0xFE) | 0x01);
	p[3] = (uint8_t)(v >> 7);
	p[4] = (uint8_t)((v << 1) | 0x01);
}

void sr_delay_restamp(sr_delay_buffer *db, uint8_t *buf, uint32_t len, uint16_t packetSize)
{
	const int32_t shift = db->count ? db->chunk[db->first].shift_ms : db->delay_ms;
	const int64_t ticks = (int64_t)shift * 90;            // 90 kHz
	const bool moved = shift != db->stamped_ms;
	uint32_t i;
	bool marked = false;

	if (shift == 0)
		{ return; }

	for (i = 0; i + packetSize <= len; i += packetSize)
	{
		uint8_t *p = buf + i;
		uint8_t *pes;
		uint16_t offset = 4;

		if (p[0] != 0x47 || (p[3] & 0xC0) != 0)           // no packet, or still scrambled
			{ continue; }

		if (p[3] & 0x20)                                  // adaptation field
		{
			// A pcr is seven bytes, so a shorter field carries none.
			if (p[4] >= 7 && (uint16_t)(5 + p[4]) <= packetSize && (p[5] & 0x10))
			{
				sr_shift_pcr(p + 6, ticks);

				// tell the client to re-anchor
				if (moved && !marked)
				{
					p[5] |= 0x80;                         // discontinuity_indicator
					marked = true;
				}
			}
			offset = (uint16_t)(5 + p[4]);
		}

		if (!(p[3] & 0x10) || !(p[1] & 0x40))             // no payload, or no PES start
			{ continue; }

		if (offset + 14 > packetSize)                     // no room for a pts
			{ continue; }

		pes = p + offset;

		if (pes[0] != 0x00 || pes[1] != 0x00 || pes[2] != 0x01 || (pes[6] & 0xC0) != 0x80)
			{ continue; }

		// header has to hold what its flags announce
		if ((pes[7] & 0x80) && pes[8] >= 5)
			{ sr_shift_pts(pes + 9, ticks); }

		if ((pes[7] & 0x40) && pes[8] >= 10 && offset + 19 <= packetSize)
			{ sr_shift_pts(pes + 14, ticks); }
	}

	// no pcr in this chunk to mark the jump with, so the next one says it instead
	if (!moved || marked)
		{ db->stamped_ms = shift; }
}

#endif // MODULE_STREAMRELAY

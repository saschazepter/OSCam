/*
 * Self tests for the stream relay playback delay.
 *
 * Included at the end of module-streamrelay.c when BUILD_TESTS is set, so the
 * tests can reach the module's static key handling. This is not a translation
 * unit of its own and must not be added to the build.
 *
 * The packets are scrambled with libdvbcsa and checked for plaintext after the
 * relay descrambled them. That only comes out right if the key the packets
 * belong to was the one used, which is what these tests are about.
 */

#define SR_TEST_PACKETS  32
#define SR_TEST_BUF      (SR_TEST_PACKETS * 188)

/* Control words with the checksum bytes CSA expects, so they could be real. */
static const uint8_t sr_test_even1[8] = { 0x01, 0x02, 0x03, 0x06, 0x04, 0x05, 0x06, 0x0F };
static const uint8_t sr_test_even2[8] = { 0x11, 0x12, 0x13, 0x36, 0x14, 0x15, 0x16, 0x3F };
static const uint8_t sr_test_even3[8] = { 0x41, 0x42, 0x43, 0xC6, 0x44, 0x45, 0x46, 0xCF };
static const uint8_t sr_test_odd1[8]  = { 0x21, 0x22, 0x23, 0x66, 0x24, 0x25, 0x26, 0x6F };
static const uint8_t sr_test_odd2[8]  = { 0x31, 0x32, 0x33, 0x96, 0x34, 0x35, 0x36, 0x9F };

static int sr_test_failures;

struct sr_test_cw_job
{
	int32_t after_ms;
	int32_t connid;
	ECM_REQUEST er;
};

static void sr_test_check(bool ok, const char *what)
{
	printf("  %-64s %s\n", what, ok ? "ok" : "FAILED");

	if (!ok)
		{ sr_test_failures++; }
}

static void sr_test_fill(uint8_t *buf, uint8_t parity, uint8_t tag)
{
	uint32_t i, n;

	for (n = 0; n < SR_TEST_PACKETS; n++)
	{
		uint8_t *p = buf + n * 188;

		bool starts = n % 8 == 0;                               // a PES packet starts every eighth one

		p[0] = 0x47;
		p[1] = starts ? 0x41 : 0x01;                            // pid 0x0100
		p[2] = 0x00;
		p[3] = (parity == ODD ? 0xC0 : 0x80) | 0x10 | (n & 0x0F); // scrambled, payload only

		for (i = 4; i < 188; i++)
			{ p[i] = (uint8_t)(tag * 31 + i); }

		if (starts)
		{
			p[4] = 0x00;                                        // the PES start code the probe looks for
			p[5] = 0x00;
			p[6] = 0x01;
		}
	}
}

/* Nothing in line opens the period of this parity now playing. */
static bool sr_test_unopened(const stream_client_data *data, uint8_t parity)
{
	return key_data[data->connid].run_dead[parity];
}

/* Clears every payload unit start, so the buffer holds nothing judgable. */
static void sr_test_nostart(uint8_t *buf)
{
	uint32_t n;

	for (n = 0; n < SR_TEST_PACKETS; n++)
		{ buf[n * 188 + 1] &= (uint8_t)~0x40; }
}

/* How many packets still say they carry scrambled payload. */
static uint32_t sr_test_scrambled(const uint8_t *buf)
{
	uint32_t off, n = 0;

	for (off = 0; off < SR_TEST_BUF; off += 188)
	{
		if ((buf[off + 3] & 0xC0) != 0)
			{ n++; }
	}

	return n;
}

static bool sr_test_is_plain(const uint8_t *buf, uint8_t tag)
{
	uint32_t i, n;

	for (n = 0; n < SR_TEST_PACKETS; n++)
	{
		const uint8_t *p = buf + n * 188;

		for (i = n % 8 == 0 ? 7 : 4; i < 188; i++)  // a PES start code is not filler
		{
			if (p[i] != (uint8_t)(tag * 31 + i))
				{ return false; }
		}
	}

	return true;
}

static void sr_test_scramble(uint8_t *buf, const uint8_t *cw)
{
	struct dvbcsa_bs_batch_s batch[SR_TEST_PACKETS + 1];
	struct dvbcsa_bs_key_s *key = dvbcsa_bs_key_alloc();
	uint32_t n;
#if DVBCSA_KEY_ECM
	const uint8_t ecm = 0;                                      // the mode write_cw picks for a plain caid
#endif

	dvbcsa_bs_key_set(cw, key);

	for (n = 0; n < SR_TEST_PACKETS; n++)
	{
		batch[n].data = buf + n * 188 + 4;
		batch[n].len = 184;
	}
	batch[SR_TEST_PACKETS].data = NULL;

	dvbcsa_bs_encrypt(key, batch, 184);
	dvbcsa_bs_key_free(key);
}

static void sr_test_er(ECM_REQUEST *er, const uint8_t *even, const uint8_t *odd)
{
	memset(er, 0, sizeof(ECM_REQUEST));
	er->caid = 0x0100;
	er->srvid = 0x0001;
	er->rc = E_FOUND;

	if (even)
		{ memcpy(er->cw, even, 8); }

	if (odd)
		{ memcpy(er->cw + 8, odd, 8); }
}

static void *sr_test_late_cw(void *arg)
{
	struct sr_test_cw_job *job = (struct sr_test_cw_job *)arg;

	cs_sleepms(job->after_ms);
	write_cw(&job->er, job->connid);

	return NULL;
}

/* Relays one buffer of one parity and reports how long that took. */
static int64_t sr_test_period(stream_client_data *data, uint8_t *buf, struct dvbcsa_bs_batch_s *tsbbatch,
								uint8_t parity, uint8_t tag, const uint8_t *cw)
{
	struct timeb start, end;

	sr_test_fill(buf, parity, tag);
	sr_test_scramble(buf, cw);

	cs_ftime(&start);
	judge_ts_packets(data, buf, SR_TEST_BUF, 188);
	DescrambleTsPackets(data, buf, SR_TEST_BUF, 188, tsbbatch);
	cs_ftime(&end);

	return comp_timeb(&end, &start);
}

static void sr_test_put_pts(uint8_t *p, uint64_t v, uint8_t marker)
{
	p[0] = (uint8_t)((marker << 4) | ((v >> 29) & 0x0E) | 0x01);
	p[1] = (uint8_t)(v >> 22);
	p[2] = (uint8_t)(((v >> 14) & 0xFE) | 0x01);
	p[3] = (uint8_t)(v >> 7);
	p[4] = (uint8_t)((v << 1) | 0x01);
}

static uint64_t sr_test_get_pts(const uint8_t *p)
{
	return (((uint64_t)p[0] & 0x0E) << 29) | ((uint64_t)p[1] << 22)
			| (((uint64_t)p[2] & 0xFE) << 14) | ((uint64_t)p[3] << 7) | ((uint64_t)p[4] >> 1);
}

static void sr_test_put_pcr(uint8_t *p, uint64_t base)
{
	p[0] = (uint8_t)(base >> 25);
	p[1] = (uint8_t)(base >> 17);
	p[2] = (uint8_t)(base >> 9);
	p[3] = (uint8_t)(base >> 1);
	p[4] = (uint8_t)(((base & 1) << 7) | 0x7E);
	p[5] = 0;
}

static uint64_t sr_test_get_pcr(const uint8_t *p)
{
	return ((uint64_t)p[0] << 25) | ((uint64_t)p[1] << 17) | ((uint64_t)p[2] << 9)
			| ((uint64_t)p[3] << 1) | ((uint64_t)p[4] >> 7);
}

static int64_t sr_test_since(struct timeb *start)
{
	struct timeb now;

	cs_ftime(&now);

	return comp_timeb(&now, start);
}

// How many buffers the line is holding, whatever its slots are doing.
static uint32_t sr_test_buffers(const sr_delay_buffer *db)
{
	uint32_t i, n = 0;

	for (i = 0; i < SR_DELAY_MAX_CHUNKS; i++)
	{
		if (db->chunk[i].buf != NULL)
			{ n++; }
	}

	return n;
}

/*
 * The delay line on its own: when a chunk may leave, that growing also moves
 * what is already queued, and that a full line holds the source back instead
 * of dropping anything or giving the delay up.
 */
static void sr_test_delay_line(void)
{
	static sr_delay_buffer db;
	uint8_t chunk[188];
	struct timeb start;
	uint8_t *due, *pes;
	uint32_t len = 0, i;
	uint64_t before;
	int64_t took, fill_took;

	printf("\nTesting stream relay delay line\n");

	cfg.stream_relay_playback_delay = 0;
	sr_delay_init(&db, 0);
	sr_test_check(!sr_delay_active(&db) && !db.automatic, "a delay of zero relays without one");

	cfg.stream_relay_playback_delay = 200;
	sr_delay_init(&db, 0);
	sr_test_check(sr_delay_active(&db) && !db.automatic, "a fixed delay is active and does not size itself");

	memset(chunk, 0xA5, sizeof(chunk));
	chunk[0] = 0x47;
	sr_test_check(sr_delay_push(&db, chunk, sizeof(chunk)), "a chunk goes into the line");
	sr_test_check(sr_delay_due(&db, &len) == NULL, "and is not due at once");
	cs_sleepms(100);
	sr_test_check(sr_delay_due(&db, &len) == NULL, "nor halfway through the delay");
	cs_sleepms(140);
	due = sr_delay_due(&db, &len);
	sr_test_check(due != NULL && len == sizeof(chunk), "but after it, with its length");
	sr_test_check(due != NULL && due[0] == 0x47 && due[187] == 0xA5, "and with its content");
	sr_delay_release(&db);
	sr_test_check(sr_delay_due(&db, &len) == NULL, "the line is empty once the chunk is released");
	sr_delay_free(&db);

	cfg.stream_relay_playback_delay = SR_DELAY_MAX_MS + 1;
	sr_delay_init(&db, 0);
	sr_test_check(db.delay_ms == SR_DELAY_MAX_MS, "a delay above the maximum is capped");
	sr_delay_free(&db);

	cfg.stream_relay_playback_delay = 1;
	sr_delay_init(&db, 0);
	sr_test_check(db.delay_ms == SR_DELAY_AUTO_START_MS && db.automatic, "the automatic starts small");

	sr_delay_push(&db, chunk, sizeof(chunk));
	sr_test_check(db.chunk[db.first].shift_ms == SR_DELAY_AUTO_START_MS,
					"a queued chunk knows how far its clock is moved");
	sr_test_check(sr_delay_grow(&db, 300) == 400, "growing reports how far it moved the line");
	sr_test_check(db.delay_ms == 500, "a delay 300 ms short takes that and a margin on top");
	sr_test_check(db.chunk[db.first].shift_ms == 500,
					"and what is queued has its stamp raised with it");
	cs_sleepms(200);
	sr_test_check(sr_delay_due(&db, &len) == NULL, "what was already queued waits the longer time too");
	cs_sleepms(420);
	sr_test_check(sr_delay_due(&db, &len) != NULL, "and leaves at the new time");
	sr_delay_release(&db);

	// The figure is what the delay fell short by, not the whole wait, so it is
	// never a wait the line covers already.
	sr_test_check(sr_delay_grow(&db, 100) == 200, "a shortfall raises by itself and a margin");
	sr_test_check(db.delay_ms == 700, "taking the line past what fell short");

	sr_delay_grow(&db, 2000);
	sr_test_check(db.delay_ms == 700 + 2400, "a far later key is taken in one go, margin and all");

	sr_delay_grow(&db, 5000);
	sr_test_check(db.delay_ms == SR_DELAY_MAX_MS, "and the ceiling is as far as it goes");
	sr_test_check(sr_delay_grow(&db, 5000) == 0, "and grows no further");
	sr_test_check(db.delay_ms == SR_DELAY_MAX_MS, "staying at the maximum");
	sr_delay_free(&db);

	// A size that was asked for is the size that is kept: a late word is not
	// compensated for, it costs its period, and nothing moves the line.
	cfg.stream_relay_playback_delay = 2000;
	sr_delay_init(&db, 0);
	sr_test_check(db.delay_ms == 2000 && !db.automatic, "a fixed delay is the size it was given");
	sr_delay_push(&db, chunk, sizeof(chunk));
	sr_test_check(sr_delay_grow(&db, 3000) == 0, "a word 3000 ms late holds a fixed line back by nothing");
	sr_test_check(db.delay_ms == 2000, "and leaves it at the size it was given");
	sr_test_check(db.chunk[db.first].shift_ms == 2000, "what is queued keeps the clock it was stamped with");
	sr_delay_free(&db);

	// The stream's own clock moves with the delay, so what the client gets
	// does not claim to have been due a while ago.
	cfg.stream_relay_playback_delay = 500;
	sr_delay_init(&db, 0);

	memset(chunk, 0xFF, sizeof(chunk));
	chunk[0] = 0x47;
	chunk[1] = 0x41;                                  // payload starts here, pid 0x0100
	chunk[2] = 0x00;
	chunk[3] = 0x30;                                  // adaptation field and payload, clear
	chunk[4] = 7;                                     // adaptation field length
	chunk[5] = 0x10;                                  // carries a pcr
	sr_test_put_pcr(chunk + 6, 100000);
	pes = chunk + 12;
	pes[0] = 0x00; pes[1] = 0x00; pes[2] = 0x01; pes[3] = 0xE0;
	pes[4] = 0x00; pes[5] = 0x00; pes[6] = 0x80; pes[7] = 0xC0; pes[8] = 10;
	sr_test_put_pts(pes + 9, 200000, 3);
	sr_test_put_pts(pes + 14, 190000, 1);

	sr_delay_restamp(&db, chunk, sizeof(chunk), 188);
	sr_test_check(sr_test_get_pcr(chunk + 6) == 100000 + 500 * 90, "the pcr moves on by the delay");
	sr_test_check(sr_test_get_pts(pes + 9) == 200000 + 500 * 90, "and so does the pts");
	sr_test_check(sr_test_get_pts(pes + 14) == 190000 + 500 * 90, "and the dts");
	sr_test_check((chunk[5] & 0x80) != 0, "the first packet after a change says the clock jumped");

	chunk[5] &= (uint8_t)~0x80;
	sr_delay_restamp(&db, chunk, sizeof(chunk), 188);
	sr_test_check((chunk[5] & 0x80) == 0, "a later one does not, the clock is steady again");
	sr_test_check(sr_test_get_pcr(chunk + 6) == 100000 + 2 * 500 * 90, "while the shift keeps being applied");

	chunk[3] = 0x30 | 0x80;                           // still scrambled
	before = sr_test_get_pcr(chunk + 6);
	sr_delay_restamp(&db, chunk, sizeof(chunk), 188);
	sr_test_check(sr_test_get_pcr(chunk + 6) == before, "a packet that is still scrambled is left alone");
	sr_delay_free(&db);

	cfg.stream_relay_playback_delay = 200;
	sr_delay_init(&db, 0);

	cs_ftime(&start);

	for (i = 0; i < SR_DELAY_MAX_CHUNKS; i++)
	{
		chunk[0] = (uint8_t)i;

		if (!sr_delay_push(&db, chunk, sizeof(chunk)))
			{ break; }
	}
	fill_took = sr_test_since(&start);
	sr_test_check(i == SR_DELAY_MAX_CHUNKS && db.count == SR_DELAY_MAX_CHUNKS,
					"the line takes chunks up to its whole length");
	sr_test_check(sr_delay_due(&db, &len) == NULL, "none of them is due yet");

	chunk[0] = 0xFF;
	cs_ftime(&start);
	sr_test_check(!sr_delay_push(&db, chunk, sizeof(chunk)), "a full line refuses the next chunk");
	took = sr_test_since(&start);
	sr_test_check(took >= 50, "having held the source back until the oldest chunk was due");

	due = sr_delay_due(&db, &len);
	sr_test_check(due != NULL && due[0] == 0, "the oldest chunk is the one pushed first");
	sr_delay_release(&db);
	sr_test_check(sr_delay_push(&db, chunk, sizeof(chunk)), "and then there is room for the next");

	// Each chunk is held from its own arrival, so the last of the first round
	// comes due as long after the first as the filling took.
	cs_sleepms((uint32_t)fill_took + 20);

	for (i = 1; i < SR_DELAY_MAX_CHUNKS; i++)
	{
		due = sr_delay_due(&db, &len);

		if (due == NULL || due[0] != (uint8_t)i)
			{ break; }

		sr_delay_release(&db);
	}
	sr_test_check(i == SR_DELAY_MAX_CHUNKS, "the line drains in the order it was filled");

	cs_sleepms(260);
	due = sr_delay_due(&db, &len);
	sr_test_check(due != NULL && due[0] == 0xFF, "the chunk pushed after the wrap comes out last");
	sr_delay_release(&db);
	sr_test_check(db.count == 0, "and leaves the line empty");

	sr_delay_free(&db);
	sr_test_check(db.delay_ms == 0 && db.count == 0, "freeing the line clears it");

	// The memory follows the chunks in flight, not the length of the ring. A
	// line that keeps four chunks holds four buffers, however far it has turned.
	cfg.stream_relay_playback_delay = SR_DELAY_MAX_MS;
	sr_delay_init(&db, 0);

	for (i = 0; i < 4; i++)
		{ sr_delay_push(&db, chunk, sizeof(chunk)); }

	sr_test_check(sr_test_buffers(&db) == 4, "four chunks in the line, four buffers");

	for (i = 0; i < SR_DELAY_MAX_CHUNKS * 2; i++)
	{
		sr_delay_release(&db);
		sr_delay_push(&db, chunk, sizeof(chunk));
	}
	sr_test_check(db.count == 4, "still four chunks after two turns of the ring");
	sr_test_check(sr_test_buffers(&db) <= 5, "and still no more than four buffers, plus the one in hand");

	sr_delay_free(&db);
	sr_test_check(sr_test_buffers(&db) == 0, "freeing gives every buffer back");

	// Nothing but a raise moves the line. An overdue chunk leaves on the stamp it
	// was pushed with, so the clock the client reads never creeps on its own.
	cfg.stream_relay_playback_delay = 1;
	sr_delay_init(&db, 0);
	sr_delay_push(&db, chunk, sizeof(chunk));
	sr_delay_push(&db, chunk, sizeof(chunk));
	cs_sleepms(300);                                   // both are long overdue
	sr_test_check(db.delay_ms == SR_DELAY_AUTO_START_MS,
					"an overdue line is not what sizes it");
	sr_test_check(db.chunk[db.first].shift_ms == SR_DELAY_AUTO_START_MS,
					"and the head keeps the stamp it was pushed with");
	sr_delay_grow(&db, 300);
	sr_test_check(db.chunk[db.first].shift_ms == db.delay_ms,
					"only a raise moves it, and takes what waits along");
	sr_delay_free(&db);

	// A turn that ran long leaves more than one chunk due, and the caller has to
	// take them all: one per turn would never give the rest back, and the real lag
	// would run past what the stamps report.
	cfg.stream_relay_playback_delay = 200;
	sr_delay_init(&db, 0);
	{
		uint32_t turn, held;

		for (turn = 0; turn < 4; turn++)
			{ sr_delay_push(&db, chunk, sizeof(chunk)); }

		cs_sleepms(260);
		held = db.count;
		sr_test_check(sr_delay_due(&db, &len) != NULL, "a long turn leaves several due");
		sr_delay_release(&db);
		sr_test_check(db.count == held - 1, "taking one gives back only that one");

		while (sr_delay_due(&db, &len) != NULL)
			{ sr_delay_release(&db); }

		sr_test_check(db.count == 0, "taking everything due gives the whole line back");
	}
	sr_delay_free(&db);
}

int run_streamrelay_tests(void)
{
	struct dvbcsa_bs_batch_s *tsbbatch;
	struct sr_test_cw_job job;
	stream_client_data data;
	ECM_REQUEST er;
	int32_t grown;
	pthread_t tid;
	uint8_t *buf;
	int64_t took;

	const int32_t saved_delay = cfg.stream_relay_playback_delay;
	const uint32_t saved_cluster = cluster_size;
	const bool saved_ecm = has_dvbcsa_ecm;

	// cs_log() looks at cur_client(), and the tests run before main() sets the
	// thread key up.
	pthread_key_create(&getclient, NULL);

	sr_test_delay_line();

	printf("\nTesting stream relay key handling\n");

	has_dvbcsa_ecm = 1;
	cluster_size = dvbcsa_bs_batch_size();

	if (!cs_malloc(&tsbbatch, (cluster_size + 1) * sizeof(struct dvbcsa_bs_batch_s)))
		{ return 1; }

	if (!cs_malloc(&buf, SR_TEST_BUF))
	{
		NULLFREE(tsbbatch);
		return 1;
	}

	memset(&data, 0, sizeof(data));
	stream_add_pes_pid(&data, 0x0100);  // what the test data carries, so the probe judges it

	// A fresh connection: the first period of a parity begins before any control
	// word arrived, so the key has to be handed to that run when it comes in.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_period(&data, buf, tsbbatch, EVEN, 40, sr_test_even1);
	sr_test_check(!sr_test_is_plain(buf, 40), "with no key at all nothing descrambles yet");
	sr_test_check(!key_data[data.connid].have_key[EVEN],
					"because not one control word of that parity has arrived");

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_check(key_data[data.connid].have_key[EVEN] && !key_data[data.connid].has_waiting[EVEN],
					"so the first control word goes straight into the register");

	sr_test_period(&data, buf, tsbbatch, EVEN, 41, sr_test_even1);
	sr_test_check(sr_test_is_plain(buf, 41), "and the rest of that period descrambles");

	sr_test_period(&data, buf, tsbbatch, ODD, 42, sr_test_odd1);
	sr_test_check(sr_test_is_plain(buf, 42), "the odd side comes up with it");
	sr_test_check(delay_data[data.connid].delay_ms == SR_DELAY_AUTO_START_MS,
					"and none of it counts as a late key, there was nothing to be late for");

	free_key_data(data.connid);

	// A key that arrives while a crypto period is still being relayed must not
	// take the key that period needs away from it.
	cfg.stream_relay_playback_delay = 500;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);

	sr_test_period(&data, buf, tsbbatch, EVEN, 1, sr_test_even1);
	sr_test_check(sr_test_is_plain(buf, 1), "first even period descrambles");

	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_check(key_data[data.connid].has_waiting[EVEN],
					"a new even key waits, the period in play still needs the one in the register");

	sr_test_period(&data, buf, tsbbatch, EVEN, 2, sr_test_even1);
	sr_test_check(sr_test_is_plain(buf, 2), "the running period keeps descrambling with its own key");

	sr_test_period(&data, buf, tsbbatch, ODD, 3, sr_test_odd1);
	sr_test_check(sr_test_is_plain(buf, 3), "the odd period descrambles after the parity change");

	sr_test_period(&data, buf, tsbbatch, EVEN, 4, sr_test_even2);
	sr_test_check(sr_test_is_plain(buf, 4), "the next even period uses the key that had arrived");

	free_key_data(data.connid);

	// The same thing without a delay, to show the test can tell the difference.
	cfg.stream_relay_playback_delay = 0;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);

	sr_test_period(&data, buf, tsbbatch, EVEN, 5, sr_test_even1);
	sr_test_check(!sr_test_is_plain(buf, 5), "without a delay those packets are lost, as before");

	free_key_data(data.connid);

	// A late key, delivered from another thread while the period is already
	// running: the stream does not wait for it, it takes it over on arrival.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 6, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 7, sr_test_odd1);
	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);
	took = sr_test_period(&data, buf, tsbbatch, EVEN, 8, sr_test_even2);
	sr_test_check(took < 100 && sr_test_is_plain(buf, 8), "three periods on time, none of them waits");
	sr_test_check(delay_data[data.connid].delay_ms == SR_DELAY_AUTO_START_MS,
					"and the delay is still the one the automatic started with");

	job.after_ms = 200;
	job.connid = data.connid;
	sr_test_er(&job.er, sr_test_even2, sr_test_odd2);
	pthread_create(&tid, NULL, sr_test_late_cw, &job);

	took = sr_test_period(&data, buf, tsbbatch, ODD, 9, sr_test_odd2);
	sr_test_check(took < 100, "the next odd period does not wait for its late key");
	pthread_join(tid, NULL);

	sr_test_period(&data, buf, tsbbatch, ODD, 9, sr_test_odd2);
	sr_test_check(sr_test_is_plain(buf, 9), "and descrambles as soon as the key has come in");
	sr_test_check(delay_data[data.connid].delay_ms == SR_DELAY_AUTO_START_MS,
					"which is not the moment to raise the delay, the period is running");

	sr_test_er(&er, sr_test_even3, sr_test_odd2);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 8, sr_test_even3);
	sr_test_check(delay_data[data.connid].delay_ms >= 300 && delay_data[data.connid].delay_ms <= 520,
					"the next boundary raises it by how late the key was, plus a margin");

	free_key_data(data.connid);

	// A key that is not there when its period starts: the stream runs on
	// instead of stopping, and takes the key over the moment it arrives.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 10, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 11, sr_test_odd1);
	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 12, sr_test_even2);

	took = sr_test_period(&data, buf, tsbbatch, ODD, 13, sr_test_odd2);
	sr_test_check(took < 100, "a period whose key is missing does not stop the stream");
	sr_test_check(!sr_test_is_plain(buf, 13), "what leaves before the key is there is lost");
	sr_test_check(sr_test_unopened(&data, ODD), "nothing in line opens the period");
	sr_test_check(delay_data[data.connid].delay_ms == SR_DELAY_AUTO_START_MS,
					"nothing is raised while the key is still out");

	cs_sleepms(120);
	sr_test_er(&er, sr_test_even2, sr_test_odd2);
	write_cw(&er, data.connid);
	sr_test_check(key_data[data.connid].probe_armed[ODD],
					"and the arriving key gets the probe to look again");

	sr_test_period(&data, buf, tsbbatch, ODD, 14, sr_test_odd2);
	sr_test_check(sr_test_is_plain(buf, 14), "so the rest of that period descrambles");

	sr_test_er(&er, sr_test_even3, sr_test_odd2);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 15, sr_test_even3);
	grown = delay_data[data.connid].delay_ms;
	sr_test_check(grown >= 200 && grown <= 420,
					"and how late it was raises the delay at the next period boundary");

	took = sr_test_period(&data, buf, tsbbatch, ODD, 16, sr_test_odd2);
	sr_test_check(took < 100, "a key that never comes does not stop it either");
	sr_test_check(delay_data[data.connid].delay_ms == grown, "and raises nothing");

	free_key_data(data.connid);

	// A key that turns up during a run but belongs to another period is not a
	// late key and must not raise anything.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 30, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 31, sr_test_odd1);

	// the stream moves on to a key nobody has yet
	sr_test_period(&data, buf, tsbbatch, EVEN, 32, sr_test_even2);
	sr_test_check(sr_test_unopened(&data, EVEN),
					"a period whose key is missing has nothing that opens it");

	// and what comes in is the key after that, not the one this run needs
	cs_sleepms(120);
	sr_test_er(&er, sr_test_even3, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 33, sr_test_even2);
	sr_test_check(!sr_test_is_plain(buf, 33), "it does not descramble the run either");
	sr_test_check(key_data[data.connid].run_dead[EVEN],
					"and the probe does not let it through either");

	sr_test_er(&er, sr_test_even3, sr_test_odd2);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, ODD, 34, sr_test_odd2);
	sr_test_check(delay_data[data.connid].delay_ms == SR_DELAY_AUTO_START_MS,
					"and the delay stays where it was");

	free_key_data(data.connid);

	// A control word later than a whole crypto period: the count reads the run as
	// supplied while the key in force belongs to an earlier one, see probe_run_key().
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 50, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 51, sr_test_odd1);

	// one key for the parity has come in, but the stream is a period further on
	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 52, sr_test_even3);
	sr_test_check(!sr_test_is_plain(buf, 52), "while the key in force does not open it");
	sr_test_check(key_data[data.connid].late_ms[EVEN] == 0,
					"and nothing counts as late, no word opened this period");
	sr_test_check(delay_data[data.connid].delay_ms == SR_DELAY_AUTO_START_MS,
					"and nothing is measured, there is no working key to be late");
	sr_test_check(key_data[data.connid].run_dead[EVEN],
					"and notes the key as rejected");
	sr_test_check(sr_test_scrambled(buf) == SR_TEST_PACKETS,
					"so the whole period keeps the mark it came in with, not just its tail");

	// the next control word opens again, which lifts the state
	sr_test_er(&er, sr_test_even3, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, ODD, 53, sr_test_odd1);
	sr_test_period(&data, buf, tsbbatch, EVEN, 54, sr_test_even3);
	sr_test_check(!key_data[data.connid].run_dead[EVEN],
					"a key that opens clears it again");
	sr_test_check(sr_test_is_plain(buf, 54), "and the period is relayed as usual");

	free_key_data(data.connid);

	// A period whose own control word has not come yet must not be relayed with
	// the key of an earlier one: that is noise, and noise is what kills decoders.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 90, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 91, sr_test_odd1);

	// the stream moves on to a key that has not been published at all
	sr_test_period(&data, buf, tsbbatch, EVEN, 92, sr_test_even2);
	sr_test_check(sr_test_unopened(&data, EVEN),
					"a period whose control word is out has nothing that opens it");
	sr_test_check(key_data[data.connid].run_dead[EVEN],
					"and the register is marked as not opening it");
	sr_test_check(sr_test_scrambled(buf) == SR_TEST_PACKETS,
					"so it leaves marked scrambled, which is no noise to a decoder");
	sr_test_check(!keys_decided(&data, 1 << EVEN),
					"and it is not settled, its word may still turn up");

	// it comes, and the next period of that parity is relayed as usual again
	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, ODD, 93, sr_test_odd1);
	sr_test_period(&data, buf, tsbbatch, EVEN, 94, sr_test_even2);
	sr_test_check(!key_data[data.connid].run_dead[EVEN] && sr_test_is_plain(buf, 94),
					"the control word that turns up clears it again");

	free_key_data(data.connid);

	// What the log says about a period must match what happened to it: a word of
	// its own that does not open it is unusable, no word at all is a gap.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 110, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 111, sr_test_odd1);

	// the stream moves on and no word for that parity has come in at all
	sr_test_period(&data, buf, tsbbatch, EVEN, 112, sr_test_even2);
	sr_test_check(key_data[data.connid].miss_pending[EVEN],
					"a period nobody sent a word for is noted as a gap");

	// the word for the other parity is the gap it belongs in, and clears it
	sr_test_er(&er, sr_test_even1, sr_test_odd2);
	write_cw(&er, data.connid);
	sr_test_check(!key_data[data.connid].miss_pending[EVEN],
					"and the next word of the other parity is where it is said");

	free_key_data(data.connid);

	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 115, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 116, sr_test_odd1);

	// a word of its own did come in for the period, and it does not open it
	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 117, sr_test_even3);
	sr_test_check(key_data[data.connid].reported[EVEN]
					&& !key_data[data.connid].miss_pending[EVEN],
					"a word that does not open its period is called unusable, not a gap");

	// and it stays unusable in the period after it: nothing new came, but what is
	// in the register is still not the word that last opened one
	sr_test_period(&data, buf, tsbbatch, ODD, 118, sr_test_odd1);
	sr_test_period(&data, buf, tsbbatch, EVEN, 119, sr_test_even3);
	sr_test_check(key_data[data.connid].reported[EVEN]
					&& !key_data[data.connid].miss_pending[EVEN],
					"a word that keeps failing is not turned into a gap afterwards");

	// The pids do not change parity at the same instant, so a handful of packets
	// of the other parity is the boundary flapping, not the next period. Judging
	// the same period again on that would say the opposite of what was just said
	// and, worse, would stop the nulling in the middle of it.
	{
		uint8_t buf2[SR_TEST_BUF];

		sr_test_fill(buf2, ODD, 118);
		sr_test_scramble(buf2, sr_test_odd1);
		judge_ts_packets(&data, buf2, (SR_PERIOD_MIN_PACKETS - 1) * 188, 188);

		sr_test_check(key_data[data.connid].parity == EVEN,
						"a short run of the other parity does not begin a period");
		sr_test_check(key_data[data.connid].run_dead[EVEN]
						&& key_data[data.connid].reported[EVEN]
						&& !key_data[data.connid].miss_pending[EVEN],
						"so the period it interrupts keeps its verdict and stays unopened");
	}

	// A flap long enough to be believed does enter the period again, and the
	// register still has nothing new to say about it: the verdict belongs to the
	// word, not to the entry, or the boundary would repeat it every time.
	{
		uint8_t buf2[SR_TEST_BUF];
		uint32_t n;

		sr_test_period(&data, buf, tsbbatch, ODD, 120, sr_test_odd1);

		sr_test_fill(buf2, EVEN, 121);

		for (n = 0; n < SR_TEST_PACKETS; n++)
			{ buf2[n * 188 + 1] &= (uint8_t)~0x40; } // no payload start, nothing to judge on

		sr_test_scramble(buf2, sr_test_even3);
		judge_ts_packets(&data, buf2, SR_TEST_BUF, 188);

		sr_test_check(key_data[data.connid].parity == EVEN
						&& key_data[data.connid].reported[EVEN],
						"entering the period again does not say the same thing twice");
	}

	// a word of its own, though, is entitled to a verdict of its own: it arrives
	// while the other parity plays, which is where a broadcaster puts it
	sr_test_period(&data, buf, tsbbatch, ODD, 122, sr_test_odd1);
	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_check(!key_data[data.connid].reported[EVEN],
					"a word that arrives after it gets a say of its own");

	free_key_data(data.connid);

	// The proof of a key may sit in a buffer that is not due yet, so judging must
	// be able to reach past the head instead of settling for what it has.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, ODD, 80, sr_test_odd1);

	sr_test_fill(buf, EVEN, 81);
	sr_test_nostart(buf);
	sr_test_scramble(buf, sr_test_even1);
	sr_test_check(judge_ts_packets(&data, buf, SR_TEST_BUF, 188) == (1 << EVEN),
					"a buffer of one parity reports that parity alone");
	sr_test_check(key_data[data.connid].probe_armed[EVEN],
					"with nothing judgable in it the key stays unproven");
	sr_test_check(!keys_decided(&data, 1 << EVEN),
					"so the search for its proof carries on into the line");

	{
		uint8_t next[SR_TEST_BUF];

		// a buffer of the other parity belongs to the next run and must settle nothing
		sr_test_fill(next, ODD, 82);
		sr_test_scramble(next, sr_test_odd1);
		sr_test_check(!probe_queued(&data, next, SR_TEST_BUF, 188, EVEN),
						"a buffer that starts the next run stops the search");
		sr_test_check(key_data[data.connid].probe_armed[EVEN],
						"and settles nothing, its packets belong to another key");

		sr_test_fill(next, EVEN, 83);
		sr_test_scramble(next, sr_test_even1);
		sr_test_check(probe_queued(&data, next, SR_TEST_BUF, 188, EVEN),
						"a buffer of the same run is searched to its end");
		sr_test_check(!key_data[data.connid].probe_armed[EVEN],
						"and its judgable packet settles the key");
	}

	free_key_data(data.connid);

	// What the head is held back for. A period boundary hands over the first
	// packets of the new parity with nothing judgable among them, and holding
	// there would cost the client a turn at every boundary for no proof at all.
	// A register caught failing is the other case: its packets leave unopened
	// anyway, so waiting for a word that opens them loses nothing.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 60, sr_test_even1);

	sr_test_fill(buf, ODD, 61);
	sr_test_nostart(buf);
	sr_test_scramble(buf, sr_test_odd1);
	judge_ts_packets(&data, buf, SR_TEST_BUF, 188);
	sr_test_check(key_data[data.connid].parity == ODD && key_data[data.connid].probe_armed[ODD],
					"the first packets of a period carry nothing to judge its key on");

	sr_test_fill(buf, ODD, 62);
	sr_test_scramble(buf, sr_test_odd2);  // not the word the register holds
	judge_ts_packets(&data, buf, SR_TEST_BUF, 188);
	sr_test_check(key_data[data.connid].run_dead[ODD],
					"a register that failed on real payload has no word that opens the period");
	DescrambleTsPackets(&data, buf, SR_TEST_BUF, 188, tsbbatch);
	sr_test_check(!sr_test_is_plain(buf, 62), "nothing of it was handed out descrambled");

	free_key_data(data.connid);

	// The control words stop for a while and then come back, as they do when a
	// reader is taken out and put back. Nothing may stay out of step after that.
	cfg.stream_relay_playback_delay = 1;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 20, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 21, sr_test_odd1);
	sr_test_check(sr_test_is_plain(buf, 21), "running before the gap");

	// nothing arrives any more while the stream moves on to the next keys
	sr_test_period(&data, buf, tsbbatch, EVEN, 22, sr_test_even2);
	sr_test_period(&data, buf, tsbbatch, ODD, 23, sr_test_odd2);
	sr_test_period(&data, buf, tsbbatch, EVEN, 24, sr_test_even2);
	sr_test_period(&data, buf, tsbbatch, ODD, 25, sr_test_odd2);
	sr_test_check(!sr_test_is_plain(buf, 25), "what leaves during the gap is lost");
	sr_test_check(sr_test_unopened(&data, EVEN) && sr_test_unopened(&data, ODD),
					"neither parity has anything that opens it while the keys are away");
	sr_test_check(delay_data[data.connid].delay_ms == SR_DELAY_AUTO_START_MS,
					"and a key that never came raises nothing");

	// and now they come back, one parity at a time as a cam delivers them
	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 26, sr_test_even2);
	sr_test_check(sr_test_is_plain(buf, 26), "the even period picks the key that came back");

	sr_test_er(&er, sr_test_even2, sr_test_odd2);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, ODD, 27, sr_test_odd2);
	sr_test_check(sr_test_is_plain(buf, 27), "and so does the odd one");

	sr_test_er(&er, sr_test_even3, sr_test_odd2);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 28, sr_test_even3);
	sr_test_check(sr_test_is_plain(buf, 28), "the period after that is still right");

	sr_test_period(&data, buf, tsbbatch, ODD, 29, sr_test_odd2);
	sr_test_check(sr_test_is_plain(buf, 29), "and the one after that, so neither parity drifted");

	free_key_data(data.connid);

	// A fixed delay is what the user asked for, so it never waits.
	cfg.stream_relay_playback_delay = 500;
	init_key_data(data.connid);

	sr_test_er(&er, sr_test_even1, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 16, sr_test_even1);
	sr_test_period(&data, buf, tsbbatch, ODD, 17, sr_test_odd1);
	sr_test_er(&er, sr_test_even2, sr_test_odd1);
	write_cw(&er, data.connid);
	sr_test_period(&data, buf, tsbbatch, EVEN, 18, sr_test_even2);

	took = sr_test_period(&data, buf, tsbbatch, ODD, 19, sr_test_odd1);
	sr_test_check(took < 100, "a missing key is not waited for");
	sr_test_check(sr_test_is_plain(buf, 19), "and relays with the key at hand");

	free_key_data(data.connid);

	NULLFREE(buf);
	NULLFREE(tsbbatch);

	cfg.stream_relay_playback_delay = saved_delay;
	cluster_size = saved_cluster;
	has_dvbcsa_ecm = saved_ecm;

	return sr_test_failures;
}

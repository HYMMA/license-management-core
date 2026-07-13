/* SNTP (RFC 4330) packet encode/decode shared by the platform ports, plus
 * the trusted-time tuning constants both ports use. Implemented in
 * hlm_ports_common.c.
 *
 * Lives in core/ (not ports/) because the wrapper vendoring scripts copy
 * only *.c from src/ports but every header from src/core. */
#ifndef HLM_SNTP_H
#define HLM_SNTP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HLM_SNTP_PACKET_SIZE 48

#define HLM_NTP_TIMEOUT_MS 3000
#define HLM_MAX_DRIFT_SECONDS 3600 /* 1.0 hour, matches TimeSyncConstants */

/* Fill a 48-byte client request: LI=0, VN=3, Mode=3. */
void hlm_sntp_build_request(uint8_t pkt[HLM_SNTP_PACKET_SIZE]);

/* Extract the transmit timestamp (bytes 40-43, big-endian seconds since
 * 1900-01-01) as unix seconds, era-pivoted past the Feb-2036 rollover.
 * Returns 0 on success, -1 on a zero/absent timestamp. */
int hlm_sntp_parse_reply(const uint8_t pkt[HLM_SNTP_PACKET_SIZE],
                         int64_t *epoch_out);

#ifdef __cplusplus
}
#endif

#endif /* HLM_SNTP_H */

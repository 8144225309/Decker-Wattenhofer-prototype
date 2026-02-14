#include "superscalar/fee.h"
#include <string.h>

void fee_init(fee_estimator_t *fe, uint64_t default_rate_sat_per_kvb) {
    if (!fe) return;
    memset(fe, 0, sizeof(*fe));
    fe->fee_rate_sat_per_kvb = default_rate_sat_per_kvb;
    fe->use_estimatesmartfee = 0;
}

uint64_t fee_estimate(const fee_estimator_t *fe, size_t vsize_bytes) {
    if (!fe || fe->fee_rate_sat_per_kvb == 0) return 0;
    /* Round up: (rate * vsize + 999) / 1000 */
    return (fe->fee_rate_sat_per_kvb * vsize_bytes + 999) / 1000;
}

uint64_t fee_for_penalty_tx(const fee_estimator_t *fe) {
    /* Penalty tx: 1 Schnorr key-path input, 1 P2TR output ~152 vB */
    return fee_estimate(fe, 152);
}

uint64_t fee_for_htlc_tx(const fee_estimator_t *fe) {
    /* HTLC resolution tx: script-path spend ~180 vB */
    return fee_estimate(fe, 180);
}

uint64_t fee_for_factory_tx(const fee_estimator_t *fe, size_t n_outputs) {
    /* Factory tree tx: ~50 vB overhead + ~43 vB per P2TR output */
    size_t vsize = 50 + 43 * n_outputs;
    return fee_estimate(fe, vsize);
}

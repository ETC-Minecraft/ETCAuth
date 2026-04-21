package com.etcmc.etcauth.web;

import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory metric counters used by the embedded HTTP server.
 *
 * <p>Counters are monotonic; gauges are recomputed on demand by
 * {@link MetricsHandler}.
 */
public final class Metrics {

    public final AtomicLong loginsOk      = new AtomicLong();
    public final AtomicLong loginsFail    = new AtomicLong();
    public final AtomicLong loginsNeeds2fa = new AtomicLong();
    public final AtomicLong registrations = new AtomicLong();
    public final AtomicLong premiumClaims = new AtomicLong();
    public final AtomicLong recoveryRequests = new AtomicLong();
    public final AtomicLong recoveryCompletions = new AtomicLong();
}

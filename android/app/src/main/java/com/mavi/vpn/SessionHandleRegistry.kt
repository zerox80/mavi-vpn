package com.mavi.vpn

/**
 * Tracks the native VPN session handle together with a monotonically increasing
 * generation counter.
 *
 * The generation is the single source of truth for "which start request is the
 * current one". Because [com.mavi.vpn.nativelib.NativeLib.init] blocks for the
 * full QUIC handshake (seconds over the network), a worker thread can return
 * with a freshly created handle long after the user has already stopped or
 * restarted the VPN. Adopting that stale handle unconditionally would:
 *
 *  - overwrite the handle of the *new* session (which then reads back a foreign
 *    handle and runs its loop on the wrong connection), and
 *  - leak the stale handle's QUIC connection — its keep-alives hold the
 *    server-side IP lease open indefinitely.
 *
 * Every mutation is therefore gated on the worker's captured generation. The
 * registry borrows the caller's monitor object so a compound operation in the
 * service (snapshotting Android resources *and* bumping the generation) stays
 * atomic; JVM monitors are reentrant, so nesting is safe.
 */
internal class SessionHandleRegistry(
    private val lock: Any = Any(),
) {
    private var generation: Long = 0L
    private var handle: Long = 0L

    /** Result of [invalidate]: the handle the superseded session had adopted
     *  (0 if none) and the new current generation. */
    data class Invalidation(
        val previousHandle: Long,
        val generation: Long,
    )

    val currentGeneration: Long
        get() = synchronized(lock) { generation }

    /**
     * Supersedes any in-flight session by bumping the generation, and returns
     * the handle that the now-superseded session had adopted so the caller can
     * stop/free it exactly once.
     */
    fun invalidate(): Invalidation =
        synchronized(lock) {
            generation += 1
            val previousHandle = handle
            handle = 0L
            Invalidation(previousHandle, generation)
        }

    /**
     * Adopts [newHandle] into the registry, but only if [workerGeneration] is
     * still current. Returns true when adopted; false means the session was
     * superseded while the handle was being created and the caller MUST
     * stop+free [newHandle] itself.
     */
    fun tryAdopt(
        newHandle: Long,
        workerGeneration: Long,
    ): Boolean =
        synchronized(lock) {
            if (generation == workerGeneration) {
                handle = newHandle
                true
            } else {
                false
            }
        }

    /** True while [workerGeneration] is still the current session generation. */
    fun isCurrent(workerGeneration: Long): Boolean =
        synchronized(lock) { generation == workerGeneration }

    /** The adopted handle if it still belongs to [workerGeneration], else 0. */
    fun handleIfCurrent(workerGeneration: Long): Long =
        synchronized(lock) { if (generation == workerGeneration) handle else 0L }

    /**
     * Runs [action] for the current handle while holding the shared session
     * monitor. This makes the native operation atomic with handle removal and
     * freeing: a callback cannot obtain a pointer that another thread frees
     * immediately afterwards.
     *
     * Returns false when [workerGeneration] is no longer current or no handle
     * has been adopted yet.
     */
    fun withHandleIfCurrent(
        workerGeneration: Long,
        action: (Long) -> Unit,
    ): Boolean =
        synchronized(lock) {
            val currentHandle = if (generation == workerGeneration) handle else 0L
            if (currentHandle == 0L) {
                false
            } else {
                action(currentHandle)
                true
            }
        }

    /**
     * Clears the stored handle if it still equals [targetHandle]. Returns true
     * if it was cleared (the registry still pointed at this handle).
     */
    fun clearIfMatches(targetHandle: Long): Boolean =
        synchronized(lock) {
            if (targetHandle != 0L && handle == targetHandle) {
                handle = 0L
                true
            } else {
                false
            }
        }
}

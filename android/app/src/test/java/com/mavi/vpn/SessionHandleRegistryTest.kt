package com.mavi.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionHandleRegistryTest {
    @Test
    fun adoptsHandleForCurrentGeneration() {
        val registry = SessionHandleRegistry()
        val generation = registry.currentGeneration

        assertTrue(registry.tryAdopt(0x1234L, generation))
        assertEquals(0x1234L, registry.handleIfCurrent(generation))
        assertTrue(registry.isCurrent(generation))
    }

    @Test
    fun rejectsAdoptionFromSupersededGeneration() {
        val registry = SessionHandleRegistry()
        val staleGeneration = registry.currentGeneration

        // A new start request bumps the generation while the worker was in init().
        val invalidation = registry.invalidate()

        assertFalse(registry.tryAdopt(0xAAAAL, staleGeneration))
        // The orphan handle must not become the current session's handle.
        assertEquals(0L, registry.handleIfCurrent(invalidation.generation))
        assertEquals(0L, registry.handleIfCurrent(staleGeneration))
    }

    @Test
    fun invalidateReturnsPreviouslyAdoptedHandleExactlyOnce() {
        val registry = SessionHandleRegistry()
        val generation = registry.currentGeneration
        registry.tryAdopt(0x55L, generation)

        val first = registry.invalidate()
        assertEquals(0x55L, first.previousHandle)
        assertEquals(generation + 1, first.generation)

        // A second invalidate must not hand the same handle out again.
        val second = registry.invalidate()
        assertEquals(0L, second.previousHandle)
        assertEquals(generation + 2, second.generation)
    }

    @Test
    fun staleWorkerCannotOverwriteNewSessionHandle() {
        // Reproduces the K1 bug: worker A finishes init() after a restart and
        // tries to store its handle; it must not clobber worker B's handle.
        val registry = SessionHandleRegistry()
        val generationA = registry.currentGeneration

        // Restart: generation bumps, worker B adopts its handle.
        val generationB = registry.invalidate().generation
        assertTrue(registry.tryAdopt(0xB0B0L, generationB))

        // Worker A returns late and attempts to adopt — must be refused.
        assertFalse(registry.tryAdopt(0xA0A0L, generationA))
        assertEquals(0xB0B0L, registry.handleIfCurrent(generationB))
    }

    @Test
    fun clearIfMatchesOnlyClearsOwnHandle() {
        val registry = SessionHandleRegistry()
        val generation = registry.currentGeneration
        registry.tryAdopt(0x99L, generation)

        assertFalse(registry.clearIfMatches(0x11L))
        assertEquals(0x99L, registry.handleIfCurrent(generation))

        assertTrue(registry.clearIfMatches(0x99L))
        assertEquals(0L, registry.handleIfCurrent(generation))

        // Clearing a zero handle is always a no-op.
        assertFalse(registry.clearIfMatches(0L))
    }

    @Test
    fun isCurrentTracksGenerationChanges() {
        val registry = SessionHandleRegistry()
        val generation = registry.currentGeneration

        assertTrue(registry.isCurrent(generation))
        registry.invalidate()
        assertFalse(registry.isCurrent(generation))
    }
}

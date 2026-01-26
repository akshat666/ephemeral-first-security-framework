package io.efsf.sealed;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * A context for tracking objects and cleanup callbacks during sealed execution.
 */
public final class SealedContext {

    private final List<WeakReference<Object>> trackedObjects;
    private final List<Runnable> cleanupCallbacks;
    private boolean active;

    SealedContext() {
        this.trackedObjects = new ArrayList<>();
        this.cleanupCallbacks = new ArrayList<>();
        this.active = true;
    }

    /**
     * Tracks an object for cleanup when the sealed context exits.
     * Uses weak references to allow garbage collection.
     *
     * @param obj the object to track
     * @param <T> the object type
     * @return the same object for chaining
     */
    public <T> T track(T obj) {
        ensureActive();
        if (obj != null) {
            trackedObjects.add(new WeakReference<>(obj));
        }
        return obj;
    }

    /**
     * Registers a cleanup callback to be called when the sealed context exits.
     *
     * @param callback the cleanup callback
     */
    public void onCleanup(Runnable callback) {
        ensureActive();
        if (callback != null) {
            cleanupCallbacks.add(callback);
        }
    }

    /**
     * Checks if this context is still active.
     *
     * @return true if active
     */
    public boolean isActive() {
        return active;
    }

    /**
     * Gets the number of tracked objects.
     *
     * @return the count
     */
    public int getTrackedCount() {
        return trackedObjects.size();
    }

    /**
     * Gets the number of registered cleanup callbacks.
     *
     * @return the count
     */
    public int getCleanupCount() {
        return cleanupCallbacks.size();
    }

    /**
     * Performs cleanup and deactivates this context.
     * Called automatically by SealedExecution.
     */
    void cleanup() {
        active = false;

        // Run cleanup callbacks in reverse order
        for (int i = cleanupCallbacks.size() - 1; i >= 0; i--) {
            try {
                cleanupCallbacks.get(i).run();
            } catch (Exception e) {
                // Log but don't throw - cleanup must complete
            }
        }
        cleanupCallbacks.clear();

        // Clear tracked objects
        trackedObjects.clear();

        // Hint to GC
        System.gc();
    }

    private void ensureActive() {
        if (!active) {
            throw new IllegalStateException("SealedContext is no longer active");
        }
    }
}

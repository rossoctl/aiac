package io.aiac.keycloak.events;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Captures the log records of one class in a test. The test classpath has no other jboss-logging
 * backend, so jboss-logging writes through {@code java.util.logging}, and a handler on the class's
 * JUL logger gets each record. Call {@link #detach()} in a {@code finally} block.
 */
final class CapturedLog extends Handler {

    private final Logger logger;
    private final List<LogRecord> records = new ArrayList<>();

    private CapturedLog(Logger logger) {
        this.logger = logger;
    }

    static CapturedLog of(Class<?> type) {
        CapturedLog log = new CapturedLog(Logger.getLogger(type.getName()));
        log.logger.addHandler(log);
        return log;
    }

    void detach() {
        logger.removeHandler(this);
    }

    /** True when a record at {@code WARNING} or above has {@code text} in its message. */
    synchronized boolean hasWarning(String text) {
        return records.stream()
                .anyMatch(r -> r.getLevel().intValue() >= Level.WARNING.intValue()
                        && String.valueOf(r.getMessage()).contains(text));
    }

    @Override
    public synchronized void publish(LogRecord record) {
        records.add(record);
    }

    @Override
    public void flush() {
        // Nothing is buffered.
    }

    @Override
    public void close() {
        // Nothing to release.
    }
}

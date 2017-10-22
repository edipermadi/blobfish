package com.github.edipermadi.security.blobfish;

import org.apache.commons.io.HexDump;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.testng.Reporter;

import java.io.IOException;

/**
 * Base Class for Testing Classes
 *
 * @author Edi Permadi
 */
public abstract class AbstractTest {
    /**
     * Log to testNG reporter
     *
     * @param format message format
     * @param args   message parameters
     */
    public void log(String format, Object... args) {
        Reporter.log(String.format(format, args), true);
    }

    /**
     * Hexdump byte array
     *
     * @param data byte array to be dumped
     * @return formatted hexdump of byte array
     * @throws IOException when processing failed
     */
    protected String hexdump(final byte[] data) throws IOException {
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            HexDump.dump(data, 0, baos, 0);
            return new String(baos.toByteArray());
        }
    }
}

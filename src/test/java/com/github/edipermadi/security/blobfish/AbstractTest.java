package com.github.edipermadi.security.blobfish;

import org.testng.Reporter;

/**
 * Base Class for Testing Classes
 *
 * @author Edi Permadi
 */
abstract class AbstractTest {
    /**
     * Log to testNG reporter
     *
     * @param format message format
     * @param args   message parameters
     */
    void log(String format, Object... args) {
        Reporter.log(String.format(format, args), true);
    }
}

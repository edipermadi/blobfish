package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.AbstractTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.sql.SQLException;

/**
 * Blob Pool Builder Unit Test
 *
 * @author Edi Permadi
 */
public final class BlobPoolBuilderTest extends AbstractTest {
    @BeforeMethod
    public void beforeMethod(final Method method) {
        log("========================================");
        log(method.getName(), true);
        log("========================================");
    }

    @Test
    public void testBuild() throws SQLException, IOException, ClassNotFoundException {
        log("building blob pool");

        final File dbFile = new File("/tmp/blob-pool");
        final String dbPassword = "password";
        new BlobPoolBuilder()
                .setDbFile(dbFile)
                .setDbPassword(dbPassword)
                .build();
    }
}

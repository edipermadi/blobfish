package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.AbstractTest;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;

/**
 * Blob Pool Builder Unit Test
 *
 * @author Edi Permadi
 */
public final class BlobPoolBuilderTest extends AbstractTest {
    private KeyStore keyStore;

    @BeforeClass
    @Parameters({"keystore-file-path", "keystore-file-password"})
    public void beforeClass(final String keystoreFilePath, final String keystoreFilePassword) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {

        log("using keystore file path     : %s", keystoreFilePath);
        log("using keystore file password : %s", keystoreFilePassword);

        this.keyStore = KeyStore.getInstance("JKS");
        try (final FileInputStream fis = new FileInputStream(new File(keystoreFilePath))) {
            keyStore.load(fis, keystoreFilePassword.toCharArray());
        }
    }

    @BeforeMethod
    public void beforeMethod(final Method method) {
        log("========================================");
        log(method.getName(), true);
        log("========================================");
    }

    @Test
    public void testBuild() throws SQLException, IOException, ClassNotFoundException {
        log("building blob pool");

        final File dbFile = new File("target/db/blob-pool-1");
        final String dbPassword = "password";
        new BlobPoolBuilder()
                .setDbFile(dbFile)
                .setDbPassword(dbPassword)
                .build();
    }

    @Test
    @Parameters({"blobfish-path-v2", "blobfish-password"})
    public void testImportPayloadByPassword(final String blobPath, final String blobPassword) throws SQLException, IOException, ClassNotFoundException, CertificateException, BlobfishDecodeException, BlobfishCryptoException {
        log("building load pool");

        final File dbFile = new File("target/db/blob-pool-2");
        final String dbPassword = "password";
        final BlobPool pool = new BlobPoolBuilder()
                .setDbFile(dbFile)
                .setDbPassword(dbPassword)
                .build();
        try (final FileInputStream fis = new FileInputStream(new File(blobPath))) {
            pool.importPayload(fis, blobPassword);
        }
    }

    @Test
    @Parameters({"blobfish-path-v2",
            "keystore-entry-password",
            "keystore-alias-enc-sender"})
    public void testImportPayloadByPrivateKey(final String blobPath,
                                     final String keyStoreEntryPassword,
                                     final String keyStoreAlias) throws SQLException, IOException, ClassNotFoundException, CertificateException, BlobfishDecodeException, BlobfishCryptoException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        log("building load pool");

        final File dbFile = new File("target/db/blob-pool-3");
        final String dbPassword = "password";
        final BlobPool pool = new BlobPoolBuilder()
                .setDbFile(dbFile)
                .setDbPassword(dbPassword)
                .build();
        try (final FileInputStream fis = new FileInputStream(new File(blobPath))) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keyStoreAlias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStoreAlias, keyStoreEntryPassword.toCharArray());
            pool.importPayload(fis, certificate, privateKey);
        }
    }
}

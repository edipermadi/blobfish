package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.AbstractTest;
import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;
import com.google.common.base.Joiner;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;

/**
 * Blob Pool Builder Unit Test
 *
 * @author Edi Permadi
 */
public final class BlobPoolBuilderTest extends AbstractTest {
    private KeyStore keyStore;
    private BlobPool blobPool;
    private UUID tagId;
    private String tagVal;

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
        log(method.getName());
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
        blobPool = new BlobPoolBuilder()
                .setDbFile(dbFile)
                .setDbPassword(dbPassword)
                .build();
        try (final FileInputStream fis = new FileInputStream(new File(blobPath))) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keyStoreAlias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStoreAlias, keyStoreEntryPassword.toCharArray());
            blobPool.importPayload(fis, certificate, privateKey);
        }
    }

    @Test(dependsOnMethods = {"testImportPayloadByPrivateKey"})
    public void testListTags() throws SQLException {
        boolean empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, String> tags = blobPool.listAvailableTags(page, 10);
            for (final Map.Entry<UUID, String> entry : tags.entrySet()) {
                log("found entry");
                log("  uuid : %s", entry.getKey());
                log("  tag  : %s", entry.getValue());
            }
            empty = tags.isEmpty();
        }
    }

    @Test(dependsOnMethods = {"testImportPayloadByPrivateKey"})
    public void testListBlobByTag() throws SQLException {
        boolean empty = false;

        /* list tags */
        final Set<UUID> tagIds = new HashSet<>();
        for (int page = 1; !empty; page++) {
            final Map<UUID, String> tags = blobPool.listAvailableTags(page, 10);
            for (final Map.Entry<UUID, String> entry : tags.entrySet()) {
                tagIds.add(entry.getKey());
            }
            empty = tags.isEmpty();
        }

        /* list blob by tags */
        for (final UUID tagId : tagIds) {
            empty = false;

            log("listing blobs with tag %s", tagId);
            for (int page = 1; !empty; page++) {
                final Map<UUID, Blob.SimplifiedMetadata> blobs = blobPool.listBlobsWithTag(tagId, page, 10);
                for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : blobs.entrySet()) {
                    final Blob.SimplifiedMetadata metadata = entry.getValue();

                    log("  found entry");
                    log("    uuid      : %s", entry.getKey());
                    log("    mime-type : %s", metadata.getMimeType());
                    log("    path      : %s", metadata.getPath());
                }
                empty = blobs.isEmpty();
            }
        }
    }

    @Test(dependsOnMethods = {"testImportPayloadByPrivateKey"})
    @Parameters({"keystore-alias-enc-sender", "keystore-alias-enc-receiver1", "keystore-alias-enc-receiver1"})
    public void testCreateRecipient(final String alias1, final String alias2, final String alias3) throws KeyStoreException, SQLException, CertificateEncodingException {
        Assert.assertNotNull(blobPool);
        final List<String> aliases = Arrays.asList(alias1, alias2, alias3);
        for (final String alias : aliases) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final String subject = certificate.getSubjectDN().toString();
            final String name = RandomStringUtils.randomAlphanumeric(16);
            blobPool.createRecipient(name, subject, certificate);
        }
    }

    @Test(dependsOnMethods = {"testCreateRecipient"})
    public void testListRecipient() throws SQLException {
        Assert.assertNotNull(blobPool);

        log("listing recipient");
        boolean empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, String> recipients = blobPool.listRecipient(page, 10);
            for (Map.Entry<UUID, String> entry : recipients.entrySet()) {
                log("  found recipient");
                log("    uuid : %s", entry.getKey());
                log("    name : %s", entry.getValue());
            }
            empty = recipients.isEmpty();
        }
    }

    @Test(dependsOnMethods = {"testImportPayloadByPrivateKey"})
    public void testCreateTag() throws SQLException {
        tagVal = RandomStringUtils.randomAlphanumeric(16).toLowerCase();

        /* compare tags before and after */
        final Set<String> originalTags = getAllTags(blobPool);
        tagId = blobPool.createTag(tagVal);
        final Set<String> updatedTags = getAllTags(blobPool);

        Assert.assertFalse(originalTags.contains(tagVal), String.format("%s should NOT in [%s]", tagVal, Joiner.on(", ").join(originalTags)));
        Assert.assertTrue(updatedTags.contains(tagVal), String.format("%s should in found [%s]", tagVal, Joiner.on(", ").join(originalTags)));
        log("tag-uuid : %s", tagId);
    }

    @Test(dependsOnMethods = {"testCreateTag"})
    public void testUpdateTag() throws SQLException {
        tagVal = RandomStringUtils.randomAlphanumeric(16).toLowerCase();

        /* check before update */
        final Set<String> originalTags = getAllTags(blobPool);
        Assert.assertFalse(originalTags.contains(tagVal), String.format("%s should NOT in [%s]", tagVal, Joiner.on(", ").join(originalTags)));

        /* update and compare */
        Assert.assertTrue(blobPool.updateTag(tagId, tagVal));
        final Set<String> updatedTags = getAllTags(blobPool);
        Assert.assertTrue(updatedTags.contains(tagVal), String.format("%s should in found [%s]", tagVal, Joiner.on(", ").join(originalTags)));

        log("tag-uuid : %s", tagId);
    }

    @Test(dependsOnMethods = {"testUpdateTag"})
    public void getTagValueByTagId() throws SQLException {
        final String value = blobPool.getTag(tagId);
        Assert.assertEquals(value, tagVal);
    }

    @Test(dependsOnMethods = {"getTagValueByTagId"})
    public void addTagToBlobByBlobIdAndTagId() throws SQLException {
        boolean empty = false;

        /* add tag to all blobs */
        for (int page = 1; !empty; page++) {
            final Map<UUID, Blob.SimplifiedMetadata> entries = blobPool.listAvailableBlobs(page, 10);
            for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : entries.entrySet()) {
                final UUID blobId = entry.getKey();
                final boolean added = blobPool.addTagToBlob(blobId, tagId);
                Assert.assertTrue(added);
            }
            empty = entries.isEmpty();
        }

        /* ensure that blobs have that tag */
        empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, Blob.SimplifiedMetadata> entries = blobPool.listAvailableBlobs(page, 10);
            for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : entries.entrySet()) {
                final UUID blobId = entry.getKey();
                final Map<UUID, String> tags = blobPool.getBlobTags(blobId);
                Assert.assertTrue(tags.containsValue(tagVal));
            }
            empty = entries.isEmpty();
        }
    }

    @Test(dependsOnMethods = {"addTagToBlobByBlobIdAndTagId"})
    public void removeTagFromBlobTagByBlobIdAndTagId() throws SQLException {
        boolean empty = false;

        /* remove tag from all blobs */
        for (int page = 1; !empty; page++) {
            final Map<UUID, Blob.SimplifiedMetadata> entries = blobPool.listAvailableBlobs(page, 10);
            for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : entries.entrySet()) {
                final UUID blobId = entry.getKey();
                final boolean added = blobPool.removeTagFromBlob(blobId, tagId);
                Assert.assertTrue(added);
            }
            empty = entries.isEmpty();
        }

        /* ensure that those blobs don't have that tag */
        empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, Blob.SimplifiedMetadata> entries = blobPool.listAvailableBlobs(page, 10);
            for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : entries.entrySet()) {
                final UUID blobId = entry.getKey();
                final Map<UUID, String> tags = blobPool.getBlobTags(blobId);
                Assert.assertFalse(tags.containsValue(tagVal));
            }
            empty = entries.isEmpty();
        }
    }

    @Test(dependsOnMethods = {"testImportPayloadByPrivateKey"})
    public void removeTagById() throws SQLException {
        final String tagVal = RandomStringUtils.randomAlphanumeric(16).toLowerCase();
        final UUID tagId = blobPool.createTag(tagVal);

        /* make sure new tag is there */
        Assert.assertTrue(getAllTags(blobPool).contains(tagVal));

        /* add tag to all blobs */
        boolean empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, Blob.SimplifiedMetadata> entries = blobPool.listAvailableBlobs(page, 10);
            for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : entries.entrySet()) {
                final UUID blobId = entry.getKey();
                final boolean added = blobPool.addTagToBlob(blobId, tagId);
                Assert.assertTrue(added);
            }
            empty = entries.isEmpty();
        }

        /* make sure association is there */
        empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, Blob.SimplifiedMetadata> entries = blobPool.listAvailableBlobs(page, 10);
            for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : entries.entrySet()) {
                final UUID blobId = entry.getKey();
                final Map<UUID, String> tags = blobPool.getBlobTags(blobId);
                Assert.assertTrue(tags.containsValue(tagVal));
            }
            empty = entries.isEmpty();
        }

        /* remove there */
        blobPool.removeTag(tagId);

        /* make sure association is removed */
        empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, Blob.SimplifiedMetadata> entries = blobPool.listAvailableBlobs(page, 10);
            for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : entries.entrySet()) {
                final UUID blobId = entry.getKey();
                final Map<UUID, String> tags = blobPool.getBlobTags(blobId);
                Assert.assertFalse(tags.containsValue(tagVal));
            }
            empty = entries.isEmpty();
        }

        /* make sure tag has been removed */
        Assert.assertFalse(getAllTags(blobPool).contains(tagVal));
    }

    @Test(dependsOnMethods = {"testImportPayloadByPrivateKey"})
    public void testListBlobs() throws SQLException, IOException {
        boolean empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, Blob.SimplifiedMetadata> blobs = blobPool.listAvailableBlobs(page, 10);
            for (final Map.Entry<UUID, Blob.SimplifiedMetadata> entry : blobs.entrySet()) {
                final Blob.SimplifiedMetadata metadata = entry.getValue();
                final Map<UUID, String> tags = blobPool.getBlobTags(entry.getKey());
                final byte[] payload = blobPool.getBlobPayload(entry.getKey());

                final Set<String> tagValues = new HashSet<>();
                for (final Map.Entry<UUID, String> tag : tags.entrySet()) {
                    tagValues.add(tag.getValue());
                }

                log("found entry");
                log("  uuid      : %s", entry.getKey());
                log("  mime-type : %s", metadata.getMimeType());
                log("  path      : %s", metadata.getPath());
                log("  tags      : %s", Joiner.on(", ").join(tagValues));

                final File file = new File(metadata.getPath());
                final File dir = new File("target");
                final File outFile = new File(dir, "pool-" + file.getName());
                try (final FileOutputStream fos = new FileOutputStream(outFile)) {
                    fos.write(payload);
                }
            }
            empty = blobs.isEmpty();
        }
    }

    /**
     * List all tags from blob-pool
     *
     * @param blobPool blob pool
     * @return set of tags
     * @throws SQLException when BlobPool access failed
     */
    private Set<String> getAllTags(final BlobPool blobPool) throws SQLException {
        final Set<String> tags = new HashSet<>();
        boolean empty = false;
        for (int page = 1; !empty; page++) {
            final Map<UUID, String> entries = blobPool.listAvailableTags(page, 10);
            for (final Map.Entry<UUID, String> entry : entries.entrySet()) {
                tags.add(entry.getValue());
            }
            empty = entries.isEmpty();
        }

        return tags;
    }
}

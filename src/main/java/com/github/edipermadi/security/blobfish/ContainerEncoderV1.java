package com.github.edipermadi.security.blobfish;

import com.github.edipermadi.security.blobfish.generated.BlobfishProto;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import org.apache.commons.io.output.ByteArrayOutputStream;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Container Encoder Version 1
 *
 * @author Edi Permadi
 */
final class ContainerEncoderV1 implements ContainerEncoder {
    private static final long MAGIC_CODE = 0x75676c7966697368L;
    private static final int VERSION_NUMBER = 1;
    private static final int ITERATION_NUMBER = 65536;
    private static final int KEY_LENGTH_BITS = 128;
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String KEY_PROTECTION_ALGORITHM = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    private static final String CIPHERING_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SIGNING_ALGORITHM = "SHA256withECDSA";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";

    private final PrivateKey signingPrivateKey;
    private final CodedOutputStream codedOutputStream;
    private final OutputStream outputStream;
    private byte[] keyBytes;
    private final AtomicInteger counter = new AtomicInteger(1);
    private final BlobfishProto.Blobfish.Body.Builder bodyBuilder;
    private final BlobfishProto.Blobfish.Header.Builder headerBuilder;

    /**
     * Container Encoder Version 1 Constructor
     *
     * @param builder Container Encoder Builder Instance
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    ContainerEncoderV1(ContainerEncoderBuilder builder) throws CertificateEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        signingPrivateKey = builder.signingPrivateKey;
        codedOutputStream = CodedOutputStream.newInstance(builder.outputStream);
        outputStream = builder.outputStream;
        bodyBuilder = BlobfishProto.Blobfish.Body.newBuilder();

        /* create header builder */
        headerBuilder = BlobfishProto.Blobfish.Header.newBuilder()
                .setCreated(System.currentTimeMillis())
                .setSender(BlobfishProto.Blobfish.Header.Sender.newBuilder()
                        .setSigningCertificate(ByteString.copyFrom(builder.signingCertificate.getEncoded()))
                        .build());

        /* generate key */
        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        if (builder.password != null) {
            byte[] salt = new byte[32];
            secureRandom.nextBytes(salt);
            final PBEKeySpec spec = new PBEKeySpec(builder.password, salt, ITERATION_NUMBER, KEY_LENGTH_BITS);
            final SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            keyBytes = factory.generateSecret(spec).getEncoded();

            /* register password entry */
            headerBuilder.setPassword(BlobfishProto.Blobfish.Header.Password.newBuilder()
                    .setIteration(ITERATION_NUMBER)
                    .setSalt(ByteString.copyFrom(salt))
                    .build());
        } else {
            keyBytes = new byte[16];
            secureRandom.nextBytes(keyBytes);
        }

        /* register recipients */
        final MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        final Cipher cipher = Cipher.getInstance(KEY_PROTECTION_ALGORITHM);
        for (final X509Certificate recipient : builder.recipientCertificates) {
            cipher.init(Cipher.ENCRYPT_MODE, recipient, secureRandom);
            md.reset();
            md.update(recipient.getPublicKey().getEncoded());
            headerBuilder.addRecipient(BlobfishProto.Blobfish.Header.Recipient.newBuilder()
                    .setCipheredKey(ByteString.copyFrom(cipher.doFinal(keyBytes)))
                    .setHashCertificate(ByteString.copyFrom(md.digest()))
                    .build());
        }
    }

    @Override
    public ContainerEncoderV1 addBlob(final String path, final Set<String> tags, final String mimeType,
                                      final InputStream inputStream) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, SignatureException {

        final byte[] encodedMetadata = encodeMetadata(path, tags, mimeType);
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(encodedMetadata)) {
            final BlobfishProto.Blobfish.Body.Entry metadata = createEntry(bais);
            final BlobfishProto.Blobfish.Body.Entry payload = createEntry(inputStream);
            final int id = counter.getAndIncrement();
            final BlobfishProto.Blobfish.Body.Blob blob = BlobfishProto.Blobfish.Body.Blob.newBuilder()
                    .setId(id)
                    .setMetadata(metadata)
                    .setPayload(payload)
                    .build();
            bodyBuilder.addBlob(blob);
        }

        return this;
    }

    @Override
    public void write() throws IOException {
        BlobfishProto.Blobfish.newBuilder()
                .setMagic(MAGIC_CODE)
                .setVersion(VERSION_NUMBER)
                .setBody(bodyBuilder)
                .setHeader(headerBuilder)
                .build()
                .writeTo(codedOutputStream);
        outputStream.flush();
    }

    /**
     * Encode metadata into byte array
     *
     * @param path     path of blob
     * @param tags     tags of blob
     * @param mimeType mime-type of blob
     * @return serialized blob metadata
     */
    private byte[] encodeMetadata(final String path, final Set<String> tags, final String mimeType) {
        return BlobfishProto.Blobfish.Body.Metadata.newBuilder()
                .setPath(path)
                .setMimeType(mimeType)
                .addAllTags(tags)
                .build()
                .toByteArray();
    }

    /**
     * Create blob entry
     *
     * @param inputStream input stream to read plain blob payload
     * @return blobfish body entry
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private BlobfishProto.Blobfish.Body.Entry createEntry(final InputStream inputStream) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        final Cipher cipher = Cipher.getInstance(CIPHERING_ALGORITHM);
        final SecretKeySpec cipherKeySpec = new SecretKeySpec(keyBytes, "AES");
        final IvParameterSpec cipherIvSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKeySpec, cipherIvSpec);

        /* initialize MAC */
        final SecretKeySpec macKeySpec = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
        final Mac macCalculator = Mac.getInstance(MAC_ALGORITHM);
        macCalculator.init(macKeySpec);

        /* initialize signer */
        final Signature signer = Signature.getInstance(SIGNING_ALGORITHM);
        signer.initSign(signingPrivateKey);

        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
             final CipherOutputStream cipherOutputStream = new CipherOutputStream(baos, cipher)) {

            /* process input stream */
            final byte[] buffer = new byte[8192];
            int r;
            while ((r = inputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, r);
                macCalculator.update(buffer, 0, r);
                signer.update(buffer, 0, r);
            }
            cipherOutputStream.flush();


            final ByteString mac = ByteString.copyFrom(macCalculator.doFinal());
            final ByteString signature = ByteString.copyFrom(signer.sign());
            final ByteString ciphertext = BlobfishProto.Blobfish.Body.Payload
                    .newBuilder()
                    .setData(ByteString.copyFrom(baos.toByteArray()))
                    .build()
                    .toByteString();

            return BlobfishProto.Blobfish.Body.Entry.newBuilder()
                    .setCiphertext(ciphertext)
                    .setHmac(mac)
                    .setSignature(signature)
                    .build();
        }
    }
}

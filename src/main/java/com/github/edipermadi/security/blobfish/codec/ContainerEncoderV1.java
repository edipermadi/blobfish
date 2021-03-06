package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.*;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import org.apache.commons.io.output.ByteArrayOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Container Encoder Version 1
 *
 * @author Edi Permadi
 */
class ContainerEncoderV1 extends ContainerEncoderBase implements ContainerEncoder {
    private final CodedOutputStream codedOutputStream;
    private byte[] keyBytes;
    private final AtomicInteger counter = new AtomicInteger(0);
    private final BlobfishProto.Blobfish.Body.Builder bodyBuilder;
    private final BlobfishProto.Blobfish.Header.Builder headerBuilder;

    /**
     * Container Encoder Version 1 Constructor
     *
     * @param builder Container Encoder Builder Instance
     * @throws BlobfishCryptoException when cryptographic exception occurred
     * @throws BlobfishEncodeException whn encoding exception occurred
     */
    ContainerEncoderV1(final ContainerEncoderBuilder builder) throws BlobfishEncodeException, BlobfishCryptoException {
        this(builder, 1, false);
    }

    /**
     * Container Encoder Version 1 Constructor
     *
     * @param builder    Container Encoder Builder Instance
     * @param version    container encoding version
     * @param compressed set to true to enable compression
     * @throws BlobfishCryptoException when cryptographic exception occurred
     * @throws BlobfishEncodeException whn encoding exception occurred
     */
    ContainerEncoderV1(final ContainerEncoderBuilder builder, final int version, final boolean compressed) throws BlobfishCryptoException, BlobfishEncodeException {
        super(builder, version, compressed);

        codedOutputStream = CodedOutputStream.newInstance(builder.outputStream);
        bodyBuilder = BlobfishProto.Blobfish.Body.newBuilder();

        /* create header builder */
        try {
            headerBuilder = BlobfishProto.Blobfish.Header.newBuilder()
                    .setCreated(System.currentTimeMillis())
                    .setSender(BlobfishProto.Blobfish.Header.Sender.newBuilder()
                            .setSigningCertificate(encodeCertificate(builder.signingCertificate))
                            .build());

            /* generate key */
            final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            if (builder.password != null) {
                final byte[] salt = deriveSalt(secureRandom);
                keyBytes = deriveKey(builder.password, salt);

                /* register password entry */
                headerBuilder.setPassword(BlobfishProto.Blobfish.Header.Password.newBuilder()
                        .setIteration(Const.ITERATION_NUMBER)
                        .setSalt(ByteString.copyFrom(salt))
                        .build());
            } else {
                keyBytes = new byte[16];
                secureRandom.nextBytes(keyBytes);
            }

            /* register recipients */
            for (final X509Certificate recipient : builder.recipientCertificates) {
                headerBuilder.addRecipient(BlobfishProto.Blobfish.Header.Recipient.newBuilder()
                        .setCipheredKey(protectKey(secureRandom, keyBytes, recipient))
                        .setHashCertificate(digestCertificate(recipient))
                        .build());
            }
        } catch (final NoSuchAlgorithmException ex) {
            throw new KeyDerivationException(ex);
        }
    }

    @Override
    public ContainerEncoderV1 addBlob(final String path, final Set<String> tags, final String mimeType,
                                      final InputStream inputStream) throws BlobfishCryptoException, BlobfishEncodeException, IOException {
        if ((path == null) || path.isEmpty() || path.endsWith("/") || !path.startsWith("/")) {
            throw new IllegalArgumentException("invalid path");
        } else if (tags == null) {
            throw new IllegalArgumentException("tags is null");
        } else if ((mimeType == null) || mimeType.isEmpty()) {
            throw new IllegalArgumentException("mimetype is null/empty");
        } else if (inputStream == null) {
            throw new IllegalArgumentException("input-stream is null/empty");
        } else if (paths.contains(path)) {
            throw new BlobAlreadyExistException();
        }

        /* encode metadata and payload */
        final byte[] encodedMetadata = encodeMetadata(path, tags, mimeType);
        final byte[] encodedPayload = encodePayload(inputStream);

        try (final ByteArrayInputStream bais1 = new ByteArrayInputStream(encodedMetadata);
             final ByteArrayInputStream bais2 = new ByteArrayInputStream(encodedPayload)) {

            /* create entries */
            final BlobfishProto.Blobfish.Body.Entry metadata = createEntry(bais1);
            final BlobfishProto.Blobfish.Body.Entry payload = createEntry(bais2);

            final int id = counter.getAndIncrement();
            final BlobfishProto.Blobfish.Body.Blob blob = BlobfishProto.Blobfish.Body.Blob.newBuilder()
                    .setId(id)
                    .setMetadata(metadata)
                    .setPayload(payload)
                    .build();
            bodyBuilder.addBlob(blob);
            paths.add(path);
        } catch (final IOException ex) {
            throw new BlobfishEncodeException("failed to encode blob", ex);
        }

        return this;
    }

    @Override
    public void write() throws IOException {
        BlobfishProto.Blobfish.newBuilder()
                .setMagic(Const.MAGIC_CODE)
                .setVersion(version)
                .setBody(bodyBuilder)
                .setHeader(headerBuilder)
                .build()
                .writeTo(codedOutputStream);
        codedOutputStream.flush();
    }

    /**
     * Create blob entry
     *
     * @param inputStream input stream to read plain blob payload
     * @return blobfish body entry
     * @throws BlobfishCryptoException when cryptographic operation occurred
     * @throws BlobfishEncodeException when encoding failed
     */
    private BlobfishProto.Blobfish.Body.Entry createEntry(final InputStream inputStream) throws BlobfishCryptoException, BlobfishEncodeException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        /* initialize cipher */
        final Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, keyBytes, ivBytes);
        final Mac macCalculator = getMac(keyBytes);
        final Signature signer = getSigner(signingPrivateKey);

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
            cipherOutputStream.close();

            /* wrap ciphertext, mac and signature*/
            final ByteString ciphertext = ByteString.copyFrom(baos.toByteArray());
            final ByteString mac = ByteString.copyFrom(macCalculator.doFinal());
            final ByteString signature = ByteString.copyFrom(signer.sign());

            /* encode entry */
            return BlobfishProto.Blobfish.Body.Entry.newBuilder()
                    .setCiphertext(ciphertext)
                    .setHmac(mac)
                    .setSignature(signature)
                    .build();
        } catch (final IOException ex) {
            throw new BlobfishEncodeException("failed to encode blob", ex);
        } catch (final SignatureException ex) {
            throw new SignCalculationException(ex);
        }
    }
}

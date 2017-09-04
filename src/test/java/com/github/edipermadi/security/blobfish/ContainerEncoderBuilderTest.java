package com.github.edipermadi.security.blobfish;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.*;
import java.util.Calendar;

public final class ContainerEncoderBuilderTest {
    private static final int VALIDITY_DAYS = 365;
    private static final String COMMON_NAME = "com.github.edipermadi.security.blobfish.test";

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNegativeVersionIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setVersion(-1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenZeroVersionIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setVersion(0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullSigningCertificateIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setSigningCertificate(null);
    }

//    @Test(expectedExceptions = IllegalArgumentException.class)
//    public void whenRsaSigningCertificateIsGivenThenExceptionThrown() throws NoSuchAlgorithmException {
//        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//        keyGen.initialize(2048);
//
//        final KeyPair keyPair = keyGen.genKeyPair();
//        final PrivateKey privateKey = keyPair.getPrivate();
//        final PublicKey publicKey = keyPair.getPublic();
//
//        final Calendar expiry = Calendar.getInstance();
//        expiry.add(Calendar.DAY_OF_YEAR, VALIDITY_DAYS);
//        final X500Name x509Name = new X500Name("CN=" + COMMON_NAME);
//
//        new ContainerEncoderBuilder()
//                .setSigningCertificate(null);
//    }
}

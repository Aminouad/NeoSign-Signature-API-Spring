package com.NEOledge.SignatureAPI.XadEsServices;

import com.NEOledge.SignatureAPI.PadEsServices.PdfTypePAdES_BASELINE_T;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class XmlTypePAdES_BASELINE_LT {
    public XmlTypePAdES_BASELINE_LT() {

    }

    public DSSDocument signXmlTypePAdES_BASELINE_LT(Pkcs12SignatureToken signingToken, DSSDocument toSignDocument,String type ) throws IOException {
        // Exctract first private key from the keystore for signing.
        List<DSSPrivateKeyEntry> keys = signingToken.getKeys();
        DSSPrivateKeyEntry privateKey = null;
        for (DSSPrivateKeyEntry entry : keys) {
            privateKey = entry;
            break;
        }
        assert privateKey != null;
        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        // We choose the level of the signature (-B, -T, -LT, -LTA).
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
        // We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
        switch (type) {
            case "ENVELOPED," -> {
                parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
            }
            case "ENVELOPING," -> {
                parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            }
            case "DETACHED," -> {
                parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
            }
            default -> parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);



        }

        // We set the digest algorithm to use with the signature algorithm. You must use the
        // same parameter when you invoke the method sign on the token. The default value is SHA256
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        // We set the signing certificate
        parameters.setSigningCertificate(privateKey.getCertificate());
        // We set the certificate chain
        parameters.setCertificateChain(privateKey.getCertificateChain());

        CommonsDataLoader commonsHttpDataLoader = new CommonsDataLoader();
        OCSPDataLoader ocspDataLoader = new OCSPDataLoader();

        KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File("src/main/resources/teststore.p12"), "PKCS12",
                "123456");

        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl("https://ec.europa.eu/tools/lotl/eu-lotl.xml");
        lotlSource.setCertificateSource(keyStoreCertificateSource);
        lotlSource.setPivotSupport(true);

        TrustedListsCertificateSource tslCertificateSource = new TrustedListsCertificateSource();

        FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader(commonsHttpDataLoader);

        CacheCleaner cacheCleaner = new CacheCleaner();
        cacheCleaner.setCleanFileSystem(true);
        cacheCleaner.setDSSFileLoader(onlineFileLoader);

        TLValidationJob validationJob = new TLValidationJob();
        validationJob.setTrustedListCertificateSource(tslCertificateSource);
        validationJob.setOnlineDataLoader(onlineFileLoader);
        validationJob.setCacheCleaner(cacheCleaner);
        validationJob.setListOfTrustedListSources(lotlSource);
        validationJob.onlineRefresh();
        // tag::certificate-verifier[]

        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        CommonsDataLoader commonsDataLoader = new CommonsDataLoader();

// init revocation sources for CRL/OCSP requesting
        commonCertificateVerifier.setCrlSource(new OnlineCRLSource(commonsDataLoader));
        commonCertificateVerifier.setOcspSource(new OnlineOCSPSource());

// Trust anchors should be defined for revocation data requesting
        commonCertificateVerifier.setTrustedCertSources(tslCertificateSource);



        commonCertificateVerifier.setCheckRevocationForUntrustedChains(true);

        final String tspServer = "http://dss.nowina.lu/pki-factory/tsa/good-tsa";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new TimestampDataLoader());
        // Create XAdES service for signature
        XAdESService service = new XAdESService(commonCertificateVerifier);
        // end::certificate-verifier[]
        service.setTspSource(tspSource);

        // Get the SignedInfo XML segment that need to be signed.
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

        // This function obtains the signature value for signed information using the
        // private key and specified algorithm
        SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

        // We invoke the service to sign the document with the signature value obtained in
        // the previous step.
        DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
        return  signedDocument;
    }

}

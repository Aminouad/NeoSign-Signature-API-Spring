package com.NEOledge.SignatureAPI.XadEsServices;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.util.List;

public class XmlTypePAdES_BASELINE_B {
    public XmlTypePAdES_BASELINE_B() {

    }
    public DSSDocument signXmlTypePAdES_BASELINE_B(Pkcs12SignatureToken signingToken, DSSDocument toSignDocument,String type ){
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
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
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



        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        XAdESService service = new XAdESService(commonCertificateVerifier);
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
        //for the PAdES_BASELINE_T
        // Create signature and attach it to the PDF file.
        SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
        DSSDocument signedFile = service.signDocument(toSignDocument, parameters, signatureValue);
        return  signedFile;
    }

}

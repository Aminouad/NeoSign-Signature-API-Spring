package com.NEOledge.SignatureAPI.PadEsServices;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
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

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.util.List;

public class PdfTypePAdES_BASELINE_LTA {
    public PdfTypePAdES_BASELINE_LTA(){

    }
    public DSSDocument signPdfTypePAdES_BASELINE_LTA(String pathCertificate,String password, DSSDocument toSignDocument,Boolean visible,String imgSignature,String label) throws IOException {
        // Exctract first private key from the keystore for signing.

        Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken(pathCertificate, new KeyStore.PasswordProtection(password.toCharArray()));

        List<DSSPrivateKeyEntry> keys = signingToken.getKeys();
        DSSPrivateKeyEntry privateKey = null;
        for (DSSPrivateKeyEntry entry : keys) {
            privateKey = entry;
            break;
        }
        CertificateToken signerCert = privateKey.getCertificate();
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
        parameters.setSigningCertificate(signerCert);
        parameters.setCertificateChain(privateKey.getCertificateChain());
//
        CommonsDataLoader commonsHttpDataLoader = new CommonsDataLoader();
        OCSPDataLoader ocspDataLoader = new OCSPDataLoader();

        KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File(pathCertificate), "PKCS12",
                password);

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

        //
        //for the PAdES_BASELINE_T

        //for visible signature
        // We set the signing certificate
        parameters.setSigningCertificate(privateKey.getCertificate());
// We set the certificate chain
        parameters.setCertificateChain(privateKey.getCertificateChain());
        if(visible) {
// Initialize visual signature and configure
            SignatureImageParameters imageParameters = new SignatureImageParameters();
// set an image
            imageParameters.setImage(new FileDocument(new File(imgSignature)));
            Color transparent = new Color(0, 0, 0, 0.01f);

// initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            imageParameters.setFieldParameters(fieldParameters);
// the origin is the left and top corner of the page
            fieldParameters.setOriginX(350);
            fieldParameters.setOriginY(620);
            fieldParameters.setWidth(200);
            fieldParameters.setHeight(200);
            DSSFont font = new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSans-VariableFont_wdth,wght.ttf"));
            // end::font[]
            // tag::text[]
            // Instantiates a SignatureImageTextParameters object
            SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
            // Allows you to set a DSSFont object that defines the text style (see more information in the section "Fonts usage")
            textParameters.setFont(font);
            // Defines the text content
            textParameters.setText(label);
            // Defines the color of the characters
            textParameters.setTextColor(Color.BLACK);
            // Defines the background color for the area filled out by the text
            textParameters.setBackgroundColor(transparent);
            // Defines a padding between the text and a border of its bounding area
            textParameters.setPadding(10);
            // TextWrapping parameter allows defining the text wrapping behavior within  the signature field
			/*
			  FONT_BASED - the default text wrapping, the text is computed based on the given font size;
			  FILL_BOX - finds optimal font size to wrap the text to a signature field box;
			  FILL_BOX_AND_LINEBREAK - breaks the words to multiple lines in order to find the biggest possible font size to wrap the text into a signature field box.
			*/
            textParameters.setTextWrapping(TextWrapping.FONT_BASED);
            // Set textParameters to a SignatureImageParameters object
            imageParameters.setTextParameters(textParameters);
            // end::text[]
            // tag::textImageCombination[]
            // Specifies a text position relatively to an image (Note: applicable only for joint image+text visible signatures).
            // Thus with _SignerPosition.LEFT_ value, the text will be placed on the left side,
            // and image will be aligned to the right side inside the signature field
            textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
            // Specifies a horizontal alignment of a text with respect to its area
            textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
            // Specifies a vertical alignment of a text block with respect to a signature field area
            textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);

            parameters.setImageParameters(imageParameters);
        }

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
        // For test purpose (not recommended for use in production)
        // Will request unknown OCSP responder / download untrusted CRL
        PAdESService service = new PAdESService(commonCertificateVerifier);
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
        //for the PAdES_BASELINE_T
        service.setTspSource(tspSource);



        // Create signature and attach it to the PDF file.
        SignatureValue signatureValue = signingToken.sign(dataToSign, DigestAlgorithm.SHA256, privateKey);
        DSSDocument signedFile = service.signDocument(toSignDocument, parameters, signatureValue);
        return  signedFile;
    };

}

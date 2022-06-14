package com.NEOledge.SignatureAPI.PadEsServices;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.awt.*;
import java.io.File;
import java.util.List;

public class PdfTypePAdES_BASELINE_T {
    public PdfTypePAdES_BASELINE_T() {

    }


    public  DSSDocument signPdfTypePAdES_BASELINE_T(Pkcs12SignatureToken signingToken, DSSDocument toSignDocument,Boolean visible,String imgSignature,String label){
        // Exctract first private key from the keystore for signing.
        List<DSSPrivateKeyEntry> keys = signingToken.getKeys();
        DSSPrivateKeyEntry privateKey = null;
        for (DSSPrivateKeyEntry entry : keys) {
            privateKey = entry;
            break;
        }
        CertificateToken signerCert = privateKey.getCertificate();
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        parameters.setSigningCertificate(signerCert);
        parameters.setCertificateChain(privateKey.getCertificateChain());

        //for the PAdES_BASELINE_T
        OnlineTSPSource tsa2 = new OnlineTSPSource("http://timestamp.sectigo.com");
     if(visible){


        SignatureImageParameters imageParameters = new SignatureImageParameters();
// set an image
        //imageParameters.setImage(new InMemoryDocument(Objects.requireNonNull(getClass().getResourceAsStream("resources/img/sign.png"))));
// initialize signature field parameters
       // imageParameters.setImage(new FileDocument(new File("src/main/resources/img/sign.png")));
         imageParameters.setImage(new FileDocument(new File(imgSignature)));
        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        Color transparent = new Color(0, 0, 0, 0.01f);
        imageParameters.setFieldParameters(fieldParameters);

// the origin is the left and top corner of the page
        fieldParameters.setOriginX(350);
        fieldParameters.setOriginY(680);
        fieldParameters.setWidth(200);
        fieldParameters.setHeight(150);
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
        PAdESService service = new PAdESService(commonCertificateVerifier);
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
        //for the PAdES_BASELINE_T
        service.setTspSource(tsa2);
        // Create signature and attach it to the PDF file.
        SignatureValue signatureValue = signingToken.sign(dataToSign, DigestAlgorithm.SHA256, privateKey);
        DSSDocument signedFile = service.signDocument(toSignDocument, parameters, signatureValue);
         return  signedFile;
    };

}

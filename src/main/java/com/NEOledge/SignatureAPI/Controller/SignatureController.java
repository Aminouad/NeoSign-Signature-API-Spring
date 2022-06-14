package com.NEOledge.SignatureAPI.Controller;

import com.NEOledge.SignatureAPI.PadEsServices.PdfTypePAdES_BASELINE_B;
import com.NEOledge.SignatureAPI.PadEsServices.PdfTypePAdES_BASELINE_LT;
import com.NEOledge.SignatureAPI.PadEsServices.PdfTypePAdES_BASELINE_LTA;
import com.NEOledge.SignatureAPI.PadEsServices.PdfTypePAdES_BASELINE_T;
import com.NEOledge.SignatureAPI.XadEsServices.XmlTypePAdES_BASELINE_B;
import com.NEOledge.SignatureAPI.XadEsServices.XmlTypePAdES_BASELINE_LT;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.Objects;

@RestController
public class SignatureController {
    private static final Logger logger = LoggerFactory.getLogger(SignatureController.class);

    private File convertMultiPartToFile(MultipartFile file) throws IOException {
        File convFile = new File(Objects.requireNonNull(file.getOriginalFilename()));
        FileOutputStream fos = new FileOutputStream(convFile);
        fos.write(file.getBytes());
        fos.close();
        return convFile;
    }

    @PostMapping("/api/sign-pdf")
    public ResponseEntity<InputStreamResource> signPdf(@RequestParam(name = "document", required = true) MultipartFile document,
                                                                @RequestParam(name = "pathCertificate", required = true) String pathCertificate,
                                                                @RequestParam(name = "password", required = true) String password,
                                                                @RequestParam(name = "typeOfSignature", required = true) String typeOfSignature,
                                                                @RequestParam(name = "pathImageCertificate", required = true) String pathImageCertificate,
                                                                @RequestParam(name = "nature", required = true) String nature,
                                                                @RequestParam(name = "label", required = true) String label)
            throws Exception {
        Boolean visible ;
        logger.info("Starting to sign file");
         if(nature.equals("visible")){
             visible=true;
         }
         else {
             visible=false;
         }
        DSSDocument toSignDocument = new FileDocument(convertMultiPartToFile(document));
        DSSDocument signedFile ;

        Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken(pathCertificate, new KeyStore.PasswordProtection(password.toCharArray()));
        switch (typeOfSignature) {
            case "PAdES_BASELINE_T," -> {
                PdfTypePAdES_BASELINE_T pdfTypePAdES_baseline_T = new PdfTypePAdES_BASELINE_T();
                signedFile = pdfTypePAdES_baseline_T.signPdfTypePAdES_BASELINE_T(signingToken, toSignDocument, visible, pathImageCertificate, label);
            }
            case "PAdES_BASELINE_B," -> {
                PdfTypePAdES_BASELINE_B pdfTypePAdES_baseline_B = new PdfTypePAdES_BASELINE_B();
                signedFile = pdfTypePAdES_baseline_B.signPdfTypePAdES_BASELINE_B(signingToken, toSignDocument, visible, pathImageCertificate, label);
            }
            case "PAdES_BASELINE_LT," -> {
                PdfTypePAdES_BASELINE_LT pdfTypePAdES_baseline_LT = new PdfTypePAdES_BASELINE_LT();
                signedFile = pdfTypePAdES_baseline_LT.signPdfTypePAdES_BASELINE_LT(signingToken, toSignDocument, visible, pathImageCertificate, label);
            }
            case "PAdES_BASELINE_LTA," -> {
                PdfTypePAdES_BASELINE_LTA pdfTypePAdES_baseline_LTA = new PdfTypePAdES_BASELINE_LTA();
                signedFile = pdfTypePAdES_baseline_LTA.signPdfTypePAdES_BASELINE_LTA(pathCertificate, password, toSignDocument, visible, pathImageCertificate, label);
            }
            default -> signedFile = null;
        }


        InputStreamResource resource = new InputStreamResource(signedFile.openStream());

        logger.info("File signed, downloading...");
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed-pdf.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(resource);


    }
    @PostMapping("/api/sign-xml")
    public ResponseEntity<InputStreamResource> signXml(@RequestParam(name = "document", required = true) MultipartFile document,
                                                                @RequestParam(name = "pathCertificate", required = true) String pathCertificate,
                                                                @RequestParam(name = "password", required = true) String password,
                                                                @RequestParam(name = "typeOfSignature", required = true) String typeOfSignature,
                                                                @RequestParam(name = "levelOfSignature", required = true) String levelOfSignature)
            throws Exception {
        logger.info("Starting to sign file");

        DSSDocument toSignDocument = new FileDocument(convertMultiPartToFile(document));
        DSSDocument signedFile ;

        Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken(pathCertificate, new KeyStore.PasswordProtection(password.toCharArray()));
        switch (levelOfSignature) {
            case "XAdES_BASELINE_T," -> {
                PdfTypePAdES_BASELINE_T pdfTypePAdES_baseline_T = new PdfTypePAdES_BASELINE_T();
                signedFile = pdfTypePAdES_baseline_T.signPdfTypePAdES_BASELINE_T(signingToken, toSignDocument, false, null, null);
            }
            case "XAdES_BASELINE_B," -> {
                XmlTypePAdES_BASELINE_B xmlTypePAdES_baseline_B = new XmlTypePAdES_BASELINE_B();
                signedFile = xmlTypePAdES_baseline_B.signXmlTypePAdES_BASELINE_B(signingToken, toSignDocument,typeOfSignature);
            }
            case "XAdES_BASELINE_LT," -> {
                XmlTypePAdES_BASELINE_LT xmlTypePAdES_BASELINE_LT = new XmlTypePAdES_BASELINE_LT();
                signedFile = xmlTypePAdES_BASELINE_LT.signXmlTypePAdES_BASELINE_LT(signingToken, toSignDocument,typeOfSignature);
            }
            case "XAdES_BASELINE_LTA," -> {
                PdfTypePAdES_BASELINE_LTA pdfTypePAdES_baseline_LTA = new PdfTypePAdES_BASELINE_LTA();
                signedFile = pdfTypePAdES_baseline_LTA.signPdfTypePAdES_BASELINE_LTA(pathCertificate, password, toSignDocument, false, null, null);
            }
            default -> signedFile = null;
        }


        InputStreamResource resource = new InputStreamResource(signedFile.openStream());

        logger.info("File signed, downloading...");
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed-xml.xml")
                .contentType(MediaType.APPLICATION_XML)
                .body(resource);


    }
}

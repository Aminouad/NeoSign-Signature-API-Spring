package com.NEOledge.SignatureAPI;

import com.NEOledge.SignatureAPI.Services.PdfTypePAdES_BASELINE_T;
import eu.europa.esig.dss.model.*;

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

@RestController
public class PAdESController {
    private File convertMultiPartToFile(MultipartFile file) throws IOException {
        File convFile = new File(file.getOriginalFilename());
        FileOutputStream fos = new FileOutputStream(convFile);
        fos.write(file.getBytes());
        fos.close();
        return convFile;
    }

    private static final Logger logger = LoggerFactory.getLogger(PAdESController.class);

    @PostMapping("/api/sign-pdf")
    public ResponseEntity<InputStreamResource> getTest(@RequestParam(name = "document", required = true) MultipartFile document, @RequestParam(name = "pathCertificate", required = true) String pathCertificate, @RequestParam(name = "password", required = true) String password
    ) throws Exception {
        logger.info("Starting to sign file");


        DSSDocument toSignDocument = new FileDocument(convertMultiPartToFile(document));

        Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken(pathCertificate, new KeyStore.PasswordProtection(password.toCharArray()));

        //PdfTypePAdES_BASELINE_T pdfTypePAdES_baseline_t = new PdfTypePAdES_BASELINE_T();
        //DSSDocument signedFile=pdfTypePAdES_baseline_t.signPdfTypePAdES_BASELINE_T(signingToken,toSignDocument);
        //PdfTypePAdES_BASELINE_LT pdfTypePAdES_baseline_LT = new PdfTypePAdES_BASELINE_LT();
       // DSSDocument signedFile=pdfTypePAdES_baseline_LT.signPdfTypePAdES_BASELINE_LT(signingToken,toSignDocument);
        PdfTypePAdES_BASELINE_T pdfTypePAdES_baseline_T = new PdfTypePAdES_BASELINE_T();
        DSSDocument signedFile=pdfTypePAdES_baseline_T.signPdfTypePAdES_BASELINE_T(signingToken,toSignDocument);

        InputStreamResource resource = new InputStreamResource(signedFile.openStream());

        logger.info("File signed, downloading...");
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed-pdf.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(resource);
    }
}

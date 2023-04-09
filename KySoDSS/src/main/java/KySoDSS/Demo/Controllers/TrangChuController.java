package KySoDSS.Demo.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;
//
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.poifs.crypt.HashAlgorithm;
//
import org.apache.poi.util.Units;
import org.apache.poi.xwpf.usermodel.*;
import org.openxmlformats.schemas.drawingml.x2006.picture.CTPicture;
import org.openxmlformats.schemas.drawingml.x2006.main.CTPoint2D;

@Controller
public class TrangChuController {
    @GetMapping("/")
    public ModelAndView viewTrangChu() {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("index");
        mv.addObject("mess", null);
        mv.addObject("messss", null);
        return mv;
    }
    // Tạo cặp khóa và tải xuống
    @GetMapping("/createkey")
    public ResponseEntity<?> downloadFiles() throws Exception {
        // Get the files to be downloaded
        List<byte[]> list = generateRSAKeyPair();
        // List<File> files = getFilesToDownload();
        // Create a zip file containing the files
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        try {
            for (int i = 0; i < list.size(); i++) {
                if (i == 0) {
                    zos.putNextEntry(new ZipEntry("publickey"));
                } else {
                    zos.putNextEntry(new ZipEntry("private"));
                }
                zos.write(list.get(i));
                zos.closeEntry();
            }
            zos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Set the response headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDisposition(ContentDisposition.attachment().filename("key.zip").build());
        // Return the response entity with the zip file
        return ResponseEntity.ok()
                .headers(headers)
                .contentLength(baos.toByteArray().length)
                .body(new ByteArrayResource(baos.toByteArray()));
    }

    // Tạo File ký số và download
    @PostMapping("/digitalsignature")
    public ResponseEntity<?> uploadFile(@RequestParam("filePrivate") MultipartFile filePrivate,
            @RequestParam("fileSign") MultipartFile fileSign) throws Exception {
        // Get the file name
        // String fileName = file.getOriginalFilename();
        // String fileName1 = file1.getOriginalFilename();
        // System.out.println(fileName+fileName1);
        // Read the file contents as a byte array
        byte[] fileContent;
        byte[] fileContent1;
        byte[] data = null;
        if (CheckPrivateKey(filePrivate.getBytes()) == null) {
            return ResponseEntity.ok()
                    .body(false);
        }
        try {
            fileContent = filePrivate.getBytes();
            fileContent1 = fileSign.getBytes();
            data = CreateSign1(fileContent, fileContent1);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok().body(data);
    }

    public PrivateKey CheckPrivateKey(byte[] priv) {
        PrivateKey pr = null;
        try {
            // Kiểm tra định dạng private key
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(priv);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pr = kf.generatePrivate(spec);
            System.out.println("This is private key RSA");
        } catch (Exception e2) {
            System.out.println("This isn't private key RSA");
        }
        return pr;
    }

    public PublicKey CheckPublicKey(byte[] pub) {
        PublicKey pr = null;
        try {
            // Kiểm tra định dạng public key
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pub);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pr = kf.generatePublic(spec);
            System.out.println("This is public key RSA");
        } catch (Exception e1) {
            System.out.println("This isn't public key RSA");
        }
        return pr;
    }

    

    // Xác thực Chữ Ký Số
    @PostMapping("/verifyDS")
    public ResponseEntity<?> Digitalsignatureverification(@RequestParam("filePublic") MultipartFile filePublic,
            @RequestParam("fileverify") MultipartFile fileverify,
            @RequestParam("fileSignature") MultipartFile fileSignature) throws Exception {
        // ModelAndView mv = new ModelAndView();
        boolean check = true;
        byte[] fileContent;
        byte[] fileContent1;
        byte[] fileContent2;
        byte[] data = null;
        try {
            fileContent = filePublic.getBytes();
            fileContent1 = fileverify.getBytes();
            fileContent2 = fileSignature.getBytes();
            File file = new File("KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\ticked.png");
            FileInputStream fis = new FileInputStream(file);
            byte[] img = new byte[(int) file.length()];
            // đọc dữ liệu từ FileInputStream vào mảng byteArray
            fis.read(img);
            fis.close();
            //
            check = verifyy(fileContent, fileContent1, fileContent2);
            if(check == true)
            {
                data = createFile(img,fileContent1);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok().body(data);
    }

    public boolean verifyy(byte[] PublicKey, byte[] Input, byte[] Signature) throws Exception {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(PublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        boolean verifies = verifyDigitalSignature(Input, Signature, pubKey);
        System.out.println("Authentication Signature: " + verifies);
        return verifies;
    }

    public static boolean verifyDigitalSignature(byte[] input, byte[] signatureToVerify, PublicKey key)
            throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(input);
        return sig.verify(signatureToVerify);
    }

    public byte[] CreateSign1(byte[] PrivateKey, byte[] DS) throws Exception {
        PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(PrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFactory.generatePrivate(pubKeySpec);
        /* Create a Signature object and initialize it with the private key */
        Signature dsa = Signature.getInstance("SHA256withRSA");
        dsa.initSign(priv);
        dsa.update(DS);
        byte[] realSig = dsa.sign();
        /* Save the signature in a file */
        // FileOutputStream sigfos = new FileOutputStream("KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\signature.txt");
        // sigfos.write(realSig);
        // sigfos.close();
        return realSig;
    }

    /* Tạo cặp khóa(key pair)*/
    public static List<byte[]> generateRSAKeyPair() throws Exception {
        SecureRandom sr = new SecureRandom();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, sr);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey priv = keyPair.getPrivate();
        PublicKey pub = keyPair.getPublic();
        byte[] key = pub.getEncoded();
        // FileOutputStream keyfos = new FileOutputStream("KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\publickey.txt");
        // keyfos.write(key);
        // keyfos.close();

        byte[] privKey = priv.getEncoded();
        // FileOutputStream filePrivate = new FileOutputStream(
        // "KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\privatekey.txt");
        // filePrivate.write(privKey);
        // filePrivate.close();
        List<byte[]> list = new ArrayList<>();
        list.add(key);
        list.add(privKey);
        return list;
    }
    // Tạo file và lưu
    public byte[] createFile(byte[] Moc, byte[] Hopdong) throws InvalidFormatException {
        byte[] data = null;
        try {
            // Tạo đối tượng XWPFDocument để đọc file Word đã có sẵn nội dung
            InputStream in = new ByteArrayInputStream(Hopdong);
            XWPFDocument document = new XWPFDocument(in);
    
            // Tạo đối tượng XWPFParagraph để chèn dấu mộc vào văn bản của file Word
            XWPFParagraph paragraph = document.createParagraph();
    
            // Tạo đối tượng XWPFRun để chèn dấu mộc vào văn bản của file Word
            XWPFRun run = paragraph.createRun();
    
            // Tạo đối tượng XWPFPicture để thêm dấu mộc vào file Word
            InputStream mocInputStream = new ByteArrayInputStream(Moc);
            XWPFPicture moc = run.addPicture(mocInputStream, XWPFDocument.PICTURE_TYPE_PNG, "moc.png", Units.toEMU(80), Units.toEMU(40));
    
            // Thiết lập vị trí của dấu mộc
            int x = Units.toEMU(10);
            int y = Units.toEMU(5);
            CTPicture ctMoc = moc.getCTPicture();
            CTPoint2D newOff = CTPoint2D.Factory.newInstance();
            newOff.setX(x);
            newOff.setY(y);
            ctMoc.getSpPr().getXfrm().setOff(newOff);
    
            // Bảo vệ file Word tránh bị chỉnh sửa
            document.enforceReadonlyProtection("5995@@", HashAlgorithm.sha256);
    
            // Lưu file Word đã thêm dấu mộc ra file mới
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.write(out);
            data = out.toByteArray();
    
            // Đóng luồng
            out.close();
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return data;
    }
    
}

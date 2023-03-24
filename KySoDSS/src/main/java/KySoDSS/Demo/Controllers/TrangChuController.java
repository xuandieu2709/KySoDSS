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

    // @GetMapping
    // public void Dowload(HttpServletResponse response) throws IOException{
    // generateRSAKeyPair();
    // try {
    // File file = ResourceUtils.getFile("classpath:file/publickey.txt");
    // byte[] data = FileUtils.readFileToByteArray(file);
    // // Thiết lập thông tin trả về
    // response.setContentType("application/octet-stream");
    // response.setHeader("Content-disposition", "attachment; filename=" +
    // file.getName());
    // response.setContentLength(data.length);
    // InputStream inputStream = new BufferedInputStream(new
    // ByteArrayInputStream(data));
    // FileCopyUtils.copy(inputStream, response.getOutputStream());
    // } catch (Exception ex) {
    // ex.printStackTrace();
    // }
    // }
    // public ResponseEntity<InputStreamResource> downloadPublic() throws
    // IOException {
    // Resource resource =
    // resourceLoader.getResource("classpath:KySoDSS/Demo/file/publickey.txt");
    // InputStream inputStream = new
    // ByteArrayInputStream(resource.getInputStream().readAllBytes());

    // HttpHeaders headers = new HttpHeaders();
    // headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment;
    // filename=publickey.txt");
    // headers.add(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE);

    // InputStreamResource inputStreamResource = new
    // InputStreamResource(inputStream);
    // return ResponseEntity.ok()
    // .headers(headers)
    // .contentLength(resource.contentLength())
    // .contentType(MediaType.TEXT_PLAIN)
    // .body(inputStreamResource);
    // }
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
                    zos.putNextEntry(new ZipEntry("publickey.txt"));
                } else {
                    zos.putNextEntry(new ZipEntry("private.txt"));
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
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file,
            @RequestParam("file1") MultipartFile file1) throws Exception {
        // Get the file name
        // String fileName = file.getOriginalFilename();
        // String fileName1 = file1.getOriginalFilename();
        // System.out.println(fileName+fileName1);
        // Read the file contents as a byte array
        byte[] fileContent;
        byte[] fileContent1;
        byte[] data = null;
        // if (CheckPrivateKey(file.getBytes()) == null) {
        //     ModelAndView modelAndView = new ModelAndView();
        //     modelAndView.addObject("messss", true);
        //     modelAndView.setViewName("index");

        //     // HttpHeaders headers = new HttpHeaders();
        //     // headers.add("Location", "/");
        //     // headers.add("Content-Type", "text/html");

        //     return ResponseEntity.ok()
        //             .body(modelAndView);
        // }
        try {
            fileContent = file.getBytes();
            fileContent1 = file1.getBytes();
            data = CreateSign1(fileContent, fileContent1);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return download(data);
    }

    public PrivateKey CheckPrivateKey(byte[] priv) {
        PrivateKey pr = null;
        try {
            // Kiểm tra định dạng private key
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(priv);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pr = kf.generatePrivate(spec);
            System.out.println("Đây là private key RSA");
        } catch (Exception e2) {
            System.out.println("Không phải là private key RSA");
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
            System.out.println("Đây là public key RSA");
        } catch (Exception e1) {
            System.out.println("Không phải là public key RSA");
        }
        return pr;
    }

    // Test Xác Thực
    // @GetMapping("/verifyDSs")
    // public String xacthuc() throws Exception {
    //     String str = "KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\publickey.txt";
    //     String str1 = "KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\xd.png";
    //     String str2 = "KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\signature.txt";
    //     verify(str, str1, str2);
    //     return "index";
    // }

    // Xác thực Chữ Ký Số
    @PostMapping("/verifyDS")
    public ModelAndView Digitalsignatureverification(@RequestParam("filePublic") MultipartFile filePublic,
            @RequestParam("fileverify") MultipartFile fileverify,
            @RequestParam("fileSignature") MultipartFile fileSignature) throws Exception {
        // Get the file name
        // String fileName = file.getOriginalFilename();
        // String fileName1 = file1.getOriginalFilename();
        // System.out.println(fileName+fileName1);
        // Read the file contents as a byte array
        ModelAndView mv = new ModelAndView();
        boolean check = true;
        byte[] fileContent;
        byte[] fileContent1;
        byte[] fileContent2;
        try {
            fileContent = filePublic.getBytes();
            fileContent1 = fileverify.getBytes();
            fileContent2 = fileSignature.getBytes();
            check = verifyy(fileContent, fileContent1, fileContent2);
        } catch (IOException e) {
            e.printStackTrace();
        }
        mv.addObject("mess", check);
        mv.setViewName("index :: h2#mess");
        return mv;
    }

    public ResponseEntity<Resource> download(byte[] data) throws IOException {
        // Assume I already have this byte array
        ByteArrayResource resource = new ByteArrayResource(data);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signature.txt");
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE);
        return ResponseEntity.ok()
                .headers(headers)
                .contentLength(data.length)
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }
    /* Tạo cặp(key pair) key c */
    public static List<byte[]> generateRSAKeyPair() throws Exception {
        SecureRandom sr = new SecureRandom();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, sr);
        KeyPair keyPair = kpg.generateKeyPair();

        PrivateKey priv = keyPair.getPrivate();
        PublicKey pub = keyPair.getPublic();

        byte[] key = pub.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\publickey.txt");
        keyfos.write(key);
        keyfos.close();

        byte[] privKey = priv.getEncoded();
        FileOutputStream filePrivate = new FileOutputStream(
                "KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\privatekey.txt");
        filePrivate.write(privKey);
        filePrivate.close();
        List<byte[]> list = new ArrayList<>();
        list.add(key);
        list.add(privKey);
        return list;
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
        FileOutputStream sigfos = new FileOutputStream("KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\signature.txt");
        sigfos.write(realSig);
        sigfos.close();
        return realSig;
    }
    // ######## Bỏ   ##########

    // public ResponseEntity<InputStreamResource> downloadPrivate() throws
    // IOException {
    // Resource resource =
    // resourceLoader.getResource("classpath:KySoDSS/Demo/file/privatekey.txt");
    // InputStream inputStream = new
    // ByteArrayInputStream(resource.getInputStream().readAllBytes());

    // HttpHeaders headers = new HttpHeaders();
    // headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment;
    // filename=privatekey.txt");
    // headers.add(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE);

    // InputStreamResource inputStreamResource = new
    // InputStreamResource(inputStream);
    // return ResponseEntity.ok()
    // .headers(headers)
    // .contentLength(resource.contentLength())
    // .contentType(MediaType.TEXT_PLAIN)
    // .body(inputStreamResource);
    // }

    public boolean verifyy(byte[] PublicKey, byte[] Input, byte[] Signature) throws Exception {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(PublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        boolean verifies = verifyDigitalSignature(Input, Signature, pubKey);
        System.out.println("Chữ ký số xác thực: " + verifies);
        return verifies;
    }

    public static boolean verifyDigitalSignature(byte[] input, byte[] signatureToVerify, PublicKey key)
            throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(input);
        return sig.verify(signatureToVerify);
    }

    @Autowired
    private ResourceLoader resourceLoader;

    public ResponseEntity<InputStreamResource> downloadDS() throws IOException {
        Resource resource = resourceLoader.getResource("classpath:KySoDSS/Demo/file/signature.txt");
        InputStream inputStream = new ByteArrayInputStream(resource.getInputStream().readAllBytes());
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signature.txt");
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE);

        InputStreamResource inputStreamResource = new InputStreamResource(inputStream);
        return ResponseEntity.ok()
                .headers(headers)
                .contentLength(resource.contentLength())
                .contentType(MediaType.TEXT_PLAIN)
                .body(inputStreamResource);
    }

    /* Tạo chữ ký số từ 2 file private và file hợp đồng */
    public void CreateSign(String pathPrivateKey, String pathHongDong) throws Exception {
        FileInputStream keyfis = new FileInputStream(pathPrivateKey);
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);
        keyfis.close();
        PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(encKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFactory.generatePrivate(pubKeySpec);
        /* Create a Signature object and initialize it with the private key */
        Signature dsa = Signature.getInstance("SHA256withRSA");
        dsa.initSign(priv);
        /* Update and sign the data */
        FileInputStream fis = new FileInputStream(pathHongDong);
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while (bufin.available() != 0) {
            len = bufin.read(buffer);
            dsa.update(buffer, 0, len);
        }
        ;
        bufin.close();
        /*
         * Now that all the data to be signed has been read in,
         * generate a signature for it
         */
        byte[] realSig = dsa.sign();
        /* Save the signature in a file */
        FileOutputStream sigfos = new FileOutputStream("KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\signature.txt");
        sigfos.write(realSig);
        sigfos.close();
    }

    // new func

    public void verify(String pathPublicKey, String pathHopDong, String pathSignature) throws Exception {
        /* import encoded public key */
        FileInputStream keyfis = new FileInputStream(pathPublicKey);
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);
        keyfis.close();
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        boolean verifies = verifyDigitalSignature(convertFileToByteArray(new File(pathHopDong)),
                convertFileToByteArray(new File(pathSignature)), pubKey);
        System.out.println("Chữ ký số xác thực: " + verifies);
    }

    public static byte[] convertFileToByteArray(File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        byte[] byteArray = new byte[(int) file.length()];
        fis.read(byteArray);
        fis.close();
        return byteArray;
    }

    private List<File> getFilesToDownload() {
        // Create a list of files to download
        List<File> files = new ArrayList<>();
        // Add the files to the list
        File file1 = new File("KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\publickey.txt");
        File file2 = new File("KySoDSS\\src\\main\\java\\KySoDSS\\Demo\\file\\privatekey.txt");
        files.add(file1);
        files.add(file2);
        return files;
    }
}

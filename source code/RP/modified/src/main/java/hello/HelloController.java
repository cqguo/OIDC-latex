package hello;

import Bean.*;
import Tools.Util;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.google.gson.Gson;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@RestController
public class HelloController {

    long start, end, point1, point2, point3, point4, point5, point6, point7;
    int count = 0;
    long totalNegotiation = 0;
    long totalRegistration = 0;
    long totalTokenObtaining = 0;
    long serverClientIDGenerate ;
    long clientClientIDGenerate ;
    long serverRegistration ;
    long IdPRegistration ;
    long clientRegistration ;
    long serverAuthorization ;
    long IdPAuthorization ;
    long clientAuthorization ;
    long totalNetCost;
    String RPCert = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJiYXNpY19SUF9pZCI6IjgwNjUwNTYzMzg1OTUwMDQyNjM4NDk1NTg1NDU1OTE2OTkzNTc1MDEwNjUwMTI3MjM4NjA5ODk3NjMzNDIxNzY2ODI1NjcxMDI5MzIzOTA0MzA2MDczMTU0ODA1MTUwMDE4MDA2OTA4ODcwNjAzMjg1MjUzOTE4NDYzNTQzMzM4MDM5NTU0ODUxNjk4NjAxMjA4MDY4NzUyNTg1NTI1NjIwODA3NTI4ODIwNzQ2NDQ3ODU5MTM1MTgwNTgzMzQzMzQyODIxNjM4ODU0ODMwNzE3NTgwMjgyNDA0ODY5MjQyMjAxNzE0Mjk1Njc2Mzg1MDAwMzAwNDIzNzU3NjM2NDA4NDUxODcwMDQzMTA4MzkxMDY4MzY2NDI3ODEyNzA3NDc1MzQxNTE0MjMxNzU5MDMzOTc0NTQzMTk2MjgyNDkwNjk0MjgwODEyMzQ0Mjc3MTM2OTE1NDYzNDUxNTYxMzU5NjAwNjMwNDU0MTQxMTU1NjMxMzc0NjAzNDUwNTI5MzQyNzIwOTU2MjkyNjAxMzYwMzc1MzM4NTI4MDM0NDc1OTI1ODgzMzEzMjMzOTkzODAwNzM2OTE5NTIwMjMxNzU2MTA1OTUyNTMwMzA0MTkxMzkxNTc3MTc5NzY2MzU5MjE1ODA5MjY5NTAzMzM2NDY5NTU5MDUwNzc0NzE0Mzk2ODU4OTgzNDYxODA4MDA4NjMyOTA3MjMxNTQ3OTc4NjUyNjY2OTIyNzg5MzkyNzYyNDY1MTYyMDE2MDYyNjk2NjU4NzA1MTIzMDE2OTk2MTIyMzczNzk1MTc3ODUzMjE0MjMzOTQ5NDkiLCJJZFAiOiJPSURDIiwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDkwLyIsImlhdCI6MTUxNjIzOTAyMn0.a0JmPTfE9zsubGEaMDJaZO2cjY6sZJgHVf2PlgnE8JUNtuWiQBBDiBrF1PhQx5jnEnE8ceN5ngWTQRFHcca2Xv0P7+mljKJ9L9xpJZ2dLYSdE94wgUTRMk+/WJm9clPLmY/C+Pc9J0YC+F/yX4rGq0h7VEuFiT1UTIMqe0gN/+wise2OSobyIh+A5b2X7yuxrgj7uWtA8iVI+19OxcfO+LRvpATsXKhGXD/lVXxTtLCvz1E/8hjZczrpNfn2FcxoTEXh0UQNck10/0/JrQxuxSCZplZEtI+O1TEKIM1rSIwPBOfqhqAHCpoAzYhmJWiBXgQea2z4cDV8FXN/O140aw==";
    String e = "AQAB";
    String n = "qt6yOiI_wCoCVlGO0MySsez0VkSqhPvDl3rfabOslx35mYEO-n4ABfIT5Gn2zN-CeIcOZ5ugAXvIIRWv5H55-tzjFazi5IKkOIMCiz5__MtsdxKCqGlZu2zt-BLpqTOAPiflNPpM3RUAlxKAhnYEqNha6-allPnFQupnW_eTYoyuzuedT7dSp90ry0ZcQDimntXWeaSbrYKCj9Rr9W1jn2uTowUuXaScKXTCjAmJVnsD75JNzQfa8DweklTyWQF-Y5Ky039I0VIu-0CIGhXY48GAFe2EFb8VpNhf07DP63p138RWQ1d3KPEM9mYJVpQC68j3wzDQYSljpLf9by7TGw";

//    BigInteger P = new BigInteger("31355180255069932180092993243707535038808256836405857250770313981784764154020063644880886309980151531761806343359442224283100564956433958357546569743359323403739799143711658486350818704556237746628503296034608346067569333784947560482588070651916161275498198576485047772633575766124389390624461580502297559408308321585109584898425792369600358220535841658549678786749339864508421830660363357911319701575885008989602129643166613028993079515988496880099901480718951358602928607040499845932439878308134831121422572742815819230366864624625895217779574376422112762037823779987710073504628889305202639867518109487769345149171");
    BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    BigInteger g = new BigInteger("19299511126646292735677292065102783378778561114499641085286923120222713237601305948723274636946434828439258268451017100017289362609809530943953925122724233079625518307164581865346039279958415260851483914979882607249628154657564772465176937924043016651149702794189608748225948183639860129062463800074390249087334605293869748396724146880710440740089853821262200757261880275288528764000814009047632654386817621518213519647015345016546802807219266477048059044879836930479745054159401430016737064411017654823699890141551946139887889860734567892357377796679842840391597803008049834321595373016445579567494805998016197754762");
    BigInteger basic_client_id = new BigInteger("8065056338595004263849558545591699357501065012723860989763342176682567102932390430607315480515001800690887060328525391846354333803955485169860120806875258552562080752882074644785913518058334334282163885483071758028240486924220171429567638500030042375763640845187004310839106836642781270747534151423175903397454319628249069428081234427713691546345156135960063045414115563137460345052934272095629260136037533852803447592588331323399380073691952023175610595253030419139157717976635921580926950333646955905077471439685898346180800863290723154797865266692278939276246516201606269665870512301699612237379517785321423394949");
    @RequestMapping("/")
    public String index() {
        return "this is a index";
    }

    @RequestMapping("/login")
    public String login(HttpServletRequest request, HttpSession session, HttpServletResponse response) {
        System.out.println("/login");
        start = new Date().getTime();
        BigInteger sk = generateSK();
        BigInteger pk = g.modPow(sk, P);
        DHKey dhKey = new DHKey();
        String ID;
        do {
            ID = generateID();
            dhKey.setID(ID);
        }while (DHKeyManager.hasID(ID));
        dhKey.setG(g.toString());
        dhKey.setPk_server(pk.toString());
        dhKey.setBasic_client_id(basic_client_id.toString());
        dhKey.setRPCert(RPCert);
        Gson gson = new Gson();
        String responseBody = gson.toJson(dhKey);
        dhKey.setSK_server(sk.toString());
        DHKeyManager.put(dhKey.getID(), dhKey);
        point1 = new Date().getTime();
        response.setHeader("Access-Control-Allow-Origin", "*");
        return responseBody;
    }

    private BigInteger generateSK() {
        BigInteger sk = new BigInteger("2").pow(2047);
        SecureRandom r = new SecureRandom();
        for(int i=0;i<2047;i++){
            if(r.nextBoolean()){
                sk = sk.setBit(i);
            }
        }
        return sk;
    }

    private String generateID() {
        SecureRandom r = new SecureRandom();
        String ID = "";
        for(int i=0; i<24;i++){
            ID = ID + r.nextInt(10);
        }
        return ID;
    }

    @RequestMapping(value = "/uploadPK", method = RequestMethod.POST)
    public String uploadPK(@RequestBody String body, HttpServletRequest request, HttpSession session, HttpServletResponse response){
        System.out.println("/uploadPK");
        point2 = new Date().getTime();
        Gson gson = new Gson();
        DHKey dhKey_client = gson.fromJson(body, DHKey.class);
        String ID = dhKey_client.getID();
        String pk_client = dhKey_client.getPk_client();
        String result = dhKey_client.getResult();
        DHKey dhKey = (DHKey) DHKeyManager.getByName(ID);
        String sk_server = dhKey.getSk_server();
        BigInteger pk = new BigInteger(pk_client);
        BigInteger sk = new BigInteger(sk_server);
        String result_server = pk.modPow(sk, P).toString();
        response.setHeader("Access-Control-Allow-Origin", "*");
        if(result.equals(result_server)){
            dhKey.setResult(result);
            dhKey.setPk_client(pk_client);
            BigInteger client_id = basic_client_id.modPow(new BigInteger(result), P);
            dhKey.setClient_id(client_id.toString());
            point3 = new Date().getTime();
            return "{\"result\":\"ok\", \"client_id\": \""+client_id.toString()+"\"}";
        }else {
            return "{\"result\":\"error\"}";
        }
    }

    @RequestMapping(value = "/register_finished", method = RequestMethod.POST)
    public ModelAndView register_finished(@RequestBody String body, HttpServletRequest request, HttpSession session, HttpServletResponse response){
        System.out.println("/register_finished");
        point4 = new Date().getTime();
        Gson gson = new Gson();
        RegistrationResult registrationResult = gson.fromJson(body, RegistrationResult.class);
        response.setHeader("Access-Control-Allow-Origin", "*");
        if(registrationResult.isResultOK()){
            DHKey dhKey = (DHKey)DHKeyManager.getByName(registrationResult.getID());
            if(registrationResult.getClient_id().equals(dhKey.getClient_id())){
                point5 = new Date().getTime();
                return new ModelAndView("redirect:http://localhost:8080/openid-connect-server-webapp/authorize?client_id=" + registrationResult.getClient_id() + "&redirect_uri=" + registrationResult.getRedirect_uri() + "&response_type=token&scope=openid%20email");
            }else {
                return null;
            }
        }else {
            return null;
        }
    }

    DecodedJWT decodeToken(String token){
        String estr = Util.bytes2HexString(Base64.getUrlDecoder().decode(e));//getDecoder().decode(e).toString();
        String nstr = Util.bytes2HexString(Base64.getUrlDecoder().decode(n));
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(nstr, 16), new BigInteger(estr, 16));
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token);
            return jwt;
        } catch (JWTVerificationException exception){
            //Invalid signature/claims
            return null;
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            return null;
        } catch (InvalidKeySpecException e1) {
            e1.printStackTrace();
            return null;
        }
    }

    @RequestMapping(value = "/authorization", method = RequestMethod.GET)
    public String authorization( HttpServletRequest request, HttpSession session){
        System.out.println("/authorization");
        point6 = new Date().getTime();
        String ID = request.getParameter("ID");
        String id_token = request.getParameter("id_token");
        DHKey dhKey = (DHKey)DHKeyManager.getByName(ID);
        DecodedJWT token = decodeToken(id_token);
        if(token != null) {
            BigInteger _result = ExtendEculid(new BigInteger(dhKey.getResult()), P.subtract(new BigInteger("1")))[1];
            BigInteger sub = new BigInteger(token.getSubject());
            BigInteger userIdentity = sub.modPow(_result, P);
            UserInfo localUserInfo = UserManager.getUserByID(userIdentity.toString());
            if (token.getAudience().contains(dhKey.getClient_id())) {
                if (localUserInfo != null) {
                    if (userIsValidate(dhKey, localUserInfo, userIdentity.toString())) {
                        point7 = new Date().getTime();
                        return "{\"result\":\"ok\"}";
                    } else
                        return "{\"result\":\"error\"}";
                } else {
                    //token.init();
                    UserInfo user = new UserInfo();
                    user.setID(userIdentity.toString());
                    UserManager.setUser(user);
                    return "{\"result\":\"register\"}";
                }
            }
        }
        return "{\"result\":\"error\"}";
    }
    @RequestMapping(value = "/end", method = RequestMethod.GET)
    public String end( HttpServletRequest request, HttpSession session){
        end = new Date().getTime();
        count++;
//        long netCost = (end - point7) / 2;
//        serverClientIDGenerate = point1 - start + point3 -point2;
//        clientClientIDGenerate = point2 - point1 - netCost * 2;
        long negotiation = point3 - start;
        long registration = point5 - point3;
        long tokenObtaining = point7 - point5;
        long total1 = negotiation + registration + tokenObtaining;
        totalNegotiation += negotiation;
        totalRegistration += registration;
        totalTokenObtaining += tokenObtaining;
        long totalTotal = totalNegotiation + totalRegistration + totalTokenObtaining;
        System.out.println("negotiation: " + totalNegotiation/count + "ms");
        System.out.println("registration: " + totalRegistration/count + "ms");
        System.out.println("tokenObtaining: " + totalTokenObtaining/count + "ms");
        System.out.println("total: " + total1);
//        serverRegistration = point5 - point4;
//        //IdPRegistration = Long.parseLong(request.getParameter("time1")) - netCost * 2;
//        clientRegistration = point4 - point3 - netCost * 4 - IdPRegistration;
//        serverAuthorization = point7 - point6;
//        IdPAuthorization = Long.parseLong(request.getParameter("time2")) - netCost * 2;
//        clientAuthorization = point6 - point5 - netCost * 4 - IdPAuthorization;
//        totalNetCost = netCost * 12;
//        long total = serverClientIDGenerate
//                + clientClientIDGenerate
//                + serverRegistration
//                + IdPRegistration
//                + clientRegistration
//                + serverAuthorization
//                + IdPAuthorization
//                + clientAuthorization
//                + totalNetCost;
//        System.out.println("current count: " + count);
//        System.out.println("totalTime: " + total/1000 + "s" + total%1000 + "ms");
//        System.out.println("serverClientIDGenerateTime: " + serverClientIDGenerate/1000 + "s" + serverClientIDGenerate%1000 + "ms");
//        System.out.println("clientClientIDGenerateTime: " + clientClientIDGenerate/1000 + "s" + clientClientIDGenerate%1000 + "ms");
//        System.out.println("serverRegistrationTime: " + serverRegistration/1000 + "s" + serverRegistration%1000 + "ms");
//        System.out.println("IdPRegistrationTime: " + IdPRegistration/1000 + "s" + IdPRegistration%1000 + "ms");
//        System.out.println("clientRegistrationTime: " + clientRegistration/1000 + "s" + clientRegistration%1000 + "ms");
//        System.out.println("serverAuthorizationTime: " + serverAuthorization/1000 + "s" + serverAuthorization%1000 + "ms");
//        System.out.println("IdPAuthorizationTime: " + IdPAuthorization/1000 + "s" + IdPAuthorization%1000 + "ms");
//        System.out.println("clientAuthorizationTime: " + clientAuthorization/1000 + "s" + clientAuthorization%1000 + "ms");
//        System.out.println("totalNetCostTime: " + totalNetCost/1000 + "s" + totalNetCost%1000 + "ms");
        return "end";
    }

    static BigInteger[] ExtendEculid(BigInteger a, BigInteger b)
    {
        BigInteger x,  y;
        if (b.compareTo(new BigInteger("0"))==0)
        {
            x = new BigInteger("1");
            y = new BigInteger("0");
            BigInteger[] t = new BigInteger[3];
            t[0] = a; t[1] = x; t[2] = y;
            return t;
        }
        BigInteger[] t = ExtendEculid(b, a.mod(b));
        BigInteger result = t[0];
        x = t[1];
        y = t[2];
        BigInteger temp = x;
        x = y;
        y = temp.subtract(a.divide(b).multiply(y));
        BigInteger[] t1 = new BigInteger[3];
        t1[0] = result; t1[1] = x; t1[2] = y;
        return t1;
    }


    private boolean userIsValidate(DHKey dhKey, UserInfo userInfo, String sub) {
        if(userInfo.getID().equals(sub)){
            return true;
        }
        return false;
    }

//    @RequestMapping("/login1")
//    public ModelAndView login1(HttpServletRequest request, HttpSession session, HttpServletResponse response){
//        return new ModelAndView("redirect:http://localhost:8080/openid-connect-server-webapp/authorize?client_id=client&redirect_uri=http://localhost:8090/authorization1&response_type=token&scope=openid");
//    }
//
//    @RequestMapping("/authorization1")
//    public String authorization1(HttpServletRequest request, HttpSession session, HttpServletResponse response){
//        String id_token = "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoicGYzZVdpb1prc0V3MGVMbGFZYzJGQSIsInN1YiI6IjEyNDUwLkFTREZKV0ZBIiwiYXVkIjoiY2xpZW50Iiwia2lkIjoicnNhMSIsImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC9vcGVuaWQtY29ubmVjdC1zZXJ2ZXItd2ViYXBwXC8iLCJleHAiOjE1NDI2MjA1NTIsImlhdCI6MTU0MjYxOTk1MiwianRpIjoiNjdkODBhNGItMmU1Ni00YzA0LTkyNzYtMjg2OGRmNGY5ZDc2In0.cS70HvBMoAseXSxSX-Ks0EgGweNWMA_ZOVi9dOVqLQYDR6UBAJDvHl9C9XPqkauZufQp1O0pZS3aPOj7Rg3WQO0XgqnDLthU4Xa6V3D0BzC6PCiXQpzbO6Srjw5dYugbYclFLm7pGupPycdTBwssvP3UbstKHT9XRhDEqclmS54dxnwY1Bdpr3vH52uK1xUYYliHvcFHf3diwZWNVQm7pB6qKnURbx4Alq71nqzifczRn1-bHutOpRIj6GOOls9YfNeHJ1avPo2nuEB8VVdaQZaTrhpAuZNwfS6mPOQ0Ui92DBayaJ3zkRHh6VzmDbEJAiStEtYMUq4sKGkDJy8ZVQ";//request.getParameter("id_token");
//        Token token = new Token(id_token);
//        UserInfo localUserInfo = UserManager.getUserByID(token.getBody().getSub());
//        if(token.getBody().getAud().equals("client")) {
//            if (token.isValid()) {
//                if (localUserInfo != null) {
//                        return "{\"result\":\"ok\"}";
//                } else {
//                    token.init();
//                    UserInfo user = new UserInfo();
//                    user.setID(token.getBody().getSub());
////                user.setRegister_uid(userIdentity.toString());
////                user.setSk_server(dhKey.getSk_server());
//                    UserManager.setUser(user);
//                    return "{\"result\":\"register\"}";
//                }
//            } else {
//                return "{\"result\":\"error\"}";
//            }
//        }
//        return "ok";
//    }


}
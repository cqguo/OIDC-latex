let p = "27449016760001930830125617668247859359745430986704432309085929677995807338305678419885652753794242496407976182871494825520552812933077776662415387179356727792234451654055658177210561689664280863983972105655690337291450879107894692596167210983185326590416340066192826004270803522574046051860102165172244586056707834948333241005980694712476760216030160395462421297530733396614124258707965156976358959843617034441619164457098759725517618250918992025137481460788874501395889763568442978210065547845149324569983455235117868998436516548293413794803510612425480720620581614363153446128915785524341773999191504845709308817083";
let q = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
let g = "3"
let Domain = "http://192.168.0.190:8080/openid-connect-server-webapp"
let state = "start"
let pubKey = ""
let Cert, Y_RP, N_U,  ID_RP, N_RP, PID_RP, redirect_uri, payload
let currentEndpoint




function doAuthorize() {
	// let authorizationUrl = Domain + "/authorize?client_id=" + PID_RP + "&redirect_uri=" + redirect_uri + "&response_type=token&scope=openid%20email"
	// let xmlhttp = initXML()
	// xmlhttp.onreadystatechange = function () {
	// 	if (xmlhttp.readyState == 3 && xmlhttp.status == 200) {
	// 		console.log(xmlhttp.fragment)
	// 	} else {
	//
	// 	}
	// }
	// xmlhttp.open("GET", authorizationUrl, false);
	// xmlhttp.send()


	$.ajax({
		url : 'authorize?client_id=' + PID_RP + '&redirect_uri=' + redirect_uri + '&response_type=token&scope=openid%20email',
		// dataType : 'json',
		complete : function(xhr){
			if((xhr.status >= 300 && xhr.status < 400) && xhr.status != 304){
				//重定向网址在响应头中，取出再执行跳转
				let redirectUrl = xhr.getResponseHeader('X-Redirect');
				location.href = redirectUrl;
			}
		},
		success : function(result){
			let origin = "http://192.168.0.190:8090/"
			let message = {"Type": "Token", "Token": result}
			window.opener.postMessage(JSON.stringify(message), origin)
		}

	});

	// $.get('/openid-connect-server-webapp/authorize?client_id=' + PID_RP + '&redirect_uri=' + redirect_uri + '&response_type=token&scope=openid%20email', {}, function(response, status, request) {
	// 	if (status == STATUS.REDIRECT) {
	// 		// you need to return the redirect url
	// 		location.href = response.redirectUrl;
	// 	} else {
	// 		$('#content').html(request.responseText);
	// 	}
	// });

	// fetch('/openid-connect-server-webapp/authorize?client_id=' + PID_RP + '&redirect_uri=' + redirect_uri + '&response_type=token&scope=openid%20email', { redirect: 'manual' })
	// 	.then(response => {
	// 		console.log(response);
	// 	})
}


function logFuc(){
	let username = document.getElementById("username").value;
	let password = document.getElementById("password").value;
	let _csrf = document.getElementById("_csrf").value;
	let registrationUrl = Domain + "/login"
	let xmlhttp = initXML()
	xmlhttp.onreadystatechange = function () {
		if (xmlhttp.readyState == 3 && xmlhttp.status == 200) {
			let redirection = xmlhttp.responseURL
			if (redirection.endsWith("failure")){

			}else {
				doAuthorize()
			}
		} else {

		}
	}
	let body = "username=" + username + "&password=" + password + "&_csrf="+ _csrf + "&submit=Login"
	xmlhttp.open("POST", registrationUrl, true);
	xmlhttp.setRequestHeader("Upgrade-Insecure-Requests", "1")
	xmlhttp.setRequestHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	xmlhttp.setRequestHeader("Cache-Control", "max-age=0")
	xmlhttp.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	xmlhttp.send(body);
}



var pKey = KEYUTIL.getKey("-----BEGIN PUBLIC KEY-----\n" +
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n" +
	"vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n" +
	"aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n" +
	"tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n" +
	"e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n" +
	"V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n" +
	"MwIDAQAB\n" +
	"-----END PUBLIC KEY-----")

var sKey = 	KEYUTIL.getKey("-----BEGIN RSA PRIVATE KEY-----\n" +
	"MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw\n" +
	"kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr\n" +
	"m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi\n" +
	"NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV\n" +
	"3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2\n" +
	"QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs\n" +
	"kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go\n" +
	"amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM\n" +
	"+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9\n" +
	"D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC\n" +
	"0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y\n" +
	"lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+\n" +
	"hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp\n" +
	"bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X\n" +
	"+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B\n" +
	"BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC\n" +
	"2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx\n" +
	"QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz\n" +
	"5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9\n" +
	"Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0\n" +
	"NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j\n" +
	"8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma\n" +
	"3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K\n" +
	"y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB\n" +
	"jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=\n" +
	"-----END RSA PRIVATE KEY----");

function verify(mes, key){
	return true
}


function generateModPow(x, y, z){
	let xbn = nbi();
	let ybn = nbi();
	let zbn = nbi();
	xbn.fromString(x);
	ybn.fromString(y);
	zbn.fromString(z);
	return xbn.modPow(ybn, zbn).toString();
}

function initXML(){
	if (window.XMLHttpRequest)
	{
		//  IE7+, Firefox, Chrome, Opera, Safari 浏览器执行代码
		return new XMLHttpRequest();
	}
	else
	{
		// IE6, IE5 浏览器执行代码
		return ActiveXObject("Microsoft.XMLHTTP");
	}
}



function doRequestToken (data){
	let registrationUrl = Domain + "/isAuthenticated"
	let xmlhttp = initXML()
	xmlhttp.onreadystatechange = function () {
		if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
			let date
			try {
				data = JSON.parse(xmlhttp.responseText)
				if (data.Result == "OK"){
					doAuthorize()
				}
			} catch(e) {
				document.getElementById("login").style = ""
			}
		} else {

		}
	}
	xmlhttp.open("GET", registrationUrl, true);
	xmlhttp.send();

}


function doRegistration() {
	let registrationUrl = Domain + "/register"
	let xmlhttp = initXML()
	xmlhttp.onreadystatechange = function () {
		if (xmlhttp.readyState == 4 && xmlhttp.status == 201) {
			let data = JSON.parse(xmlhttp.responseText)
			console.log(xmlhttp.responseText)
			if (data.Content.Result == "OK"){
				state = "expectRequest"
				let RegistrationResult = {"Type": "RegistrationResult", "RegistrationResult": xmlhttp.responseText}
				window.opener.postMessage(JSON.stringify(RegistrationResult), '*');
			}
		} else {

		}
	}
	xmlhttp.open("POST", registrationUrl, true);
	let sha256 = new KJUR.crypto.MessageDigest({"alg": "sha256", "prov": "cryptojs"})
	sha256.updateString(N_U)
	let sha256Str = sha256.digest()
	redirect_uri = Domain + "1/" + sha256Str
	let body = {"client_id": PID_RP, "application_type": "web", "client_name": "M_OIDC", "redirect_uris":redirect_uri, "grant_types": "implicit"}
	//let body = "{\"client_id\":\"" + PID_RP + "\",\"application_type\":\"web\",\"client_name\":\"M_OIDC\",\"redirect_uris\":\"http://oidcupload.12450.com/token\", \"grant_types\": \"implicit\"}"// \"response_types\": [\"id_token\", \"token\"],
	xmlhttp.send(JSON.stringify(body));
}


function onReceiveMessage(event){
	const message = JSON.parse(event.data)
	let messageType = message.Type
	switch (messageType) {
		case "Cert":
			if (state != "expectYRP")
				break
			Cert = message.Cert
		//	Y_RP = message.Y_RP
			if (Cert==null)//||Y_RP==null)
				break
			let CertTup = Cert.split('\.')
			let header = CertTup[0]
			let payload = CertTup[1]
			let sig = CertTup[2]
			if (header==null||payload==null||sig==null)
				break
		//	let key = pubKey[JSON.parse(header).kid]
			let signatureVf=new KJUR.crypto.Signature({"alg":"SHA256withRSA", "prvkeypem": pKey});
			signatureVf.updateString(header + "." + payload);
			let verify = signatureVf.verify(b64tohex(sig));
			if (!verify)
				break
			N_U = bigInt.randBetween("0", q).toString();
			ID_RP = JSON.parse(atob(payload)).basic_client_id
			PID_RP = generateModPow(ID_RP, N_U, p);
			state = "expectPIDRP"
			let content = {"Type": "N_U", "N_U": N_U}
			console.log(content)
			window.opener.postMessage(JSON.stringify(content), '*');
			break
		case "PID_RP":
			if (state != "expectPIDRP")
				break
			if (PID_RP != message.PID_RP) {
				state = "stop"
				break
			}
			doRegistration()
			break
		case "Request":
			if(state != "expectRequest")
				break
			let data = message.Content
			if (PID_RP != data.client_id) {
				state = "stop"
				break
			}
			// if (data.redirect_uri in Cert) {
				doRequestToken(data)
			// }
	}


}




window.addEventListener('message', onReceiveMessage);
let Ready = {'Type': 'Ready'}
state = "expectYRP"
window.opener.postMessage(JSON.stringify(Ready), '*');












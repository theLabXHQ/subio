package gen

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// builtinLabels and environmentWords were written for subio from common
// hosting, mail and development vocabulary.
const builtinLabels = `
www www1 www2 www3 web web1 web2 web3 site home portal app apps app1 app2 api api1 api2 apis
backend backends frontend front svc service services gateway-api
mail mail1 mail2 smtp smtp1 smtp2 pop pop3 imap webmail mx mx1 mx2 mx3 email owa exchange autodiscover
autoconfig mta relay postfix newsletter news lists list spam antispam
ns ns1 ns2 ns3 ns4 dns dns1 dns2 dns3 resolver
vpn vpn1 vpn2 remote gateway gw gw1 gw2 proxy proxy1 proxy2 bastion jump jumphost firewall fw fw1 router
dev dev1 dev2 develop development devel test test1 test2 testing tests qa qa1 qa2 uat stage staging stg
sandbox sbx demo demo1 demo2 preview preprod pre prod production prd live beta alpha canary nightly
lab labs research experimental internal intranet corp corporate private public external extranet
admin administrator adm root manage manager management console control panel cpanel dashboard
monitor monitoring sysmon status health metrics grafana prometheus kibana nagios zabbix alerts logs logging
elastic elasticsearch splunk sentry
git gitlab github bitbucket svn repo repos code source jenkins ci cd build builds drone travis runner
artifactory nexus registry docker hub harbor k8s kubernetes rancher cluster node node1 node2 master
worker worker1 worker2 swarm
db db1 db2 db3 database sql mysql mariadb postgres postgresql pg mongo mongodb redis memcached cache
queue queues broker rabbitmq kafka
cassandra oracle mssql ldap ad sso auth oauth login signin id idp identity accounts account users user
secure security cert certs ca pki
ftp ftp1 ftp2 sftp files file fileserver share shares storage s3 backup backups bak nas drive docs
doc documents wiki confluence jira kb help helpdesk support ticket tickets desk service services
cdn cdn1 cdn2 static static1 static2 assets asset img img1 img2 image images media video videos
ad ads adserver adservice banner banners promo advert advertising
download downloads upload uploads content edge lb lb1 lb2 balancer loadbalancer origin
shop store cart checkout pay payment payments billing invoice invoices orders order crm erp hr
blog forum forums community wordpress wp cms press careers jobs about info contact partners partner
m mobile wap ios android
chat slack teams meet meeting zoom conference voip sip pbx phone
search solr es graphql rest ws wss socket realtime stream streaming push
data analytics stats stat reports report bi etl warehouse
us uk eu de fr nl sg jp au ca in br asia emea apac east west north south central
old new legacy archive archives v1 v2 v3 temp tmp bak1
crm1 office office365 outlook calendar cal
server server1 server2 srv srv1 srv2 host host1 host2 vm vm1 vm2 cloud aws azure gcp
tracking track click go link links redirect r s t
`

// environmentWords vary known names: the words organizations put next to a
// service to say which copy of it this is.
const environmentWords = `
dev develop development test testing qa uat stage staging stg sandbox demo preview preprod prod production
beta alpha canary internal int ext external admin api app web www old new legacy backup bak temp tmp v1 v2
v3 us eu asia east west corp private public secure vpn db cache cdn static mobile
`

// regionWords are the cloud region and provider tokens an organisation puts
// beside a service name.
const regionWords = `
us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 eu-central-1
ap-south-1 ap-southeast-1 ap-northeast-1 sa-east-1 ca-central-1
aws azure gcp
`

// yearWords are a sliding window of recent years.
func recentYears(now int) []string {
	const span = 8
	out := make([]string, 0, span)
	for y := now - span + 1; y <= now+1; y++ {
		out = append(out, strconv.Itoa(y))
	}
	return out
}

// Builtin returns the list used by -brute when no -w is given.
func Builtin() *Wordlist {
	w, _ := parseWords(strings.NewReader(strings.ReplaceAll(builtinLabels, " ", "\n")))
	sum := sha256.Sum256([]byte(builtinLabels))
	w.Name = "builtin"
	w.SHA256 = hex.EncodeToString(sum[:])
	return w
}

// EnvironmentWords returns the default words for varying known names.
func EnvironmentWords() []string {
	out := strings.Fields(environmentWords)
	out = append(out, strings.Fields(regionWords)...)
	return append(out, recentYears(time.Now().Year())...)
}

// uzbekLabels is a service-label list for Uzbek and Russian-speaking
// targets.
const uzbekLabels = `
sklad reklama muxbir bizninguylar
pochta sayt saytlar novosti magazin kassa zakaz zakazy dostavka oplata platezh
lichnyy kabinet lk arxiv bank kredit strahovanie spravka kontakty obratnaya
yangiliklar yangilik aloqa xizmat xizmatlar mahsulot mahsulotlar buyurtma
tolov tolovlar hisob hisobot kirish chiqish royxat qidiruv bolim bolimlar
hujjat hujjatlar murojaat xabar xabarlar elon elonlar vakansiya ish narx
buxgalteriya kadrlar rahbariyat matbuot tadbir tadbirlar loyiha loyihalar
dastur dasturlar tizim kengash
ombor savdo bozor dokon dokonlar
talaba talabalar fakultet universitet institut maktab kollej litsey
shifoxona dorixona poliklinika
vazirlik hokimiyat tuman viloyat shahar mahalla davlat
soliq bojxona adliya mehnat talim fan madaniyat sport turizm transport
qurilish energetika suv gaz issiqlik
yordam qollanma qoidalar shartlar maxfiylik
`

// BuiltinUzbek returns the Uzbek and Russian label list.
func BuiltinUzbek() *Wordlist {
	w, _ := parseWords(strings.NewReader(strings.ReplaceAll(uzbekLabels, " ", "\n")))
	sum := sha256.Sum256([]byte(uzbekLabels))
	w.Name = "builtin-uz"
	w.SHA256 = hex.EncodeToString(sum[:])
	return w
}

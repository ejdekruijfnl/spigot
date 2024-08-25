// Package firewall generates Fortinet Firewall log messages
//
// For the configuration file there are no options so only the following is needed:
//
//   - generator:
//     type: "fortinet:firewall"
package firewall

import (
	"bytes"
	"math/rand"
	"net"
	"strconv"
	"text/template"
	"time"

	"github.com/elastic/go-ucfg"
	"github.com/leehinman/spigot/pkg/generator"
	"github.com/leehinman/spigot/pkg/random"
)

// Name is the name used in the configuration file and the registry.
const Name = "fortinet:firewall"

var (
	eventUserTemplate      = "date={{.Date.UTC.Format \"2006-01-02\"}} time={{.Timestamp}} devname=\"{{.DevName}}\" devid=\"{{.DevId}}\" logid=\"{{.LogId}}\" type=\"event\" subtype=\"user\" level=\"{{.Level}}\" vd=\"{{.Vd}}\" eventtime={{.Date.Unix}} tz=\"{{.Timezone}}\" logdesc=\"FSSO logon authentication status\" srcip={{.SrcIp}} user=\"{{.User}}\" server=\"{{.Server}}\" action=\"FSSO-logon\" msg=\"FSSO-logon event from FSSO_{{.Server}}: user {{.User}} logged on {{.SrcIp}}\""
	eventSystemTemplate    = "date={{.Date.UTC.Format \"2006-01-02\"}} time={{.Timestamp}} devname=\"{{.DevName}}\" devid=\"{{.DevId}}\" logid=\"{{.LogId}}\" type=\"event\" subtype=\"system\" level=\"{{.Level}}\" vd=\"{{.Vd}}\" eventtime={{.Date.Unix}} tz=\"{{.Timezone}}\" logdesc=\"FortiSandbox AV database updated\" version=\"1.522479\" msg=\"FortiSandbox AV database updated\""
	utmDnsTemplate         = "date={{.Date.UTC.Format \"2006-01-02\"}} time={{.Timestamp}} devname=\"{{.DevName}}\" devid=\"{{.DevId}}\" logid=\"{{.LogId}}\" type=\"utm\" subtype=\"dns\" eventtype=\"dns-query\" level=\"{{.Level}}\" vd=\"{{.Vd}}\" eventtime={{.Date.Unix}} tz=\"{{.Timezone}}\" policyid={{.PolicyId}} sessionid={{.SessionId}} srcip={{.SrcIp}} srcport={{.SrcPort}} srcintf=\"{{.Interface1}}\" srcintfrole=\"{{.InterfaceRole1}}\" dstip={{.DstIp}} dstport=53 dstintf=\"{{.Interface2}}\" dstintfrole=\"{{.InterfaceRole2}}\" proto={{.Protocol}} profile=\"{{.Server}}\" xid={{.XId}} qname=\"{{.QueryName}}\" qtype=\"{{.QueryType}}\" qtypeval=1 qclass=\"IN\""
	trafficForwardTemplate = "date={{.Date.UTC.Format \"2006-01-02\"}} time={{.Timestamp}} devname=\"{{.DevName}}\" devid=\"{{.DevId}}\" logid=\"{{.LogId}}\" type=\"traffic\" subtype=\"forward\" level=\"{{.Level}}\" vd=\"{{.Vd}}\" eventtime={{.Date.Unix}} srcip={{.SrcIp}} srcport={{.SrcPort}} srcintf=\"{{.Interface1}}\" srcintfrole=\"{{.InterfaceRole1}}\" dstip={{.DstIp}} dstport={{.DstPort}} dstintf=\"{{.Interface2}}\" dstintfrole=\"{{.InterfaceRole2}}\" sessionid={{.SessionId}} proto={{.Protocol}} action=\"{{.TrafficAction}}\" policyid={{.PolicyId}} policytype=\"policy\" service=\"SNMP\" dstcountry=\"Reserved\" srccountry=\"Reserved\" trandisp=\"noop\" duration={{.Duration}} sentbyte={{.SentBytes}} rcvdbyte={{.SentBytes}} sentpkt={{.SentPackets}} appcat=\"unscanned\" crscore=30 craction=131072 crlevel=\"high\""
	msgTemplates           = [...]string{
		eventUserTemplate,
		eventSystemTemplate,
		utmDnsTemplate,
		trafficForwardTemplate,
	}
	devices        = [...]string{"Lakewood", "Midvale", "Brookside", "Holloway", "Fairview", "Westport", "Elmswood", "Ridgefield", "Pinehurst", "Stonebridge", "Mapleton", "Riverside", "Graysville", "Windermere", "Briarcliff", "Oakridge", "Highland", "Copperfield", "Woodhaven", "Silverton", "Rosewood", "Cedarcrest", "Ashford", "Elmwood", "Woodbury", "Springfield", "Ravenswood", "Stonegate", "Brookhaven", "Southgate", "Seabrook", "Edgewood", "Greenfield", "Meadowbrook", "Bellevue", "Clarksville", "Oakwood", "Ridgemont", "Crystal_Lake", "Riverview", "Whispering_Pines", "Forest_Hill", "Sunnydale", "Mountview", "Woodlake", "Baywood", "Brentwood", "Lincolnwood", "Summitville", "Elm_Grove"}
	devid          = [...]string{"Lakew", "Midva", "Broos", "Hollo", "Fairv", "Westp", "Elmsw", "Ridge", "Pineh", "Stonb", "Maple", "Rivers", "Grayv", "Windm", "Briac", "Oakri", "Highl", "Copfi", "Woodh", "Silve", "Rosew", "Cedcr", "Ashfo", "Elmwo", "Woodb", "Sprin", "Raven", "Stoga", "Brooh", "South", "Seabr", "Edgew", "Green", "Meado", "Belle", "Clark", "Oakwo", "Ridgm", "Cryla", "Rivew", "Whisp", "Foreh", "Sunny", "Mount", "Woodl", "Baywo", "Brewd", "Lincw", "Summi", "Elmgv"}
	users          = [...]string{"Liam_Walters", "Emma_Douglas", "Noah_Hamilton", "Olivia_Stevens", "Elijah_Baker", "Ava_Reynolds", "James_Thompson", "Sophia_Parker", "Lucas_Bennett", "Isabella_Brooks", "Mason_Rogers", "Mia_Campbell", "Ethan_Phillips", "Amelia_Bell", "Alexander_Carter", "Charlotte_Adams", "Henry_Patterson", "Harper_Wright", "Sebastian_Cooper", "Evelyn_Gray", "Jack_Hughes", "Lily_Ross", "Owen_Morris", "Ella_Hayes", "Daniel_Peterson", "Aria_Myers", "Samuel_Long", "Chloe_Collins", "Matthew_Hughes", "Grace_Cook", "Wyatt_Warren", "Scarlett_Reed", "Caleb_Bryant", "Penelope_Rogers", "Isaac_Murphy", "Nora_Jenkins", "Jacob_Cunningham", "Hazel_Clark", "Levi_Morgan", "Riley_Perry", "Nathaniel_Foster", "Zoey_Ford", "Joshua_Harrison", "Lillian_Sullivan", "David_McCarthy", "Avery_Hart", "Andrew_Walker", "Stella_Price", "Thomas_Ward", "Hannah_Hall"}
	levels         = [...]string{"warning", "notice", "information", "error"}
	interfaces     = [...]string{"int0", "int1", "int2", "int3", "int4", "int5", "int6", "int7"}
	roles          = [...]string{"lan", "wan", "internal", "external", "inbound", "outbound"}
	protocols      = [...]int{6, 17}
	queries        = [...]string{"www.silverpinevalley.com", "www.brickstoneridge.net", "www.oakwoodgrove.org", "www.bluewaterhaven.co", "www.copperhollow.info", "www.windyriverplains.com", "www.crystalbayvillage.net", "www.ironwoodcove.org", "www.sunsetbluffresort.co", "www.whisperinghillspoint.info", "www.mapleridgeranch.com", "www.goldenpeakfarms.net", "www.riverviewmeadows.org", "www.stonecreekwoods.co", "www.briarwoodcrossing.info", "www.highlandgrovesprings.com", "www.greenfieldretreat.net", "www.silverlakehollow.org", "www.rosewoodvista.co", "www.ashforddunes.info", "www.willowbrookcourt.com", "www.oakridgefalls.net", "www.copperfieldgrove.org", "www.windermerebay.co", "www.meadowbrookhaven.info", "www.bellavistaacres.com", "www.ridgemontestates.net", "www.sunnydaleshores.org", "www.lakewoodreserves.co", "www.westportpines.info", "www.elmswoodmeadow.com", "www.ridgefieldplaza.net", "www.pinehurstcove.org", "www.stonebridgeflats.co", "www.mapletonlodge.info", "www.graysvillemanor.com", "www.windermerepoint.net", "www.briarcliffheights.org", "www.oakridgebay.co", "www.highlandcrossing.info", "www.copperfieldterrace.com", "www.woodhavenhills.net", "www.silvertonview.org", "www.rosewoodvalley.co", "www.cedarcrestgrove.info", "www.ashfordpeaks.com", "www.elmwoodlakes.net", "www.woodburyridge.org", "www.springfieldbluff.co"}
	queryTypes     = [...]string{"A", "AAAA"}
	servers        = [...]string{"Zeus_prod", "Hera_test", "Poseidon_dev", "Demeter_prod", "Athena_dev", "Apollo_test", "Artemis_prod", "Ares_dev", "Aphrodite_test", "Hephaestus_prod", "Hermes_dev", "Hestia_test", "Dionysus_prod", "Hades_dev", "Persephone_test", "Hecate_prod", "Gaia_dev", "Cronus_test", "Rhea_prod", "Eros_dev", "Helios_test", "Selene_prod", "Eos_dev", "Nike_test", "Nemesis_prod", "Iris_dev", "Hypnos_test", "Thanatos_prod", "Morpheus_dev", "Tyche_test", "Pan_prod", "Eris_dev", "Hebe_test", "Nyx_prod", "Khione_dev", "Themis_test", "Harmonia_prod", "Phoebe_dev", "Leto_test", "Tethys_prod", "Metis_dev", "Aether_test", "Hemera_prod", "Eurus_dev", "Notus_test", "Boreas_prod", "Zephyrus_dev", "Styx_test", "Phobos_prod", "Deimos_dev"}
	trafficActions = [...]string{"deny", "accept"}
)

// Firewall holds the random fields for a firewall record
type Firewall struct {
	Timestamp      string
	Date           time.Time
	DevId          string
	DevName        string
	Direction      string
	DstIp          net.IP
	DstPort        int
	Duration       int
	Interface1     string
	Interface2     string
	InterfaceRole1 string
	InterfaceRole2 string
	Level          string
	LogId          int
	PolicyId       int
	Protocol       int
	QueryName      string
	QueryType      string
	ReceivedBytes  int
	SentBytes      int
	SentPackets    int
	Server         string
	SessionId      int
	SrcIp          net.IP
	SrcPort        int
	Templates      []*template.Template
	Timezone       string
	TrafficAction  string
	User           string
	Vd             string
	XId            int
}

func init() {
	generator.Register(Name, New)
}

// New is the Factory for Firewall objects.
func New(cfg *ucfg.Config) (generator.Generator, error) {
	c := defaultConfig()
	if err := cfg.Unpack(&c); err != nil {
		return nil, err
	}

	f := &Firewall{}
	f.randomize()

	for i, v := range msgTemplates {
		t, err := template.New(strconv.Itoa(i)).Funcs(generator.FunctionMap).Parse(v)
		if err != nil {
			return nil, err
		}
		f.Templates = append(f.Templates, t)
	}
	return f, nil
}

// Next produces the next firewall record.
//
// Example:
//
// date=1970-01-02 time=03:04:05 devname=\"testswitch3\" devid=\"testrouter\" logid=\"0123456789\" type=\"event\" subtype=\"user\" level=\"error\" vd=\"root\" eventtime=97445 tz=\"-0500\" logdesc=\"FSSO logon authentication status\" srcip=142.155.32.170 user=\"user07\" server=\"srv7\" action=\"FSSO-logon\" msg=\"FSSO-logon event from FSSO_srv7: user user07 logged on 142.155.32.170\"
func (f *Firewall) Next() ([]byte, error) {
	var buf bytes.Buffer

	err := f.Templates[rand.Intn(len(f.Templates))].Execute(&buf, f)
	if err != nil {
		return nil, err
	}

	//randomize after evaluating template to make testing easier
	f.randomize()
	return buf.Bytes(), err
}

func (f *Firewall) randomize() {
	f.Timestamp = random.Randomtime()
	f.DevName = devices[rand.Intn(len(devices))]
	f.DevId = devid[rand.Intn(len(devid))]
	f.LogId = rand.Intn(10)
	f.Timezone = "-0500"
	f.Date = time.Now()
	f.Vd = "root"
	f.User = users[rand.Intn(len(users))]
	f.Server = servers[rand.Intn(len(servers))]
	f.SrcIp = random.IPv4()
	f.SrcPort = random.Port()
	f.DstIp = random.IPv4()
	f.DstPort = random.Port()
	f.PolicyId = rand.Intn(256)
	f.SessionId = rand.Intn(65536)
	f.Interface1 = interfaces[rand.Intn(len(interfaces))]
	f.Interface2 = interfaces[rand.Intn(len(interfaces))]
	f.InterfaceRole1 = roles[rand.Intn(len(roles))]
	f.InterfaceRole2 = roles[rand.Intn(len(roles))]
	f.Protocol = protocols[rand.Intn(len(protocols))]
	f.QueryName = queries[rand.Intn(len(queries))]
	f.QueryType = queryTypes[rand.Intn(len(queryTypes))]
	f.XId = rand.Intn(256)
	f.Level = levels[rand.Intn(len(levels))]
	f.TrafficAction = trafficActions[rand.Intn(len(trafficActions))]
	f.SentPackets = rand.Intn(65536)
	f.SentBytes = f.SentPackets * 1500
	f.Duration = rand.Intn(1024)
}

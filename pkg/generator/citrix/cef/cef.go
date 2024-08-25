// Package cef implements the generator for Citrix CEF logs.
//
//	generator:
//	  type: citrix:cef
package cef

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"text/template"
	"time"

	"github.com/elastic/go-ucfg"
	"github.com/leehinman/spigot/pkg/generator"
	"github.com/leehinman/spigot/pkg/random"
)

// Details from https://docs.citrix.com/en-us/citrix-adc/downloads/cef-log-components.pdf,
// https://docs.citrix.com/en-us/citrix-adc/current-release/application-firewall/logs.html
// and https://support.citrix.com/article/CTX136146/common-event-format-cef-logging-support-in-the-application-firewall.

// Name is the name of the generator in the configuration file and registry
const Name = "citrix:cef"

var (
	tmpl         = `{{.Timestamp.Format .TimeLayout}} <{{.Facility}}.{{.Priority}}> {{.Addr}} CEF:{{.CEFVersion}}|{{.Vendor}}|{{.Product}}|{{.Version}}|{{.Module}}|{{.Violation}}|{{.Severity}}|src={{.SrcAddr}} {{with .Geo}}geolocation={{.}} {{end}}spt={{.SrcPort}} method={{.Method}} request={{.Request}} msg={{.Message}} cn1={{.EventID}} cn2={{.TxID}} cs1={{.Profile}} cs2={{.PPEID}} cs3={{.SessID}} cs4={{.SeverityLabel}} cs5={{.Year}} {{with .ViolationCategory}}cs6={{.}} {{end}}act={{.Action}}`
	msgTemplates = []string{
		tmpl,
	}
	timeLayouts = []string{
		"Jan 02 15:04:05",
		"Jan 2 15:04:05",
	}
	facilities = []string{
		"auth", "authpriv", "cron", "daemon", "kern", "lpr", "mail", "mark", "news", "syslog", "user", "uucp", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
	}
	priorities = []string{
		"debug", "info", "notice", "warning", "warn", "err", "error", "crit", "alert", "emerg", "panic",
	}
	vendors = []string{
		"Citrix",
	}
	products = []string{
		"NetScalar",
	}
	versions = []string{
		"NS10.0",
		"NS11.0",
	}
	modules = []string{
		"APPFW",
	}
	violations = []string{
		"APPFW_FIELDCONSISTENCY",
		"APPFW_SAFECOMMERCE",
		"APPFW_SAFECOMMERCE_XFORM",
		"APPFW_SIGNATURE_MATCH",
		"APPFW_STARTURL",
	}
	locations = []string{
		"",
		"Unknown",
		"NorthAmerica.Altimoria.Corvax.CityCenter.*.*",
		"NorthAmerica.Florensia.Novath.TremorValley.*.*",
		"NorthAmerica.Gallania.Rovento.Sunridge.*.*",
		"NorthAmerica.Baltoria.Velzora.PolarisHeights.*.*",
		"NorthAmerica.Novadia.Quivera.FlamingRidge.*.*",
		"NorthAmerica.Xandria.Velmos.Riverstone.*.*",
		"NorthAmerica.Kestoria.Yalvaz.CrimsonHill.*.*",
		"NorthAmerica.Vollara.Zendar.AuroraPeaks.*.*",
		"NorthAmerica.Quintara.Pallaxa.SilverLake.*.*",
		"NorthAmerica.Morovia.Korvath.SolarisPlains.*.*",
		"NorthAmerica.Serenia.Ryland.Stormview.*.*",
		"NorthAmerica.Zyrenthia.Vortak.Ironcliff.*.*",
		"NorthAmerica.Valoria.Draconis.WildroseGlen.*.*",
		"NorthAmerica.Tarvonia.Felwind.ShadowGrove.*.*",
		"NorthAmerica.Lorasia.Velthra.Sunspire.*.*",
		"NorthAmerica.Talvaxia.Balaria.CrimsonFalls.*.*",
		"NorthAmerica.Elandria.Kovoria.Glintwood.*.*",
		"NorthAmerica.Orlanta.Zandor.Mistvale.*.*",
		"NorthAmerica.Valteris.Xanoris.ThunderValley.*.*",
		"NorthAmerica.Morlonia.Phaedra.EchoHaven.*.*",
		"NorthAmerica.Theria.Vestoria.TremorHollow.*.*",
		"NorthAmerica.Zarvath.Mystara.Glintwood.*.*",
		"NorthAmerica.Kalandor.Volvax.Silverstrand.*.*",
		"NorthAmerica.Olivar.Ventara.CrimsonMesa.*.*",
		"NorthAmerica.Theronia.Pyrax.ThunderRidge.*.*",
		"NorthAmerica.Veloria.Zyros.Moonshadow.*.*",
		"NorthAmerica.Zovaris.Korvax.Stormcrest.*.*",
		"NorthAmerica.Valentia.Rivenor.Sunblade.*.*",
		"NorthAmerica.Zeltria.Orex.Shadowridge.*.*",
		"NorthAmerica.Voronia.Xelthra.Thunderpeak.*.*",
		"SouthAmerica.Viridia.Malothia.JadeHollow.*.*",
		"SouthAmerica.Malandria.Aurelia.PhoenixBay.*.*",
		"SouthAmerica.Valcoria.Lorvia.EmeraldIsle.*.*",
		"SouthAmerica.Aronya.Valeria.MysticFalls.*.*",
		"SouthAmerica.Celestia.Palvoria.EbonyVale.*.*",
		"SouthAmerica.Zorvia.Sarath.TalonCliffs.*.*",
		"SouthAmerica.Celentis.Volara.Dreamshade.*.*",
		"SouthAmerica.Valthera.Tarvora.CrimsonCove.*.*",
		"SouthAmerica.Xanthia.Theros.MysticGrove.*.*",
		"SouthAmerica.Selveria.Pyros.Riverwind.*.*",
		"SouthAmerica.Volthea.Arventis.ShadowGlen.*.*",
		"SouthAmerica.Eldoria.Lithara.Thunderstone.*.*",
		"SouthAmerica.Korvax.Talora.Sunspire.*.*",
		"SouthAmerica.Vyxoria.Zandros.Shadowvale.*.*",
		"SouthAmerica.Pyronia.Volcath.SilentHill.*.*",
		"SouthAmerica.Zylandria.Orvath.CrimsonBay.*.*",
		"SouthAmerica.Valtheris.Vorlon.Suncrest.*.*",
		"SouthAmerica.Xylandria.Antaris.EchoValley.*.*",
		"SouthAmerica.Novanta.Pallaxa.LunarGrove.*.*",
		"SouthAmerica.Quilara.Talvos.StormBluff.*.*",
		"SouthAmerica.Vandora.Valzor.SilverStream.*.*",
		"SouthAmerica.Xyvronia.Lithara.MysticCove.*.*",
		"SouthAmerica.Selvoria.Vorvath.ThunderGlen.*.*",
		"SouthAmerica.Valencia.Orvalon.Rivercrest.*.*",
		"SouthAmerica.Xylothia.Zentar.GlintRidge.*.*",
		"SouthAmerica.Voloria.Sylvara.TwilightPeak.*.*",
		"Europe.Maldera.Quinthra.Shadowpeak.*.*",
		"Europe.Talvoria.Aurex.LunarHollow.*.*",
		"Europe.Valtoria.Xelara.SunfallGlen.*.*",
		"Europe.Xylandria.Korinox.StormCrest.*.*",
		"Europe.Ceridia.Vandor.SilverGrove.*.*",
		"Europe.Kytheria.Zorthal.Ravenridge.*.*",
		"Europe.Zypheria.Malvora.Sunwood.*.*",
		"Europe.Volaxia.Talendria.Moonstone.*.*",
		"Europe.Karvoria.Vorlon.EchoMesa.*.*",
		"Europe.Thalandia.Zaltor.Sunridge.*.*",
		"Europe.Vantoria.Syldor.CrimsonHollow.*.*",
		"Europe.Xantheas.Oltar.Stormwind.*.*",
		"Europe.Quinthia.Aetheris.ThunderCliff.*.*",
		"Europe.Rovinthar.Zyros.CrimsonGlade.*.*",
		"Europe.Selveris.Vorath.MoonBluff.*.*",
		"Europe.Talvora.Zyloth.Glintwood.*.*",
		"Europe.Valtheris.Vorath.MysticHaven.*.*",
		"Europe.Zelvoris.Altira.Silverthorn.*.*",
		"Europe.Valthera.Kylos.Sunspire.*.*",
		"Europe.Xyphera.Voltara.ShadowMire.*.*",
		"Europe.Celathra.Tharvos.MysticCove.*.*",
		"Europe.Theronis.Orvax.CrimsonPeak.*.*",
		"Europe.Selvorn.Korvath.ThunderBay.*.*",
		"Europe.Zantheria.Voloria.SilverMesa.*.*",
		"Europe.Xyrelia.Talvora.RavenGlen.*.*",
		"Europe.Valoria.Zelthra.Moonrise.*.*",
		"Europe.Quinthara.Olthera.SilverLake.*.*",
		"Europe.Zoltara.Ryvon.ThunderHill.*.*",
		"Europe.Selvoris.Vorland.Suncrest.*.*",
		"Europe.Theronix.Xarvath.CrimsonRidge.*.*",
		"Europe.Korvaris.Valthros.StormBay.*.*",
		"Europe.Valdoria.Quinthos.EchoGrove.*.*",
		"Africa.Voltheon.Zoltris.Suncrest.*.*",
		"Africa.Thalvaria.Ravinthar.LunarHollow.*.*",
		"Africa.Valoria.Xalvath.ThunderPlains.*.*",
		"Africa.Zorvath.Selenor.Silverpeak.*.*",
		"Africa.Vandora.Kylandar.MysticRidge.*.*",
		"Africa.Quinthar.Valthoria.Stormshade.*.*",
		"Africa.Xylothar.Vorath.SunValley.*.*",
		"Africa.Zelandia.Theronis.CrimsonCove.*.*",
		"Africa.Vantheon.Selvos.Moonspire.*.*",
		"Africa.Therondar.Volaria.ShadowGrove.*.*",
		"Africa.Valdoria.Altira.LunarBay.*.*",
		"Africa.Selvoria.Xylandor.Glintwood.*.*",
		"Africa.Xyronia.Valtheris.Sunridge.*.*",
		"Africa.Quinthar.Voltara.ThunderGrove.*.*",
		"Africa.Valterra.Olthoria.CrimsonBluff.*.*",
		"Africa.Xalvoria.Zorath.MysticPeak.*.*",
		"Africa.Thalvaris.Zanthon.Sunstone.*.*",
		"Africa.Rovinthar.Vantoria.EchoRidge.*.*",
		"Africa.Selthara.Zorvath.SilverCrest.*.*",
		"Africa.Xylandra.Valdoria.MoonRidge.*.*",
		"Africa.Valtheris.Zolvaris.ShadowValley.*.*",
		"Africa.Vorlonia.Thalvaris.Thunderstone.*.*",
		"Africa.Xalvaris.Zeltria.Sunbluff.*.*",
		"Africa.Vandaria.Rovinthar.GlintPeak.*.*",
		"Africa.Thalvath.Xoltris.SilverVale.*.*",
		"Africa.Valdaria.Sylvoris.MoonCrest.*.*",
		"Africa.Seltheris.Voltrax.CrimsonHill.*.*",
		"Africa.Valtheris.Rovinthor.SunGrove.*.*",
		"Africa.Xarvath.Zorvinth.StormValley.*.*",
		"Africa.Kylandor.Valthros.Glintstone.*.*",
		"Africa.Sylvoria.Zelvath.MoonGlen.*.*",
		"Asia.Valdoria.Tharvos.SunGrove.*.*",
		"Asia.Xelthar.Vorlon.Moonshade.*.*",
		"Asia.Zantheria.Vorath.StormVale.*.*",
		"Asia.Valtheris.Selvath.ThunderCrest.*.*",
		"Asia.Tharvath.Xoltria.Sunbluff.*.*",
		"Asia.Zolvaris.Valthros.ShadowGrove.*.*",
		"Asia.Xarvath.Selvorn.Moonstone.*.*",
		"Asia.Voltaris.Zeltria.GlintRidge.*.*",
		"Asia.Seltharis.Valoria.Sunwood.*.*",
		"Asia.Valtoris.Thalvath.MysticGrove.*.*",
		"Asia.Zarvath.Xelvos.CrimsonPeak.*.*",
		"Asia.Volaris.Tharvon.Shadowvale.*.*",
		"Asia.Xelvoris.Valtheria.SilverGlen.*.*",
		"Asia.Valdoria.Zorvath.LunarHollow.*.*",
		"Asia.Xylandar.Valvoria.Sunstone.*.*",
		"Asia.Theronis.Voltrax.Glintwood.*.*",
		"Asia.Zeltria.Valtoria.StormGlen.*.*",
		"Asia.Vanthara.Tharvath.ThunderBay.*.*",
		"Asia.Selthra.Zoltrax.Moonridge.*.*",
		"Asia.Valtheria.Zarvath.Sunbluff.*.*",
		"Asia.Xoltria.Volaria.SilverBay.*.*",
		"Asia.Theronis.Valdaria.Shadowstone.*.*",
		"Asia.Valvoria.Zyloth.SunVale.*.*",
		"Asia.Xantheria.Thalvath.Moonstone.*.*",
		"Asia.Zarvath.Valthros.GlintGlen.*.*",
		"Asia.Vorathia.Xelthros.Suncrest.*.*",
		"Asia.Selvoria.Zolvaris.CrimsonHill.*.*",
		"Asia.Valdoris.Theronis.MoonGrove.*.*",
	}
	methods = []string{
		"GET", "POST",
	}
	requests = []string{
		`http://aaron.stratum8.net/FFC/login.html`,
		`http://aaron.stratum8.net/FFC/login.php?login_name=abc&passwd=123456789234&drinking_pref=on&text_area=&loginButton=ClickToLogin&as_sfid=AAAAAAWIahZuYoIFbjBhYMP05mJLTwEfIY0a7AKGMg3jIBaKmwtK4t7M7lNxOgj7Gmd3SZc8KUj6CR6a7W5kIWDRHN8PtK1Zc-txHkHNx1WknuG9DzTuM7t1THhluevXu9I4kp8%3D&as_fid=feeec8758b41740eedeeb6b35b85dfd3d5def30c`,
		`http://aaron.stratum8.net/FFC/wwwboard/passwd.txt`,
		`http://aaron.stratum8.net/FFC/CreditCardMind.html`,
		`http://vpx247.example.net/FFC/CreditCardMind.html`,
		`http://vpx247.example.net/FFC/login_post.html?abc\=def`,
		`http://vpx247.example.net/FFC/wwwboard/passwd.txt`,
	}
	messages = []string{
		"Signature violation rule ID 807: web-cgi /wwwboard/passwd.txt access",
		"Disallow Illegal URL.",
		"Transformed (xout) potential credit card numbers seen in server response",
		"Maximum number of potential credit card numbers seen",
		"Field consistency check failed for field passwd",
	}
	profiles = []string{
		"pr_ffc",
	}
	severityLabels = []string{
		"INFO", "ALERT",
	}
	violationCategory = []string{
		"",
		"web-cgi",
		"sql-injection",
		"phishing",
	}
	actions = []string{
		"blocked", "not blocked", "transformed",
	}
)

type CEF struct {
	Timestamp  time.Time
	TimeLayout string

	Facility string
	Priority string

	Addr net.IP

	CEFVersion int
	Vendor     string
	Product    string
	Version    string
	Module     string
	Violation  string
	Severity   int

	SrcAddr           net.IP
	Geo               string
	SrcPort           int
	Method            string
	Request           string
	Message           string
	EventID           int
	TxID              int
	Profile           string
	PPEID             string
	SessID            string
	SeverityLabel     string
	Year              int
	ViolationCategory string
	Action            string

	templates []*template.Template
}

func init() {
	generator.Register(Name, New)
}

// New returns a new Citrix CEF log line generator.
func New(cfg *ucfg.Config) (generator.Generator, error) {
	def := defaultConfig()
	if err := cfg.Unpack(&def); err != nil {
		return nil, err
	}

	c := &CEF{}
	c.randomize()

	for i, v := range msgTemplates {
		t, err := template.New(strconv.Itoa(i)).Funcs(generator.FunctionMap).Parse(v)
		if err != nil {
			return nil, err
		}
		c.templates = append(c.templates, t)
	}

	return c, nil
}

// Next produces the next CEF log entry.
func (c *CEF) Next() ([]byte, error) {
	var buf bytes.Buffer

	err := c.templates[rand.Intn(len(c.templates))].Execute(&buf, c)
	if err != nil {
		return nil, err
	}

	c.randomize()

	return buf.Bytes(), err
}

func (c *CEF) randomize() {
	c.Timestamp = time.Now()
	c.TimeLayout = randString(timeLayouts)

	c.Facility = randString(facilities)
	c.Priority = randString(priorities)

	c.Addr = random.IPv4()

	c.CEFVersion = rand.Intn(2)
	c.Vendor = randString(vendors)
	c.Product = randString(products)
	c.Version = randString(versions)
	c.Module = randString(modules)
	c.Violation = randString(violations)
	c.Severity = rand.Intn(10) + 1

	c.SrcAddr = random.IPv4()
	c.Geo = randString(locations)
	c.SrcPort = random.Port()
	c.Method = randString(methods)
	c.Request = randString(requests)
	c.Message = randString(messages)
	c.EventID = rand.Intn(1000)
	c.TxID = rand.Intn(100000)
	c.Profile = randString(profiles)
	c.PPEID = fmt.Sprintf("PPE%d", rand.Intn(9)+1)
	sessID := make([]byte, 16)
	rand.Read(sessID)
	c.SessID = hex.EncodeToString(sessID)
	c.SeverityLabel = randString(severityLabels)
	c.Year = c.Timestamp.Year()
	c.ViolationCategory = randString(violationCategory)
	c.Action = randString(actions)
}

func randString(s []string) string {
	return s[rand.Intn(len(s))]
}
